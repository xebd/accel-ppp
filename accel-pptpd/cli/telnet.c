#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "triton.h"
#include "log.h"
#include "list.h"
#include "memdebug.h"

#include "telnet.h"

#define RECV_BUF_SIZE 4096
#define BANNER "accel-pptp-1.3-rc1\r\n"
#define AUTH_FAILED "\r\nAuthentication failed\r\n"

struct buffer_t
{
	struct list_head entry;
	int size;
	uint8_t buf[0];
};

static const char *conf_passwd;
static const char *conf_prompt = "accel-pptp# ";

static struct triton_context_t serv_ctx;
static struct triton_md_handler_t serv_hnd;

static void disconnect(struct client_t *cln)
{
	struct buffer_t *b;

	log_debug("cli: disconnect\n");

	triton_md_unregister_handler(&cln->hnd);
	close(cln->hnd.fd);

	if (cln->xmit_buf)
		_free(cln->xmit_buf);

	while (!list_empty(&cln->xmit_queue)) {
		b = list_entry(cln->xmit_queue.next, typeof(*b), entry);
		list_del(&b->entry);
		_free(b);
	}

	_free(cln->recv_buf);
	_free(cln);
}

void telnet_disconnect(struct client_t *cln)
{
	disconnect(cln);
}

static void queue_buffer(struct client_t *cln, struct buffer_t *b)
{
	if (cln->xmit_buf)
		list_add_tail(&b->entry, &cln->xmit_queue);
	else
		cln->xmit_buf = b;
}

int telnet_send(struct client_t *cln, const void *_buf, int size)
{
	int n, k;
	struct buffer_t *b;
	const uint8_t *buf = (const uint8_t *)_buf;

	for (n = 0; n < size; n += k) {
		k = write(cln->hnd.fd, buf + n, size - n);
		if (k < 0) {
			if (errno == EAGAIN) {
				b = _malloc(sizeof(*b) + size - n);
				b->size = size - n;
				memcpy(b->buf, buf, size - n);
				queue_buffer(cln, b);

				triton_md_enable_handler(&cln->hnd, MD_MODE_WRITE);
				break;
			}
			if (errno != EPIPE)
				log_error("cli: write: %s\n", strerror(errno));
			disconnect(cln);
			return -1;
		}
	}
	return 0;
}

static int send_banner(struct client_t *cln)
{
	return telnet_send(cln, BANNER, sizeof(BANNER));
}

static int send_password_request(struct client_t *cln)
{
	uint8_t buf0[] = {IAC, WILL, TELOPT_ECHO};
	uint8_t buf1[] = "Password: ";

	if (telnet_send(cln, buf0, sizeof(buf0)))
		return -1;
	
	if (telnet_send(cln, buf1, sizeof(buf1)))
		return -1;
	
	return 0;
}

static int send_prompt(struct client_t *cln)
{
	return telnet_send(cln, conf_prompt, strlen(conf_prompt));
}

static void print_buf(const uint8_t *buf, int size)
{
	int i;

	for (i = 0; i < size; i++)
		log_debug("%x ", buf[i]);
	log_debug("\n");
}

static int process_data(struct client_t *cln)
{
	int i, n;
	char *eof;
	uint8_t buf[] = {IAC, DONT, 0, '\r', '\n'};

	eof = strstr((const char*)cln->recv_buf, "\r\n");
	if (!eof)
		return 0;
	
	*eof = 0;

	for (i = 0; i < cln->recv_pos; i++) {
		if (cln->recv_buf[i] == 0xff) {
			if (i >= cln->recv_pos - 1)
				return 0;
			if (cln->recv_buf[i + 1] == WILL || cln->recv_buf[i + 1] == WONT) {
				if (i >= cln->recv_pos - 2)
					return 0;
				buf[2] = cln->recv_buf[i + 2];
				if (telnet_send(cln, buf, 3))
					return -1;
			}

			if (cln->recv_buf[i + 1] >= 251 && cln->recv_buf[i + 1] <= 254) {
				if (i >= cln->recv_pos - 2)
					return 0;
				n = 3;
			} else
				n = 2;
			
			memmove(cln->recv_buf + i, cln->recv_buf + i + n, cln->recv_pos - i - n);
			cln->recv_pos -= n;
			i--;
		}
	}

	if (!cln->auth) {
		if (strcmp((const char*)cln->recv_buf, conf_passwd)) {
			if (telnet_send(cln, AUTH_FAILED, sizeof(AUTH_FAILED)))
				return -1;
			disconnect(cln);
			return -1;
		}
		cln->auth = 1;
		buf[1] = WONT;
		buf[2] = TELOPT_ECHO;
		if (telnet_send(cln, buf, 5))
			return -1;

	} else {
		if (process_cmd(cln))
			return -1;
	}

	if (send_prompt(cln))
		return -1;

	cln->recv_pos = 0;

	return 0;
}

static int cln_read(struct triton_md_handler_t *h)
{
	struct client_t *cln = container_of(h, typeof(*cln), hnd);
	int n;

	while (1) {
		n = read(h->fd, cln->recv_buf + cln->recv_pos, RECV_BUF_SIZE - cln->recv_pos);
		if (n == 0) {
			disconnect(cln);
			return 0;
		}
		if (n < 0) {
			if (errno != EAGAIN)
				log_error("cli: read: %s\n", strerror(errno));
			return 0;
		}
		log_debug("cli: read(%i): ", n);
		print_buf(cln->recv_buf + cln->recv_pos, n);
		cln->recv_pos += n;
		if (process_data(cln))
			return -1;
	}

	return 0;
}

static int cln_write(struct triton_md_handler_t *h)
{
	struct client_t *cln = container_of(h, typeof(*cln), hnd);
	int k;
	
	while (1) {
		for (; cln->xmit_pos < cln->xmit_buf->size; cln->xmit_pos += k) {
			k = write(cln->hnd.fd, cln->xmit_buf->buf + cln->xmit_pos, cln->xmit_buf->size - cln->xmit_pos);
			if (k < 0) {
				if (errno == EAGAIN)
					return 0;
				if (errno != EPIPE)
					log_error("cli: write: %s\n", strerror(errno));
				disconnect(cln);
				return -1;
			}
		}

		_free(cln->xmit_buf);
		cln->xmit_pos = 0;

		if (list_empty(&cln->xmit_queue))
			break;

		cln->xmit_buf = list_entry(cln->xmit_queue.next, typeof(*cln->xmit_buf), entry);
		list_del(&cln->xmit_buf->entry);
	}

	triton_md_disable_handler(&cln->hnd, MD_MODE_WRITE);

	return 0;
}

static int serv_read(struct triton_md_handler_t *h)
{
  struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock;
	struct client_t *conn;

	while(1) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("cli: accept failed: %s\n", strerror(errno));
			continue;
		}

		log_info("cli: new connection from %s\n", inet_ntoa(addr.sin_addr));

		if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
			log_error("cli: failed to set nonblocking mode: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		conn = _malloc(sizeof(*conn));
		memset(conn, 0, sizeof(*conn));
		conn->hnd.fd = sock;
		conn->hnd.read = cln_read;
		conn->hnd.write = cln_write;
		conn->recv_buf = _malloc(RECV_BUF_SIZE);
		INIT_LIST_HEAD(&conn->xmit_queue);
		
		triton_md_register_handler(&serv_ctx, &conn->hnd);
		triton_md_enable_handler(&conn->hnd,MD_MODE_READ);

		if (send_banner(conn))
			continue;

		if (conf_passwd)
			send_password_request(conn);
		else {
			conn->auth = 1;
			send_prompt(conn);
		}
	}
	return 0;
}
static void serv_close(struct triton_context_t *ctx)
{
	triton_md_unregister_handler(&serv_hnd);
	close(serv_hnd.fd);
	triton_context_unregister(ctx);
}

static struct triton_context_t serv_ctx = {
	.close = serv_close,
};

static struct triton_md_handler_t serv_hnd = {
	.read = serv_read,
};

static void start_server(const char *host, int port)
{
  struct sockaddr_in addr;

	serv_hnd.fd = socket(PF_INET, SOCK_STREAM, 0);
  if (serv_hnd.fd < 0) {
    log_emerg("cli: failed to create server socket: %s\n", strerror(errno));
    return;
  }

	memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
	if (host)
		addr.sin_addr.s_addr = inet_addr(host);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind (serv_hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    log_emerg("cli: failed to bind socket: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
	}

  if (listen (serv_hnd.fd, 1) < 0) {
    log_emerg("cli: failed to listen socket: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
  }

	if (fcntl(serv_hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("cli: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
	}
	
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(host);

	triton_context_register(&serv_ctx, NULL);
	triton_md_register_handler(&serv_ctx, &serv_hnd);
	triton_md_enable_handler(&serv_hnd, MD_MODE_READ);
	triton_context_wakeup(&serv_ctx);
}

static void __init init(void)
{
	const char *opt;
	int port = 0;
	const char *host="127.0.0.1";

	opt = conf_get_opt("cli", "port");
	if (opt && atoi(opt) > 0)
		port = atoi(opt);
	
	opt = conf_get_opt("cli", "bind");
	if (opt)
		host = opt;
	
	if (!port) {
		log_emerg("cli: disabled\n");
		return;
	}

	conf_passwd = conf_get_opt("cli", "passwd");
	opt = conf_get_opt("cli", "prompt");
	if (opt)
		conf_prompt = opt;

	start_server(host, port);
}

