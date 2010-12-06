#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "triton.h"
#include "log.h"
#include "list.h"
#include "memdebug.h"

#include "cli_p.h"

#define RECV_BUF_SIZE 1024
#define AUTH_FAILED "\r\nAuthentication failed\r\n"

#define ESC_LEFT "[D"
#define ESC_RIGHT "[C"
#define ESC_UP "[A"
#define ESC_DOWN "[B"

struct telnet_client_t
{
	struct cli_client_t cli_client;
	struct list_head entry;
	struct triton_md_handler_t hnd;
	struct list_head xmit_queue;
	struct buffer_t *xmit_buf;
	int xmit_pos;
	struct list_head history;
	struct list_head *history_pos;
	uint8_t *cmdline;
	int cmdline_pos;
	int cmdline_pos2;
	int cmdline_len;
	int auth:1;
	int echo:1;
	int telcmd:1;
	int esc:1;
	int disconnect:1;
};

struct buffer_t
{
	struct list_head entry;
	int size;
	uint8_t buf[0];
};

static struct triton_context_t serv_ctx;
static struct triton_md_handler_t serv_hnd;
static LIST_HEAD(clients);

static uint8_t *recv_buf;
static uint8_t *temp_buf;

static void disconnect(struct telnet_client_t *cln)
{
	struct buffer_t *b;

	log_debug("cli: disconnect\n");

	list_del(&cln->entry);

	triton_md_unregister_handler(&cln->hnd);
	close(cln->hnd.fd);

	if (cln->xmit_buf)
		_free(cln->xmit_buf);

	while (!list_empty(&cln->xmit_queue)) {
		b = list_entry(cln->xmit_queue.next, typeof(*b), entry);
		list_del(&b->entry);
		_free(b);
	}

	while (!list_empty(&cln->history)) {
		b = list_entry(cln->history.next, typeof(*b), entry);
		list_del(&b->entry);
		_free(b);
	}

	_free(cln->cmdline);
	_free(cln);
}

static void cli_client_disconnect(struct cli_client_t *tcln)
{
	struct telnet_client_t *cln = container_of(tcln, typeof(*cln), cli_client);
	disconnect(cln);
}

static void queue_buffer(struct telnet_client_t *cln, struct buffer_t *b)
{
	if (cln->xmit_buf)
		list_add_tail(&b->entry, &cln->xmit_queue);
	else
		cln->xmit_buf = b;
}

static int telnet_send(struct telnet_client_t *cln, const void *_buf, int size)
{
	int n, k;
	struct buffer_t *b;
	const uint8_t *buf = (const uint8_t *)_buf;

	if (cln->disconnect)
		return -1;
	
	if (!list_empty(&cln->xmit_queue)) {
		b = _malloc(sizeof(*b) + size);
		b->size = size;
		memcpy(b->buf, buf, size);
		queue_buffer(cln, b);
		return 0;
	}

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
			//disconnect(cln);
			cln->disconnect = 1;
			return -1;
		}
	}
	return 0;
}

static int cli_client_send(struct cli_client_t *tcln, const void *buf, int size)
{
	struct telnet_client_t *cln = container_of(tcln, typeof(*cln), cli_client);
	return telnet_send(cln, buf, size);
}

static int cli_client_sendv(struct cli_client_t *tcln, const char *fmt, va_list ap)
{
	struct telnet_client_t *cln = container_of(tcln, typeof(*cln), cli_client);
	int r = vsnprintf((char *)temp_buf, RECV_BUF_SIZE, fmt, ap);

	if (r >= RECV_BUF_SIZE) {
		strcpy((char *)temp_buf + RECV_BUF_SIZE - 6, "...\r\n");
		r = RECV_BUF_SIZE;
	}

	return telnet_send(cln, temp_buf, r);
}

static int send_banner(struct telnet_client_t *cln)
{
	return telnet_send(cln, "accel-pptp version " ACCEL_PPTP_VERSION "\r\n", sizeof("accel-pptp version " ACCEL_PPTP_VERSION "\r\n"));
}

static int send_config(struct telnet_client_t *cln)
{
	uint8_t buf[] = {IAC, WILL, TELOPT_ECHO, IAC, WILL,	TELOPT_SGA, IAC, DONT, TELOPT_LINEMODE};
	return telnet_send(cln, buf, sizeof(buf));
}

static int send_password_request(struct telnet_client_t *cln)
{
	uint8_t buf0[] = {IAC, WILL, TELOPT_ECHO};
	uint8_t buf1[] = "Password: ";

	if (telnet_send(cln, buf0, sizeof(buf0)))
		return -1;
	
	if (telnet_send(cln, buf1, sizeof(buf1)))
		return -1;
	
	return 0;
}

static int send_prompt(struct telnet_client_t *cln)
{
	return telnet_send(cln, conf_cli_prompt, strlen(conf_cli_prompt));
}

/*static void print_buf(const uint8_t *buf, int size)
{
	int i;

	for (i = 0; i < size; i++)
		log_debug("%x ", buf[i]);
	log_debug("\n");
}*/

static int send_cmdline_tail(struct telnet_client_t *cln, int corr)
{
	if (telnet_send(cln, cln->cmdline + cln->cmdline_pos, cln->cmdline_len - cln->cmdline_pos))
		return -1;

	memset(temp_buf, '\b', cln->cmdline_len - cln->cmdline_pos - corr);
	
	if (telnet_send(cln, temp_buf, cln->cmdline_len - cln->cmdline_pos - corr))
		return -1;
	
	return 0;
}

static int load_history(struct telnet_client_t *cln)
{
	struct buffer_t *b = list_entry(cln->history_pos, typeof(*b), entry);
	if (b->size < cln->cmdline_len) {
		memset(temp_buf, '\b', cln->cmdline_len - b->size);
		memset(temp_buf + cln->cmdline_len - b->size, ' ', cln->cmdline_len - b->size);
		if (telnet_send(cln, temp_buf, (cln->cmdline_len - b->size) * 2))
			return -1;
	}
	if (telnet_send(cln, "\r", 1))
		return -1;
	if (send_prompt(cln))
		return -1;
	memcpy(cln->cmdline, b->buf, b->size);
	cln->cmdline_pos = b->size;
	cln->cmdline_len = b->size;
	if (telnet_send(cln, b->buf, b->size))
		return -1;

	return 0;
}

static int telnet_input_char(struct telnet_client_t *cln, uint8_t c)
{
	uint8_t buf[] = {IAC, DONT, 0};
	struct buffer_t *b;
	
	if (c == '\n')
		return 0;
	
	if (c == '\r') {
		cln->cmdline[cln->cmdline_len] = 0;

		if (cln->echo) {
			if (telnet_send(cln, "\r\n", 2))
				return -1;
		}

		if (!cln->auth) {
			if (strcmp((char *)cln->cmdline, conf_cli_passwd)) {
				if (telnet_send(cln, AUTH_FAILED, sizeof(AUTH_FAILED)))
					return -1;
				disconnect(cln);
				return -1;
			}
			cln->auth = 1;
		} else if (cln->cmdline_len) {
			b = _malloc(sizeof(*b) + cln->cmdline_len);
			memcpy(b->buf, cln->cmdline, cln->cmdline_len);
			b->size = cln->cmdline_len;
			list_add(&b->entry, cln->history.next);
			cln->history_pos = cln->history.next;
			
			if (cli_process_cmd(&cln->cli_client))
				return -1;
		}
	
		cln->cmdline_pos = 0;
		cln->cmdline_len = 0;

		return send_prompt(cln);
	}

	if (cln->telcmd) {
		if (cln->cmdline_pos2 == RECV_BUF_SIZE - 1) {
			log_error("cli: buffer overflow, dropping connection ...\n");
			disconnect(cln);
			return -1;
		}

		cln->cmdline[cln->cmdline_pos2] = c;
		cln->cmdline_pos2++;

		if (cln->cmdline[cln->cmdline_len] >= WILL && cln->cmdline[cln->cmdline_len] <= DONT && cln->cmdline_pos2 - cln->cmdline_len != 2)
			return 0;

		switch (cln->cmdline[cln->cmdline_len]) {
			case WILL:
			case WONT:
				buf[2] = c;
				if (telnet_send(cln, buf, 3))
					return -1;
				break;
			case DO:
				if (c == TELOPT_ECHO)
					cln->echo = 1;
				break;
			case SB:
				if (c != SE)
					return 0;
		}
		
		cln->telcmd = 0;
	} else if (cln->esc) {
		if (cln->cmdline_pos2 == RECV_BUF_SIZE - 1) {
			log_error("cli: buffer overflow, dropping connection ...\n");
			disconnect(cln);
			return -1;
		}

		cln->cmdline[cln->cmdline_pos2] = c;
		cln->cmdline_pos2++;

		if (cln->cmdline_pos2 - cln->cmdline_len != 2)
			return 0;
		
		cln->esc = 0;

		if (cln->auth) {
			if (!memcmp(cln->cmdline + cln->cmdline_len, ESC_LEFT, 2)) {
				if (cln->cmdline_pos) {
					if (telnet_send(cln, "\b", 1))
						return -1;
					cln->cmdline_pos--;
				}
			} else if (!memcmp(cln->cmdline + cln->cmdline_len, ESC_RIGHT, 2)) {
				if (cln->cmdline_pos < cln->cmdline_len) {
					if (send_cmdline_tail(cln, 1))
						return -1;
					cln->cmdline_pos++;
				}
			} else if (!memcmp(cln->cmdline + cln->cmdline_len, ESC_UP, 2)) {
				if (cln->history_pos == cln->history.next) {
					b = list_entry(cln->history_pos, typeof(*b), entry);
					memcpy(b->buf, cln->cmdline, cln->cmdline_len);
					b->size = cln->cmdline_len;
				}
				cln->history_pos = cln->history_pos->next;
				if (cln->history_pos == &cln->history) {
					cln->history_pos = cln->history_pos->prev;
					return 0;
				}
				if (load_history(cln))
					return -1;
			} else if (!memcmp(cln->cmdline + cln->cmdline_len, ESC_DOWN, 2)) {
				cln->history_pos = cln->history_pos->prev;
				if (cln->history_pos == &cln->history) {
					cln->history_pos = cln->history_pos->next;
					return 0;
				}
				if (load_history(cln))
					return -1;
			}
		}
	} else {
		switch (c) {
			case 0xff:
				cln->cmdline_pos2 = cln->cmdline_len;
				cln->telcmd = 1;
				return 0;
			case 0x1b:
				cln->cmdline_pos2 = cln->cmdline_len;
				cln->esc = 1;
				return 0;
			case 0x7f:
				if (cln->cmdline_pos) {
					if (cln->cmdline_pos < cln->cmdline_len) {
						memmove(cln->cmdline + cln->cmdline_pos - 1, cln->cmdline + cln->cmdline_pos, cln->cmdline_len - cln->cmdline_pos);
						
						cln->cmdline[cln->cmdline_len - 1] = ' ';
						
						if (telnet_send(cln, "\b", 1))
							return -1;
					
						cln->cmdline_pos--;
					
						if (send_cmdline_tail(cln, 0))
							return -1;
					} else {
						buf[0] = '\b';
						buf[1] = ' ';
						buf[2] = '\b';
						if (telnet_send(cln, buf, 3))
							return -1;
						cln->cmdline_pos--;
					}

					cln->cmdline_len--;
				}
				return 0;
		}

		if (isprint(c)) {
			if (cln->cmdline_len == RECV_BUF_SIZE - 1)
				return 0;

			if (cln->cmdline_pos < cln->cmdline_len)
				memmove(cln->cmdline + cln->cmdline_pos + 1, cln->cmdline + cln->cmdline_pos, cln->cmdline_len - cln->cmdline_pos);
			cln->cmdline[cln->cmdline_pos] = c;
			cln->cmdline_pos++;
			cln->cmdline_len++;

			if (cln->echo) {
				if (!cln->auth) {
					if (telnet_send(cln, "*", 1))
						return -1;
				} else {
					if (telnet_send(cln, &c, 1))
						return -1;
				}
			}
			
			if (cln->cmdline_pos < cln->cmdline_len) {
				if (send_cmdline_tail(cln, 0))
					return -1;
			}
		}
	}

	return 0;
}

static int cln_read(struct triton_md_handler_t *h)
{
	struct telnet_client_t *cln = container_of(h, typeof(*cln), hnd);
	int i, n;

	while (1) {
		n = read(h->fd, recv_buf, RECV_BUF_SIZE);
		if (n == 0) {
			disconnect(cln);
			return 0;
		}
		if (n < 0) {
			if (errno != EAGAIN)
				log_error("cli: telnet: read: %s\n", strerror(errno));
			return 0;
		}
		/*log_debug("cli: read(%i): ", n);
		print_buf(cln->recv_buf + cln->recv_pos, n);*/
		for (i = 0; i < n; i++) {
			if (telnet_input_char(cln, recv_buf[i]))
				return -1;
		}
		if (cln->disconnect) {
			disconnect(cln);
			return 0;
		}
	}

	return 0;
}

static int cln_write(struct triton_md_handler_t *h)
{
	struct telnet_client_t *cln = container_of(h, typeof(*cln), hnd);
	int k;
	
	while (1) {
		for (; cln->xmit_pos < cln->xmit_buf->size; cln->xmit_pos += k) {
			k = write(cln->hnd.fd, cln->xmit_buf->buf + cln->xmit_pos, cln->xmit_buf->size - cln->xmit_pos);
			if (k < 0) {
				if (errno == EAGAIN)
					return 0;
				if (errno != EPIPE)
					log_error("cli: telnet: write: %s\n", strerror(errno));
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
	struct telnet_client_t *conn;
	struct buffer_t *b;

	while(1) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("cli: telnet: accept failed: %s\n", strerror(errno));
			continue;
		}

		log_info2("cli: telnet: new connection from %s\n", inet_ntoa(addr.sin_addr));

		if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
			log_error("cli: telnet: failed to set nonblocking mode: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		conn = _malloc(sizeof(*conn));
		memset(conn, 0, sizeof(*conn));
		conn->hnd.fd = sock;
		conn->hnd.read = cln_read;
		conn->hnd.write = cln_write;
		conn->cmdline = _malloc(RECV_BUF_SIZE);
		INIT_LIST_HEAD(&conn->xmit_queue);
		INIT_LIST_HEAD(&conn->history);

		b = _malloc(sizeof(*b) + RECV_BUF_SIZE);
		b->size = 0;
		list_add_tail(&b->entry, &conn->history);
		conn->history_pos = conn->history.next;
		
		conn->cli_client.cmdline = conn->cmdline;
		conn->cli_client.send = cli_client_send;
		conn->cli_client.sendv = cli_client_sendv;
		conn->cli_client.disconnect = cli_client_disconnect;

		triton_md_register_handler(&serv_ctx, &conn->hnd);
		triton_md_enable_handler(&conn->hnd,MD_MODE_READ);

		list_add_tail(&conn->entry, &clients);

		if (send_banner(conn))
			continue;

		if (send_config(conn))
			continue;

		if (conf_cli_passwd)
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
	struct telnet_client_t *cln;

	while (!list_empty(&clients)) {
		cln = list_entry(clients.next, typeof(*cln), entry);
		disconnect(cln);
	}

	triton_md_unregister_handler(&serv_hnd);
	close(serv_hnd.fd);
	triton_context_unregister(ctx);
}

static struct triton_context_t serv_ctx = {
	.close = serv_close,
	.before_switch = log_switch,
};

static struct triton_md_handler_t serv_hnd = {
	.read = serv_read,
};

static void start_server(const char *host, int port)
{
  struct sockaddr_in addr;

	serv_hnd.fd = socket(PF_INET, SOCK_STREAM, 0);
  if (serv_hnd.fd < 0) {
    log_emerg("cli: telnet: failed to create server socket: %s\n", strerror(errno));
    return;
  }

	memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
	if (host)
		addr.sin_addr.s_addr = inet_addr(host);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

  setsockopt(serv_hnd.fd, SOL_SOCKET, SO_REUSEADDR, &serv_hnd.fd, 4);  
  if (bind (serv_hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    log_emerg("cli: telnet: failed to bind socket: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
	}

  if (listen (serv_hnd.fd, 1) < 0) {
    log_emerg("cli: telnet: failed to listen socket: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
  }

	if (fcntl(serv_hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("cli: telnet: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv_hnd.fd);
    return;
	}
	
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(host);

	triton_context_register(&serv_ctx, NULL);
	triton_context_set_priority(&serv_ctx, 1);
	triton_md_register_handler(&serv_ctx, &serv_hnd);
	triton_md_enable_handler(&serv_hnd, MD_MODE_READ);
	triton_context_wakeup(&serv_ctx);
}

static void __init init(void)
{
	const char *opt;
	char *host, *d;
	int port;

	opt = conf_get_opt("cli", "telnet");
	if (!opt)
		return;
		
	host = strdup(opt);
	d = strstr(host, ":");
	if (!d)
		goto err_fmt;
	
	*d = 0;
	port = atoi(d + 1);
	if (port <= 0)
		goto err_fmt;

	recv_buf = malloc(RECV_BUF_SIZE);
	temp_buf = malloc(RECV_BUF_SIZE);

	start_server(host, port);
	
	return;
err_fmt:
	log_emerg("cli: telnet: invalid format\n");
	free(host);
}

