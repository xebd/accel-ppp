#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "triton.h"
#include "log.h"
#include "list.h"
#include "memdebug.h"

#define RECV_BUF_SIZE 4096
#define BANNER "accel-pptp-1.3-rc1\r\n"

struct client_t
{
	struct list_head entry;
	struct triton_md_handler_t hnd;
	char *recv_buf;
	int recv_pos;
	struct list_head xmit_queue;
	int auth:1;
};

static struct triton_context_t serv_ctx;
static struct triton_md_handler_t serv_hnd;

static void send_banner(struct client_t *cln)
{
	write(cln->hnd.fd, BANNER, sizeof(BANNER));
}

static int cln_read(struct triton_md_handler_t *h)
{
	struct client_t *cln = container_of(h, typeof(*cln), hnd);
	int n;

	while (1) {
		n = read(h->fd, cln->recv_buf + cln->recv_pos, RECV_BUF_SIZE - cln->recv_pos);
		if (n == 0) {
			//disconnect(cln);
			return 0;
		}
		if (n < 0) {
			if (errno != EAGAIN)
				log_error("cli: read: %s\n", strerror(errno));
			return 0;
		}
		log_debug("cli: read(%i): ", n);
	}

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
		//conn->hnd.write = cln_write;
		conn->recv_buf = _malloc(RECV_BUF_SIZE);
		INIT_LIST_HEAD(&conn->xmit_queue);
		
		triton_md_register_handler(&serv_ctx, &conn->hnd);
		triton_md_enable_handler(&conn->hnd,MD_MODE_READ);

		send_banner(conn);
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
	
	if (!host || !port) {
		log_emerg("cli: disabled\n");
		return;
	}

	start_server(host, port);
}

