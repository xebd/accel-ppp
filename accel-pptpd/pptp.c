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

#include "if_pppox.h"

#include "list.h"
#include "pptp_prot.h"
#include "triton/triton.h"
#include "pptpd.h"
#include "log.h"
#include "ppp.h"


#define TIMEOUT 10000

#define STATE_IDLE 0
#define STATE_ESTB 1
#define STATE_PPP  2
#define STATE_FIN  3
#define STATE_CLOSE 4

struct pptp_conn_t
{
	struct triton_ctx_t ctx;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout_timer;
	struct triton_timer_t echo_timer;
	int state;

	uint8_t *in_buf;
	int in_size;
	uint8_t *out_buf;
	int out_size;
	int out_pos;

	struct ppp_ctrl_t ctrl;
	struct ppp_t ppp;
};

static int pptp_read(struct triton_md_handler_t *h);
static int pptp_write(struct triton_md_handler_t *h);
static void pptp_timeout(struct triton_md_handler_t *h);
static void ppp_started(struct ppp_t *);
static void ppp_finished(struct ppp_t *);

static void disconnect(struct pptp_conn_t *conn)
{
	triton_md_unregister_handler(&conn->hnd);
	close(conn->hnd.fd);
	
	if (conn->state == STATE_PPP) {
		conn->state = STATE_CLOSE;
		ppp_terminate(&conn->ppp, 1);
	}
	
	triton_unregister_ctx(&conn->ctx);
	
	free(conn->in_buf);
	free(conn->out_buf);
	free(conn);
}

static int post_msg(struct pptp_conn_t *conn, void *buf, int size)
{
	int n;
	if (conn->out_size) {
		log_debug("post_msg: buffer is not empty\n");
		return -1;
	}

	n=write(conn->hnd.fd, buf, size);
	if (n < 0) {
		if (errno == EINTR || errno == EAGAIN)
			n = 0;
		else {
			if (errno != EPIPE)
				log_debug("post_msg: failed to write socket %i\n",errno);
			return -1;
		}
	}

	if ( n<size ) {
		memcpy(conn->out_buf, buf + n, size - n);
		triton_md_enable_handler(&conn->hnd, MD_MODE_WRITE);
	}

	return 0;
}

static int send_pptp_stop_ctrl_conn_rqst(struct pptp_conn_t *conn, int reason, int err_code)
{
	struct pptp_stop_ctrl_conn msg = {
		.header = PPTP_HEADER_CTRL(PPTP_STOP_CTRL_CONN_RQST),
		.reason_result = hton8(reason),
		.error_code = hton8(err_code),
	};

	return post_msg(conn, &msg, sizeof(msg));
}

static int send_pptp_stop_ctrl_conn_rply(struct pptp_conn_t *conn, int reason, int err_code)
{
	struct pptp_stop_ctrl_conn msg = {
		.header = PPTP_HEADER_CTRL(PPTP_STOP_CTRL_CONN_RPLY),
		.reason_result = hton8(reason),
		.error_code = hton8(err_code),
	};

	return post_msg(conn, &msg, sizeof(msg));
}
static int pptp_stop_ctrl_conn_rqst(struct pptp_conn_t *conn)
{
	struct pptp_stop_ctrl_conn *msg = (struct pptp_stop_ctrl_conn *)conn->in_buf;
	log_info("PPTP_STOP_CTRL_CONN_RQST reason=%i error_code=%i\n",msg->reason_result, msg->error_code);

	if (conn->state == STATE_PPP) {
		conn->state = STATE_FIN;
		ppp_terminate(&conn->ppp, 0);
	}

	//conn->hnd.twait=1000;

	send_pptp_stop_ctrl_conn_rply(conn, PPTP_CONN_STOP_OK, 0);
	return -1;
}

static int send_pptp_start_ctrl_conn_rply(struct pptp_conn_t *conn, int res_code, int err_code)
{
	struct pptp_start_ctrl_conn msg = {
		.header = PPTP_HEADER_CTRL(PPTP_START_CTRL_CONN_RPLY),
		.version = htons(PPTP_VERSION),
		.result_code = res_code,
		.error_code = err_code,
		.framing_cap = htonl(PPTP_FRAME_SYNC),
		.bearer_cap = htonl(0),
		.max_channels = htons(1),
		.firmware_rev = htons(PPTP_FIRMWARE_VERSION),
	};

	memset(msg.hostname, 0, sizeof(msg.hostname));
	strcpy((char*)msg.hostname, PPTP_HOSTNAME);

	memset(msg.vendor, 0, sizeof(msg.vendor));
	strcpy((char*)msg.vendor, PPTP_VENDOR);

	return post_msg(conn, &msg, sizeof(msg));
}
static int pptp_start_ctrl_conn_rqst(struct pptp_conn_t *conn)
{
	struct pptp_start_ctrl_conn *msg = (struct pptp_start_ctrl_conn *)conn->in_buf;

	if (conn->state != STATE_IDLE) {
		log_info("unexpected PPTP_START_CTRL_CONN_RQST\n");
		if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_EXISTS, 0))
			return -1;
		return 0;
	}

	if (msg->version != htons(PPTP_VERSION)) {
		log_info("PPTP version mismatch: expecting %x, received %s\n", PPTP_VERSION, msg->version);
		if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_PROTOCOL, 0))
			return -1;
		return 0;
	}
	if (!(ntohl(msg->framing_cap) & PPTP_FRAME_SYNC)) {
		log_info("connection does not supports sync mode\n");
		if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_GE, 0))
			return -1;
		return 0;
	}
	if (send_pptp_start_ctrl_conn_rply(conn, PPTP_CONN_RES_SUCCESS, 0))
		return -1;

	conn->state = STATE_ESTB;

	return 0;
}

static int send_pptp_out_call_rply(struct pptp_conn_t *conn, struct pptp_out_call_rqst *rqst, int call_id, int res_code, int err_code)
{
	struct pptp_out_call_rply msg = {
		.header = PPTP_HEADER_CTRL(PPTP_OUT_CALL_RPLY),
		.call_id = htons(call_id),
		.call_id_peer = rqst->call_id,
		.result_code = res_code,
		.error_code = err_code,
		.cause_code = 0,
		.speed = rqst->bps_max,
		.recv_size = rqst->recv_size,
		.delay = 0,
		.channel = 0,
	};

	return post_msg(conn, &msg, sizeof(msg));
}

static int pptp_out_call_rqst(struct pptp_conn_t *conn)
{
	struct pptp_out_call_rqst *msg = (struct pptp_out_call_rqst *)conn->in_buf;
	struct sockaddr_pppox src_addr, dst_addr;
  struct sockaddr_in addr;
	socklen_t addrlen;
	int pptp_sock;

	if (conn->state != STATE_ESTB) {
		log_info("unexpected PPTP_OUT_CALL_RQST\n");
		if (send_pptp_out_call_rply(conn, msg, 0, PPTP_CALL_RES_GE, PPTP_GE_NOCONN))
			return -1;
		return 0;
	}

	src_addr.sa_family = AF_PPPOX;
	src_addr.sa_protocol = PX_PROTO_PPTP;
	src_addr.sa_addr.pptp.call_id = 0;
	addrlen = sizeof(addr);
	getsockname(conn->hnd.fd, (struct sockaddr*)&addr, &addrlen);
	src_addr.sa_addr.pptp.sin_addr = addr.sin_addr;

	dst_addr.sa_family = AF_PPPOX;
	dst_addr.sa_protocol = PX_PROTO_PPTP;
	dst_addr.sa_addr.pptp.call_id = htons(msg->call_id);
	addrlen = sizeof(addr);
	getpeername(conn->hnd.fd, (struct sockaddr*)&addr, &addrlen);
	dst_addr.sa_addr.pptp.sin_addr = addr.sin_addr;

	pptp_sock = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_PPTP);
	if (pptp_sock < 0) {
		log_error("failed to create PPTP socket (%s)\n", strerror(errno));
		return -1;
	}
	if (bind(pptp_sock, (struct sockaddr*)&src_addr, sizeof(src_addr))) {
		log_error("failed to bind PPTP socket (%s)\n", strerror(errno));
		close(pptp_sock);
		return -1;
	}
	addrlen = sizeof(src_addr);
	getsockname(pptp_sock, (struct sockaddr*)&src_addr, &addrlen);

	if (connect(pptp_sock, (struct sockaddr*)&dst_addr, sizeof(dst_addr))) {
		log_error("failed to connect PPTP socket (%s)\n", strerror(errno));
		close(pptp_sock);
		return -1;
	}

	if (send_pptp_out_call_rply(conn, msg, src_addr.sa_addr.pptp.call_id, PPTP_CALL_RES_OK, 0))
		return -1;

	conn->ppp.fd = pptp_sock;
	conn->ppp.chan_name = strdup(inet_ntoa(dst_addr.sa_addr.pptp.sin_addr));
	conn->ppp.ctrl = &conn->ctrl;
	conn->ctrl.ctx = &conn->ctx;
	conn->ctrl.started = ppp_started;
	conn->ctrl.finished = ppp_finished;
	if (establish_ppp(&conn->ppp)) {
		close(pptp_sock);
		//if (send_pptp_stop_ctrl_conn_rqst(conn, 0, 0))
		//	return -1;
		conn->state = STATE_FIN;
		//conn->hnd.twait=1000;
		return -1;
	} else
		conn->state = STATE_PPP;

	return 0;
}

static int process_packet(struct pptp_conn_t *conn)
{
	struct pptp_header *hdr = (struct pptp_header *)conn->in_buf;
	switch(ntohs(hdr->ctrl_type))
	{
		case PPTP_START_CTRL_CONN_RQST:
			return pptp_start_ctrl_conn_rqst(conn);
		case PPTP_STOP_CTRL_CONN_RQST:
			return pptp_stop_ctrl_conn_rqst(conn);
		case PPTP_OUT_CALL_RQST:
			return pptp_out_call_rqst(conn);
	}
	return 0;
}

static int pptp_read(struct triton_md_handler_t *h)
{
	struct pptp_conn_t *conn=container_of(h,typeof(*conn),hnd);
	struct pptp_header *hdr=(struct pptp_header *)conn->in_buf;
	int n;

	while(1) {
		n = read(h->fd,conn->in_buf,PPTP_CTRL_SIZE_MAX-conn->in_size);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0;
			log_error("pptp: read: %s\n",strerror(errno));
			goto drop;
		}
		if (n == 0)
			goto drop;
		conn->in_size += n;
		if (conn->in_size >= sizeof(*hdr)) {
			if (hdr->magic != htonl(PPTP_MAGIC))
				goto drop;
			if (ntohs(hdr->length) >= PPTP_CTRL_SIZE_MAX)
				goto drop;
			if (ntohs(hdr->length) > conn->in_size)
				goto drop;
			if (ntohs(hdr->length) == conn->in_size) {
				if (ntohs(hdr->length) != PPTP_CTRL_SIZE(ntohs(hdr->ctrl_type)))
					goto drop;
				if (process_packet(conn))
					goto drop;
				conn->in_size = 0;
			}
		}
	}
drop:
	disconnect(conn);
	return 1;
}
static int pptp_write(struct triton_md_handler_t *h)
{
	struct pptp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	int n;

	while (1) {
		n = write(h->fd, conn->out_buf+conn->out_pos, conn->out_size-conn->out_pos);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				n = 0;
			else {
				if (errno != EPIPE)
					log_error("pptp:post_msg: %s\n", strerror(errno));
				disconnect(conn);
				return 1;
			}
		}

		conn->out_pos += n;
		if (conn->out_pos == conn->out_size) {
			conn->out_pos = 0;
			conn->out_size = 0;
			triton_md_disable_handler(h, MD_MODE_WRITE);
			return 0;
		}
	}
}
static void pptp_timeout(struct triton_md_handler_t *h)
{
}
static void pptp_close(struct triton_ctx_t *ctx)
{
	struct pptp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);
	if (conn->state == STATE_PPP) {
		conn->state = STATE_FIN;
		ppp_terminate(&conn->ppp, 0);
	} else
		disconnect(conn);
}
static void ppp_started(struct ppp_t *ppp)
{
	log_msg("ppp_started\n");
}
static void ppp_finished(struct ppp_t *ppp)
{
	struct pptp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_msg("ppp_finished\n");
	close(conn->ppp.fd);
	//send_pptp_stop_ctrl_conn_rqst(conn, 0, 0);
	if (conn->state != STATE_CLOSE) {
		conn->state = STATE_CLOSE;
		disconnect(conn);
	}
}

//==================================

struct pptp_serv_t
{
	struct triton_ctx_t ctx;
	struct triton_md_handler_t hnd;
};

static int pptp_connect(struct triton_md_handler_t *h)
{
  struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock;
	struct pptp_conn_t *conn;

	while(1) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("pptp: accept failed: %s\n", strerror(errno));
			continue;
		}

		log_info("pptp: new connection from %s\n", inet_ntoa(addr.sin_addr));

		if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
			log_error("pptp: failed to set nonblocking mode: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		conn = malloc(sizeof(*conn));
		memset(conn, 0, sizeof(*conn));
		conn->hnd.fd = sock;
		conn->hnd.read = pptp_read;
		conn->hnd.write = pptp_write;
		conn->ctx.close = pptp_close;
		conn->in_buf = malloc(PPTP_CTRL_SIZE_MAX);
		conn->out_buf = malloc(PPTP_CTRL_SIZE_MAX);

		triton_register_ctx(&conn->ctx);
		triton_md_register_handler(&conn->ctx, &conn->hnd);
		triton_md_enable_handler(&conn->hnd,MD_MODE_READ);
	}
	return 0;
}
static void pptp_serv_close(struct triton_ctx_t *ctx)
{
	struct pptp_serv_t *s=container_of(ctx,typeof(*s),ctx);
	triton_md_unregister_handler(&s->hnd);
	close(s->hnd.fd);
}

static struct pptp_serv_t serv=
{
	.hnd.read=pptp_connect,
	.ctx.close=pptp_serv_close,
};

static void __init pptp_init(void)
{
  struct sockaddr_in addr;
	
	serv.hnd.fd = socket (PF_INET, SOCK_STREAM, 0);
  if (serv.hnd.fd < 0) {
    log_error("pptp: failed to create server socket: %s\n", strerror(errno));
    return;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons (PPTP_PORT);
  addr.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
  	perror("pptp: bind");
    log_error("pptp: failed to bind socket: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
  }

  if (listen (serv.hnd.fd, 100) < 0) {
    log_error("pptp: failed to listen socket: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
  }

	if (fcntl(serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_error("pptp: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
	}
	
	triton_register_ctx(&serv.ctx);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
}

