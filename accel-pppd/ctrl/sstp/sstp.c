#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <termios.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#ifdef CRYPTO_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h> 
#endif

#include "triton.h"
#include "events.h"
#include "list.h"
#include "log.h"
#include "ppp.h"
#include "utils.h"
#include "mempool.h"
#include "iprange.h"
#include "connlimit.h"
#include "cli.h"

#include "memdebug.h"

#include "sstp_prot.h"

#ifndef min
#define min(x,y) ((x) < (y) ? (x) : (y))
#endif

struct sstp_serv_t {
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;

	//uint8_t certificate_hash[32];
};

struct sstp_conn_t {
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct triton_md_handler_t ppp_hnd;
	struct triton_timer_t timeout_timer;
	struct triton_timer_t hello_timer;

#ifdef CRYPTO_OPENSSL
	SSL_CTX *ssl_ctx;
	SSL *ssl;
#endif
	int state;
	int sstp_state;
	int hello_sent;

//	int bypass_auth:1;
//	char *http_cookie;
//	uint8_t auth_key[32];

	struct list_head send_queue;
	void *ppp_buf;
	uint8_t *in_buf;
	int in_size;

	struct ap_ctrl ctrl;
	struct ppp_t ppp;
};

struct sstp_pack_t {
	struct list_head entry;
	void *data;
	int size;
};

static int conf_timeout = SSTP_NEGOTIOATION_TIMEOUT;
static int conf_hello_interval = SSTP_HELLO_TIMEOUT;
static int conf_verbose = 0;
static int conf_ppp_max_mtu = SSTP_MAX_PACKET_SIZE - 8;
static int conf_hash_protocol = CERT_HASH_PROTOCOL_SHA256;
//static int conf_bypass_auth = 0;
static const char *conf_ip_pool;
static int conf_ssl = 1;
static char *conf_ssl_ciphers = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
static char *conf_ssl_ca_file = NULL;
static char *conf_ssl_pemfile = NULL;

static mempool_t conn_pool;
static mempool_t pack_pool;
static mempool_t data_pool; 

static unsigned int stat_starting;
static unsigned int stat_active;

static int sstp_msg_call_abort(struct sstp_conn_t *conn);
static int sstp_msg_call_disconnect(struct sstp_conn_t *conn);
static int sstp_send(struct sstp_conn_t *conn, void *data, int size);

/* http */

static char *http_getline(struct sstp_conn_t *conn, int *pos, char *buf, int size)
{
	unsigned char *src, *dst, c, pc;

	size = min(size - 1, conn->in_size - *pos);
	if (size <= 0)
		return NULL;

	src = conn->in_buf + *pos;
	dst = (unsigned char *)buf;
	for (pc = 0; size--; dst++) {
		c = *dst = *src++;
		if (c == '\0')
			break;
		if (c == '\n') {
			if (pc == '\r')
				dst--;
			break;
		}
		pc = c;
	}
	*dst = '\0';

	*pos = src - conn->in_buf;

	return buf;
}

static int send_http_response(struct sstp_conn_t *conn, char *proto, char *status, char *headers)
{
	char timebuf[80], *msg = mempool_alloc(data_pool);
	time_t now = time(NULL);

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	strftime(timebuf, sizeof(timebuf), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));
	snprintf(msg, SSTP_MAX_PACKET_SIZE,
		"%s %s\r\n"
		"%s"
		"Server: Microsoft-HTTPAPI/2.0\r\n"
		"Date: %s\r\n"
		"\r\n", proto, status, headers, timebuf);

	if (conf_verbose)
		log_ppp_debug("send [sstp HTTP reply <%s %s>]\n", proto, status);

	return sstp_send(conn, msg, strlen(msg));
}

static int http_request(struct sstp_conn_t *conn)
{
	char buf[1024];
	char *line, *method, *request, *proto;
	int pos = 0;

	if (conn->sstp_state != STATE_SERVER_CALL_DISCONNECTED)
		return -1;

	line = http_getline(conn, &pos, buf, sizeof(buf));
	if (line == NULL)
		goto error;
	if (conf_verbose)
		log_ppp_debug("recv [sstp HTTP request <%s>]\n", line);

	method = strsep(&line, " ");
	request = strsep(&line, " ");
	proto = strsep(&line, " ");

	if (!method || !request || !proto) {
		send_http_response(conn, "HTTP/1.1", "400 Bad Request", NULL);
		goto error;
	}
	if (strncmp(proto, "HTTP/1", sizeof("HTTP/1") - 1) != 0) {
		send_http_response(conn, "HTTP/1.1", "505 HTTP Version Not Supported", NULL);
		goto error;
	}
	if (strcmp(method, SSTP_HTTP_METHOD) != 0) {
		send_http_response(conn, proto, "405 Method Not Allowed", NULL);
		goto error;
	}
	if (strcmp(request, SSTP_HTTP_URI) != 0) {
		send_http_response(conn, proto, "404 Not Found", NULL);
		goto error;
	}

	while ((line = http_getline(conn, &pos, buf, sizeof(buf))) != NULL) {
		if (*line == '\0')
			break;
		if (conf_verbose)
			log_ppp_debug("recv [sstp HTTP request <%s>]\n", line);
	} while (*line);

	if (send_http_response(conn, proto, "200 OK",
			"Content-Length: 18446744073709551615\r\n")) {
		goto error;
	}
	conn->sstp_state = STATE_SERVER_CONNECT_REQUEST_PENDING;

	return pos;

error:
	return -1;
}

/* ppp */

static int ppp_allocate_pty(int *master, int *slave, int flags)
{
	struct termios tios;
	char pty_name[16];
	int value, mfd, sfd = -1;

	mfd = open("/dev/ptmx", O_RDWR | flags);
	if (mfd < 0) {
		log_ppp_error("sstp: can't open pty %s: %s\n", "/dev/ptmx", strerror(errno));
		return -1;
	}

	if (ioctl(mfd, TIOCGPTN, &value) < 0) {
		log_ppp_error("sstp: can't allocate slave pty: %s\n", strerror(errno));
		goto error;
	}
	snprintf(pty_name, sizeof(pty_name), "/dev/pts/%d", value);

	value = 0;
	if (ioctl(mfd, TIOCSPTLCK, &value) < 0)
		log_ppp_warn("sstp: can't unlock pty %s: %s\n", pty_name, strerror(errno));

	sfd = open(pty_name, O_RDWR | O_NOCTTY | flags);
	if (sfd < 0) {
		log_ppp_error("sstp: can't open pty %s: %s\n", pty_name, strerror(errno));
		goto error;
	}

	if (tcgetattr(sfd, &tios) == 0) {
		tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB);
		tios.c_cflag |= CS8 | CREAD | CLOCAL;
		tios.c_iflag  = IGNPAR;
		tios.c_oflag  = 0;
		tios.c_lflag  = 0;
		if (tcsetattr(sfd, TCSAFLUSH, &tios) < 0)
			log_ppp_warn("sstp: can't set attributes on pty: %s\n", strerror(errno));
	}

	value = N_HDLC;
	if (ioctl(mfd, TIOCSETD, &value) < 0) {
		log_ppp_error("sstp: can't set N_HDLC line discipline: %s", strerror(errno));
		goto error;
	}

	value = N_SYNC_PPP;
	if (ioctl(sfd, TIOCSETD, &value) < 0) {
		log_ppp_error("sstp: can't set N_SYNC_PPP line discipline: %s", strerror(errno));
		goto error;
	}

	*master = mfd;
	*slave = sfd;
	return 0;

error:
	if (mfd >= 0)
		close(mfd);
	if (sfd >= 0)
		close(sfd);
	return -1;
}

static void ppp_started(struct ap_session *ses)
{
	log_ppp_debug("sstp: ppp started\n");
}

static void ppp_finished(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct sstp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	if (conn->state != STATE_CLOSE) {
		log_ppp_debug("sstp: ppp finished\n");
		__sync_sub_and_fetch(&stat_active, 1);
		conn->state = STATE_CLOSE;
		sstp_msg_call_abort(conn);
	}
}

static int ppp_read(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), ppp_hnd);
	struct sstp_hdr *hdr;
	int n;

	hdr = conn->ppp_buf ? : mempool_alloc(data_pool);
	if (!hdr) {
		log_error("sstp: no memory\n");
		return -1;
	}

again:
	n = read(h->fd, hdr->data, SSTP_MAX_PACKET_SIZE - sizeof(*hdr));

//int err = errno;
//log_ppp_info2("sstp: ppp.read = %d [%02x%02x...] errno %d %s\n", n,
//	(n > 0) ? hdr->data[0] : 0,
//	(n > 1) ? hdr->data[1] : 0,
//	(n < 0) ? errno : 0, (n < 0) ? strerror(errno) : "");
//errno = err;

	if (n < 0) {
		if (errno == EINTR)
			goto again;
		if (errno == EAGAIN) {
			conn->ppp_buf = hdr;
			return 0;
		}
		if (errno != EPIPE && conf_verbose)
			log_ppp_error("ppp error: %s\n", strerror(errno));
		goto drop;
	}
	if (n == 0) {
		if (conf_verbose)
			log_ppp_info2("ppp error\n");
		goto drop;
	}

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED_PENDING:
	case STATE_SERVER_CALL_CONNECTED:
		break;
	default:
		goto drop;
	}

	n += sizeof(*hdr);
	INIT_SSTP_DATA_HDR(hdr, n);

	if (sstp_send(conn, hdr, n))
		goto drop;

	conn->ppp_buf = NULL;
	return 0;

drop:
	conn->ppp_buf = hdr;
	return 1;
}

/* sstp */

static void sstp_ctx_switch(struct triton_context_t *ctx, void *arg)
{
	if (arg) {
		struct ap_session *s = arg;
		net = s->net;
	} else
		net = def_net;
	log_switch(ctx, arg);
}

static void sstp_timer_set(struct triton_context_t *ctx, struct triton_timer_t *t, int timeout)
{
	t->period = timeout * 1000;

	if (timeout == 0)
		triton_timer_del(t);
	else if (t->tpd)
		triton_timer_mod(t, 0);
	else
		triton_timer_add(ctx, t, 0);
}

static void sstp_disconnect(struct sstp_conn_t *conn)
{
	struct sstp_pack_t *pack;

	log_ppp_debug("sstp: disconnect\n");

#ifdef CRYPTO_OPENSSL
	if (conn->ssl)
		SSL_free(conn->ssl);
#endif
	triton_md_unregister_handler(&conn->hnd, 1);

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	if (conn->state == STATE_PPP) {
		__sync_sub_and_fetch(&stat_active, 1);
		conn->state = STATE_CLOSE;
		ap_session_terminate(&conn->ppp.ses, TERM_LOST_CARRIER, 1);
	} else if (conn->state != STATE_CLOSE)
		__sync_sub_and_fetch(&stat_starting, 1);

	if (conn->ppp_hnd.tpd)
		triton_md_unregister_handler(&conn->ppp_hnd, 1);

	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp.ses);

	log_ppp_info1("disconnected\n");

#ifdef CRYPTO_OPENSSL
	if (conn->ssl_ctx)
		SSL_CTX_free(conn->ssl_ctx);
#endif
	triton_context_unregister(&conn->ctx);

	while (!list_empty(&conn->send_queue)) {
		pack = list_first_entry(&conn->send_queue, typeof(*pack), entry);
		list_del(&pack->entry);
		mempool_free(pack->data);
		mempool_free(pack);
	}

	if (conn->ppp_buf)
		mempool_free(conn->ppp_buf);
	_free(conn->in_buf);
	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);
	mempool_free(conn);
}

static int send_sstp_msg_call_connect_ack(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_crypto_binding_request attr;
	} __attribute__((packed)) *msg = mempool_alloc(data_pool);

	if (conf_verbose)
		log_ppp_info2("send [sstp SSTP_MSG_CALL_CONNECT_ACK]\n");

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_CONNECT_ACK, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_CRYPTO_BINDING_REQ, sizeof(msg->attr));
	msg->attr.hash_protocol_bitmask = conf_hash_protocol;
	//read(urandom_fd, msg->attr.nonce, sizeof(msg->attr.nonce));
	memset(msg->attr.nonce, 0, sizeof(msg->attr.nonce));

	return sstp_send(conn, msg, sizeof(*msg));
}

static int send_sstp_msg_call_connect_nak(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
		uint16_t attr_value;
	} __attribute__((packed)) *msg = mempool_alloc(data_pool);

	if (conf_verbose)
		log_ppp_info2("send [sstp SSTP_MSG_CALL_CONNECT_NAK]\n");

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_CONNECT_NAK, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID;
	msg->attr.status = htonl(ATTRIB_STATUS_VALUE_NOT_SUPPORTED);
	msg->attr_value = 0;

	return sstp_send(conn, msg, sizeof(*msg));
}

static int send_sstp_msg_call_abort(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
	} __attribute__((packed)) *msg = mempool_alloc(data_pool);

	if (conf_verbose)
		log_ppp_info2("send [sstp SSTP_MSG_CALL_ABORT]\n");

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_ABORT, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_STATUS_INFO;
	msg->attr.status = htonl(ATTRIB_STATUS_INVALID_FRAME_RECEIVED);

	if (sstp_send(conn, msg, sizeof(*msg)))
		return -1;

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_IN_PROGRESS_1:
		sstp_timer_set(&conn->ctx, &conn->timeout_timer, SSTP_ABORT_TIMEOUT_1);
		conn->sstp_state = STATE_CALL_ABORT_PENDING;
		break;
	case STATE_CALL_ABORT_IN_PROGRESS_2:
		sstp_timer_set(&conn->ctx, &conn->timeout_timer, SSTP_ABORT_TIMEOUT_2);
		conn->sstp_state = STATE_CALL_ABORT_TIMEOUT_PENDING;
		break;
	}

	return 0;
}

static int send_sstp_msg_call_disconnect(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
	} __attribute__((packed)) *msg = mempool_alloc(data_pool);

	if (conf_verbose)
		log_ppp_info2("send [sstp SSTP_MSG_CALL_DISCONNECT]\n");

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_DISCONNECT, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_NO_ERROR;
	msg->attr.status = htonl(ATTRIB_STATUS_NO_ERROR);

	if (sstp_send(conn, msg, sizeof(*msg)))
		return -1;

	switch (conn->sstp_state) {
	case STATE_CALL_DISCONNECT_IN_PROGRESS_1:
		sstp_timer_set(&conn->ctx, &conn->timeout_timer, SSTP_DISCONNECT_TIMEOUT_1);
		conn->sstp_state = STATE_CALL_DISCONNECT_ACK_PENDING;
		break;
	case STATE_CALL_DISCONNECT_IN_PROGRESS_2:
		sstp_timer_set(&conn->ctx, &conn->timeout_timer, SSTP_DISCONNECT_TIMEOUT_2);
		conn->sstp_state = STATE_CALL_DISCONNECT_TIMEOUT_PENDING;
		break;
	default:
		break;
	}

	return 0;
}

static int send_sstp_msg_call_disconnect_ack(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg = mempool_alloc(data_pool);

	if (conf_verbose)
		log_ppp_info2("send [sstp SSTP_MSG_CALL_DISCONNECT_ACK]\n");

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_DISCONNECT_ACK, 0, sizeof(*msg));

	return sstp_send(conn, msg, sizeof(*msg));
}

static int send_sstp_msg_echo_request(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg = mempool_alloc(data_pool);

	if (conf_verbose)
		log_ppp_info2("send [sstp SSTP_MSG_ECHO_REQUEST]\n");

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_ECHO_REQUEST, 0, sizeof(*msg));

	return sstp_send(conn, msg, sizeof(*msg));
}

static int send_sstp_msg_echo_response(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg = mempool_alloc(data_pool);

	if (conf_verbose)
		log_ppp_info2("send [sstp SSTP_MSG_ECHO_RESPONSE]\n");

	if (!msg) {
		log_error("sstp: no memory\n");
		return -1;
	}

	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_ECHO_RESPONSE, 0, sizeof(*msg));

	return sstp_send(conn, msg, sizeof(*msg));
}

static int sstp_msg_call_connect_request(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_encapsulated_protocol attr;
	} __attribute__((packed)) *msg = (void *)conn->in_buf;
	int master, slave;

	if (conf_verbose)
		log_ppp_info2("recv [sstp SSTP_MSG_CALL_CONNECT_REQUEST]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_SERVER_CONNECT_REQUEST_PENDING:
		break;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		if (send_sstp_msg_call_abort(conn))
			return -1;
		return 0;
	}

	if (ntohs(msg->hdr.length) < sizeof(*msg) ||
	    ntohs(msg->hdr.num_attributes) < 1 ||
	    msg->attr.hdr.attribute_id != SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID ||
	    ntohs(msg->attr.hdr.length) < sizeof(msg->attr)) {
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		if (send_sstp_msg_call_abort(conn))
			return -1;
		return 0;
	}
	if (ntohs(msg->attr.protocol_id) != SSTP_ENCAPSULATED_PROTOCOL_PPP) {
		if (send_sstp_msg_call_connect_nak(conn))
			return -1;
		return 0;
	}

	if (ppp_allocate_pty(&master, &slave, O_CLOEXEC | O_NONBLOCK) < 0)
		return -1;

	conn->ppp_hnd.fd = master;
	conn->ppp_hnd.read = ppp_read;
	triton_md_register_handler(&conn->ctx, &conn->ppp_hnd);
	triton_md_enable_handler(&conn->ppp_hnd, MD_MODE_READ);

	triton_event_fire(EV_CTRL_STARTED, &conn->ppp.ses);

	if (send_sstp_msg_call_connect_ack(conn))
		goto error;
	conn->sstp_state = STATE_SERVER_CALL_CONNECTED_PENDING;

	conn->ppp.fd = slave;
	if (establish_ppp(&conn->ppp)) {
		conn->state = STATE_FIN;
		goto error;
	}

	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);
	conn->state = STATE_PPP;

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	if (conn->hello_timer.tpd)
		triton_timer_mod(&conn->hello_timer, 0);
	else if (conn->hello_timer.period)
		triton_timer_add(&conn->ctx, &conn->hello_timer, 0);

	return 0;

error:
	if (conn->ppp_hnd.tpd)
		triton_md_unregister_handler(&conn->ppp_hnd, 0);
	close(master);
	close(slave);
	return -1;
}

static int sstp_msg_call_connected(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [sstp SSTP_MSG_CALL_CONNECTED]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_SERVER_CALL_CONNECTED_PENDING:
		break;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		if (send_sstp_msg_call_abort(conn))
			return -1;
		return 0;
	}

	conn->sstp_state = STATE_SERVER_CALL_CONNECTED;

	if (conn->hello_timer.tpd)
		triton_timer_mod(&conn->hello_timer, 0);
	else if (conn->hello_timer.period)
		triton_timer_add(&conn->ctx, &conn->hello_timer, 0);

	return 0;
}

static int sstp_msg_call_abort(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [sstp SSTP_MSG_CALL_ABORT]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_PENDING:
		sstp_timer_set(&conn->ctx, &conn->timeout_timer, SSTP_ABORT_TIMEOUT_2);
		conn->sstp_state = STATE_CALL_ABORT_TIMEOUT_PENDING;
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		break;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_2;
		if (send_sstp_msg_call_abort(conn))
			return -1;
		break;
	}

	return 0;
}

static int sstp_msg_call_disconnect(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [sstp SSTP_MSG_CALL_DISCONNECT]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		break;
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		sstp_timer_set(&conn->ctx, &conn->timeout_timer, 0);
		/* fall through */
	default:
		conn->sstp_state = STATE_CALL_DISCONNECT_IN_PROGRESS_2;
		if (send_sstp_msg_call_disconnect_ack(conn))
			return -1;
		break;
	}

	return 0;
}

static int sstp_msg_call_disconnect_ack(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [sstp SSTP_MSG_CALL_DISCONNECT_ACK]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		sstp_disconnect(conn);
		conn->sstp_state = STATE_SERVER_CALL_DISCONNECTED;
		break;
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		break;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		if (send_sstp_msg_call_abort(conn))
			return -1;
		break;
	}

	return 0;
}

static int sstp_msg_echo_request(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [sstp SSTP_MSG_ECHO_REQUEST]\n");

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		conn->hello_sent = 0;
		if (conn->hello_timer.tpd)
			triton_timer_mod(&conn->hello_timer, 0);
		if (send_sstp_msg_echo_response(conn))
			return -1;
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		break;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		if (send_sstp_msg_call_abort(conn))
			return -1;
		break;
	}

	return 0;
}

static int sstp_msg_echo_response(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_ppp_info2("recv [sstp SSTP_MSG_ECHO_RESPONSE]\n");

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		conn->hello_sent = 0;
		if (conn->hello_timer.tpd)
			triton_timer_mod(&conn->hello_timer, 0);
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		break;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		if (send_sstp_msg_call_abort(conn))
			return -1;
		break;
	}

	return 0;
}

static int sstp_data_packet(struct sstp_conn_t *conn)
{
	struct sstp_hdr *hdr = (struct sstp_hdr *)conn->in_buf;
	int n, pos, size;

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED_PENDING:
	case STATE_SERVER_CALL_CONNECTED:
		break;
	default:
		return 0;
	}

	pos = 0;
	size = ntohs(hdr->length) - sizeof(*hdr);
	while (pos < size) {
		n = write(conn->ppp_hnd.fd, hdr->data + pos, size - pos);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
			else {
				if (conf_verbose && errno != EPIPE)
					log_ppp_info2("sstp: write ppp: %s\n", strerror(errno));
				return -1;
			}
		}
		pos += n;
	}

	return 0;
}

static int sstp_packet(struct sstp_conn_t *conn)
{
	struct sstp_ctrl_hdr *hdr = (struct sstp_ctrl_hdr *)conn->in_buf;

	switch (hdr->reserved) {
	case SSTP_DATA_PACKET:
		return sstp_data_packet(conn);
	case SSTP_CTRL_PACKET:
		break;
	default:
		log_ppp_warn("recv [sstp Unknown packet type %02x]\n", hdr->reserved);
		return -1;
	}

	switch (ntohs(hdr->message_type)) {
	case SSTP_MSG_CALL_CONNECT_REQUEST:
		return sstp_msg_call_connect_request(conn);
	case SSTP_MSG_CALL_CONNECT_ACK:
	case SSTP_MSG_CALL_CONNECT_NAK:
		break;
	case SSTP_MSG_CALL_CONNECTED:
		return sstp_msg_call_connected(conn);
	case SSTP_MSG_CALL_ABORT:
		return sstp_msg_call_abort(conn);
	case SSTP_MSG_CALL_DISCONNECT:
		return sstp_msg_call_disconnect(conn);
	case SSTP_MSG_CALL_DISCONNECT_ACK:
		return sstp_msg_call_disconnect_ack(conn);
	case SSTP_MSG_ECHO_REQUEST:
		return sstp_msg_echo_request(conn);
	case SSTP_MSG_ECHO_RESPONSE:
		return sstp_msg_echo_response(conn);
	default:
		log_ppp_warn("recv [sstp Unknown message type %04x]\n", ntohs(hdr->message_type));
	}

	return 0;
}

static int sstp_read(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct sstp_hdr *hdr = (void *)conn->in_buf;
	int n, size;
#ifdef CRYPTO_OPENSSL
	int err, ssl_err;
#endif

	while (1) {
#ifdef CRYPTO_OPENSSL
		if (conn->ssl) {
			ERR_clear_error();
			n = SSL_read(conn->ssl, conn->in_buf + conn->in_size, SSTP_MAX_PACKET_SIZE - conn->in_size);
//err = errno;
//log_ppp_info2("sstp: sstp.read = %d/%d errno %d %s\n", n, SSTP_MAX_PACKET_SIZE - conn->in_size, (n < 0) ? errno : 0, (n < 0) ? strerror(errno) : "");
//errno = err;
			if (n < 0) {
				err = errno;
				ssl_err = SSL_get_error(conn->ssl, n);
				switch (ssl_err) {
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
					return 0;
				case SSL_ERROR_ZERO_RETURN:
					n = 0;
					break;
				case SSL_ERROR_SYSCALL:
					if (err == EINTR)
						continue;
					if (err == EAGAIN)
						return 0;
					log_ppp_error("sstp: SSL read: %s\n", strerror(err));
					goto drop;
				default:
					log_ppp_error("sstp: SSL read: %s\n", ERR_error_string(ssl_err, NULL));
					goto drop;
				}
			}
		} else
#endif
		{
			n = read(h->fd, conn->in_buf + conn->in_size, SSTP_MAX_PACKET_SIZE - conn->in_size);
//err = errno;
//log_ppp_info2("sstp: sstp.read = %d/%d errno %d %s\n", n, SSTP_MAX_PACKET_SIZE - conn->in_size, (n < 0) ? errno : 0, (n < 0) ? strerror(errno) : "");
//errno = err;
			if (n < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					return 0;
				log_ppp_error("sstp: read: %s\n", strerror(errno));
				goto drop;
			}
		}

		if (n == 0) {
			if (conf_verbose)
				log_ppp_info2("sstp: disconnect by peer\n");
			goto drop;
		}

		conn->in_size += n;

		if (conn->sstp_state == STATE_SERVER_CALL_DISCONNECTED) {
			size = http_request(conn);
			if (size < 0)
				goto drop;
			conn->in_size -= size;
			if (conn->in_size)
				memmove(conn->in_buf, conn->in_buf + size, conn->in_size);
		}

		if (conn->in_size >= sizeof(*hdr)) {
			if (hdr->version != SSTP_VERSION) {
				log_ppp_error("sstp: invalid version %d\n", hdr->version);
				goto drop;
			}
			size = ntohs(hdr->length);
			if (size > SSTP_MAX_PACKET_SIZE) {
				log_ppp_error("sstp: message is too long\n");
				goto drop;
			}
			if (size <= conn->in_size) {
				if (sstp_packet(conn))
					goto drop;
				conn->in_size -= size;
				if (conn->in_size)
					memmove(conn->in_buf, conn->in_buf + size, conn->in_size);
			}
		}
	}
drop:
	sstp_disconnect(conn);
	return 1;
}

static int sstp_write(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct sstp_pack_t *pack;
	int n;
#ifdef CRYPTO_OPENSSL
	int err, ssl_err;
#endif

	while (!list_empty(&conn->send_queue)) {
		pack = list_first_entry(&conn->send_queue, typeof(*pack), entry);
	again:
#ifdef CRYPTO_OPENSSL
		if (conn->ssl) {
			ERR_clear_error();
			n = SSL_write(conn->ssl, pack->data, pack->size);
//err = errno;
//log_ppp_info2("sstp: sstp.write = %d/%d errno %d %s\n", n, pack->size, (n < 0) ? errno : 0, (n < 0) ? strerror(errno) : "");
//errno = err;
			if (n < 0) {
				err = errno;
				ssl_err = SSL_get_error(conn->ssl, n);
				switch (ssl_err) {
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_ZERO_RETURN:
					n = 0;
					break;
				case SSL_ERROR_SYSCALL:
					if (err == EINTR)
						goto again;
					if (err == EAGAIN)
						n = 0;
					else {
						if (conf_verbose && err != EPIPE)
							log_ppp_info2("sstp: write: %s\n", strerror(errno));
						goto drop;
					}
					break;
				default:
					log_ppp_error("sstp: SSL write: %s\n", ERR_error_string(ssl_err, NULL));
					goto drop;
				}
			}
		} else
#endif
		{
			n = write(h->fd, pack->data, pack->size);
//err = errno;
//log_ppp_info2("sstp: sstp.write = %d/%d errno %d %s\n", n, pack->size, (n < 0) ? errno : 0, (n < 0) ? strerror(errno) : "");
//errno = err;
			if (n < 0) {
				if (errno == EINTR)
					goto again;
				if (errno == EAGAIN)
					n = 0;
				else {
					if (conf_verbose && errno != EPIPE)
						log_ppp_info2("sstp: write: %s\n", strerror(errno));
					goto drop;
				}
			}
		}

		if (n == 0)
			break;

		list_del(&pack->entry);
		mempool_free(pack->data);
		mempool_free(pack);
	}

	if (list_empty(&conn->send_queue))
		triton_md_disable_handler(h, MD_MODE_WRITE);

	return 0;

drop:
	sstp_disconnect(conn);
	return 1;
}

static int sstp_send(struct sstp_conn_t *conn, void *data, int size)
{
	struct sstp_pack_t *pack;
	int queue_empty = list_empty(&conn->send_queue);

	pack = mempool_alloc(pack_pool);
	if (!pack) {
		log_debug("sstp: packet: allocation fail\n");
		return -1;
	}

	memset(pack, 0, sizeof(*pack));
	pack->data = data;
	pack->size = size;
	list_add_tail(&pack->entry, &conn->send_queue);

	if (queue_empty)
		return sstp_write(&conn->hnd);

	triton_md_enable_handler(&conn->hnd, MD_MODE_WRITE);

	return 0;
}

static void sstp_msg_echo(struct triton_timer_t *t)
{
	struct sstp_conn_t *conn = container_of(t, typeof(*conn), hello_timer);

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		if (conn->hello_sent++) {
			log_ppp_warn("sstp: no echo reply\n");
			conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
			send_sstp_msg_call_abort(conn);
		} else
			send_sstp_msg_echo_request(conn);
		break;
	}
}

static void sstp_timeout(struct triton_timer_t *t)
{
	struct sstp_conn_t *conn = container_of(t, typeof(*conn), timeout_timer);

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		sstp_disconnect(conn);
		break;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		send_sstp_msg_call_abort(conn);
		break;
	}
}

static void sstp_close(struct triton_context_t *ctx)
{
	struct sstp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	if (conn->state == STATE_PPP) {
		__sync_sub_and_fetch(&stat_active, 1);
		conn->state = STATE_CLOSE;
		ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 1);
		conn->sstp_state = STATE_CALL_DISCONNECT_IN_PROGRESS_1;
		send_sstp_msg_call_disconnect(conn);
	} else {
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_1;
		send_sstp_msg_call_abort(conn);
	}
}

static void sstp_starting(struct sstp_conn_t *conn)
{
	log_ppp_debug("sstp: starting\n");

#ifdef CRYPTO_OPENSSL
	if (conf_ssl) {
		conn->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (!conn->ssl_ctx) {
			log_error("sstp: SSL_CTX error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		SSL_CTX_set_options(conn->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

		if (conf_ssl_ciphers &&
		    SSL_CTX_set_cipher_list(conn->ssl_ctx, conf_ssl_ciphers) != 1) {
			log_error("sstp: SSL cipher list error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}
		if (conf_ssl_ca_file &&
		    SSL_CTX_load_verify_locations(conn->ssl_ctx, conf_ssl_ca_file, NULL) != 1) {
			log_error("sstp: SSL ca file error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			return;
		}
		if (!conf_ssl_pemfile ||
		    SSL_CTX_use_certificate_file(conn->ssl_ctx, conf_ssl_pemfile, SSL_FILETYPE_PEM) != 1 ||
		    SSL_CTX_use_PrivateKey_file(conn->ssl_ctx, conf_ssl_pemfile, SSL_FILETYPE_PEM) != 1 ||
		    SSL_CTX_check_private_key(conn->ssl_ctx) != 1) {
			log_error("sstp: SSL certificate error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		SSL_CTX_set_default_read_ahead(conn->ssl_ctx, 1);
		SSL_CTX_set_mode(conn->ssl_ctx, SSL_CTX_get_mode(conn->ssl_ctx) | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

		conn->ssl = SSL_new(conn->ssl_ctx);
		if (!conn->ssl) {
			log_error("sstp: SSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		SSL_set_accept_state(conn->ssl);
		if (SSL_set_fd(conn->ssl, conn->hnd.fd) != 1) {
			log_error("sstp: SSL bind error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}
	}
#endif

	triton_md_enable_handler(&conn->hnd, MD_MODE_READ);
	triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	return;

#ifdef CRYPTO_OPENSSL
error:
	sstp_disconnect(conn);
#endif
}

static int sstp_connect(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn;
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock, value;

	while(1) {
		sock = accept(h->fd, (struct sockaddr *)&addr, &size);
		if (sock < 0) {
			if (errno == EAGAIN)
				return 0;
			log_error("sstp: accept failed: %s\n", strerror(errno));
			continue;
		}

		if (ap_shutdown) {
			close(sock);
			continue;
		}

		if (triton_module_loaded("connlimit") && connlimit_check(cl_key_from_ipv4(addr.sin_addr.s_addr))) {
			close(sock);
			return 0;
		}

		log_info2("sstp: new connection from %s\n", inet_ntoa(addr.sin_addr));

		if (iprange_client_check(addr.sin_addr.s_addr)) {
			log_warn("sstp: IP is out of client-ip-range, droping connection...\n");
			close(sock);
			continue;
		}

		if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
			log_error("sstp: failed to set nonblocking mode: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		value = 1;
		if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0) {
			log_error("sstp: failed to disable nagle: %s, closing connection...\n", strerror(errno));
			close(sock);
			continue;
		}

		conn = mempool_alloc(conn_pool);
		memset(conn, 0, sizeof(*conn));

		conn->ctx.close = sstp_close;
		conn->ctx.before_switch = sstp_ctx_switch;
		conn->hnd.fd = sock;
		conn->hnd.read = sstp_read;
		conn->hnd.write = sstp_write;

		conn->timeout_timer.expire = sstp_timeout;
		conn->timeout_timer.period = conf_timeout * 1000;
		conn->hello_timer.expire = sstp_msg_echo;
		conn->hello_timer.period = conf_hello_interval * 1000;

		//conn->bypass_auth = conf_bypass_auth;
		//conn->http_cookie = NULL:
		//conn->auth_key...

		conn->in_buf = _malloc(SSTP_MAX_PACKET_SIZE);
		INIT_LIST_HEAD(&conn->send_queue);

		conn->ctrl.ctx = &conn->ctx;
		conn->ctrl.started = ppp_started;
		conn->ctrl.finished = ppp_finished;
		conn->ctrl.terminate = ppp_terminate;
		conn->ctrl.max_mtu = conf_ppp_max_mtu;
		conn->ctrl.type = CTRL_TYPE_SSTP;
		conn->ctrl.ppp = 1;
		conn->ctrl.name = "sstp";
		conn->ctrl.ifname = "";
		conn->ctrl.mppe = MPPE_UNSET;
		conn->ctrl.calling_station_id = _malloc(17);
		conn->ctrl.called_station_id = _malloc(17);
		u_inet_ntoa(addr.sin_addr.s_addr, conn->ctrl.calling_station_id);
		getsockname(sock, &addr, &size);
		u_inet_ntoa(addr.sin_addr.s_addr, conn->ctrl.called_station_id);

		ppp_init(&conn->ppp);
		conn->ppp.ses.ctrl = &conn->ctrl;
		conn->ppp.ses.chan_name = conn->ctrl.calling_station_id;
		if (conf_ip_pool)
			conn->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);

		triton_context_register(&conn->ctx, &conn->ppp.ses);
		triton_md_register_handler(&conn->ctx, &conn->hnd);
		triton_context_wakeup(&conn->ctx);

		triton_context_call(&conn->ctx, (void (*)(void*))sstp_starting, conn);

		triton_event_fire(EV_CTRL_STARTING, &conn->ppp.ses);

		__sync_add_and_fetch(&stat_starting, 1);
	}
	return 0;
}

static void sstp_serv_close(struct triton_context_t *ctx)
{
	struct sstp_serv_t *s = container_of(ctx, typeof(*s), ctx);

	triton_md_unregister_handler(&s->hnd, 1);
	triton_context_unregister(ctx);
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "sstp:\r\n");
	cli_sendv(client,"  starting: %u\r\n", stat_starting);
	cli_sendv(client,"  active: %u\r\n", stat_active);

	return CLI_CMD_OK;
}

void __export sstp_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("sstp", "ssl");
	if (opt)
		conf_ssl = atoi(opt);

	conf_ssl_ciphers = conf_get_opt("sstp", "ssl_ciphers");
	conf_ssl_ca_file = conf_get_opt("sstp", "ssl_ca_file");
	conf_ssl_pemfile = conf_get_opt("sstp", "ssl_pemfile");

	opt = conf_get_opt("sstp", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("sstp", "hello-interval");
	if (opt && atoi(opt) >= 0)
		conf_hello_interval = atoi(opt);

	opt = conf_get_opt("sstp", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	opt = conf_get_opt("sstp", "ppp-max-mtu");
	if (opt && atoi(opt) > 0)
		conf_ppp_max_mtu = atoi(opt);

	conf_ip_pool = conf_get_opt("sstp", "ip-pool");

	switch (iprange_check_activation()) {
	case IPRANGE_DISABLED:
		log_warn("sstp: iprange module disabled, improper IP configuration of PPP interfaces may cause kernel soft lockup\n");
		break;
	case IPRANGE_NO_RANGE:
		log_warn("sstp: no IP address range defined in section [%s], incoming sstp connections will be rejected\n",
			 IPRANGE_CONF_SECTION);
		break;
	default:
		/* Makes compiler happy */
		break;
	}

	//read(urandom_fd, &serv.certificate_hash, sizeof(serv.certificate_hash));
}

static struct sstp_serv_t serv = {
	.hnd.read = sstp_connect,
	.ctx.close = sstp_serv_close,
	.ctx.before_switch = sstp_ctx_switch,
};

static void sstp_init(void)
{
	struct sockaddr_in addr;
	char *opt;

#ifdef CRYPTO_OPENSSL
	SSL_load_error_strings();
	SSL_library_init();
#endif

	serv.hnd.fd = socket(PF_INET, SOCK_STREAM, 0);
	if (serv.hnd.fd < 0) {
		log_emerg("sstp: failed to create server socket: %s\n", strerror(errno));
		return;
	}

	fcntl(serv.hnd.fd, F_SETFD, fcntl(serv.hnd.fd, F_GETFD) | FD_CLOEXEC);

	addr.sin_family = AF_INET;

	opt = conf_get_opt("sstp", "bind");
	if (opt)
		addr.sin_addr.s_addr = inet_addr(opt);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

	opt = conf_get_opt("sstp", "port");
	if (opt && atoi(opt) > 0)
		addr.sin_port = htons(atoi(opt));
	else
		addr.sin_port = htons(SSTP_PORT);

	setsockopt(serv.hnd.fd, SOL_SOCKET, SO_REUSEADDR, &serv.hnd.fd, 4);

	if (bind(serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		log_emerg("sstp: failed to bind socket: %s\n", strerror(errno));
		close(serv.hnd.fd);
		return;
	}

	if (listen(serv.hnd.fd, 100) < 0) {
		log_emerg("sstp: failed to listen socket: %s\n", strerror(errno));
		close(serv.hnd.fd);
		return;
	}

	if (fcntl(serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
		log_emerg("sstp: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv.hnd.fd);
		return;
	}

	conn_pool = mempool_create(sizeof(struct sstp_conn_t));
	pack_pool = mempool_create(sizeof(struct sstp_pack_t));
	data_pool = mempool_create(SSTP_MAX_PACKET_SIZE);

	load_config();

	triton_context_register(&serv.ctx, NULL);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&serv.ctx);

	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(20, sstp_init);
