#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <termios.h>
#include <pty.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

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

#define log_sstp(log_func, conn, fmt, ...)				\
	do {								\
		log_func("sstp (%s): " fmt,				\
			 conn->ctrl.calling_station_id,			\
			 ##__VA_ARGS__);				\
	} while (0)
#define log_sstp_error(conn, fmt, ...) log_sstp(log_error, conn, fmt, ####__VA_ARGS__)
#define log_sstp_warn(conn, fmt, ...) log_sstp(log_warn, conn, fmt, ####__VA_ARGS__)
#define log_sstp_info1(conn, fmt, ...) log_sstp(log_info1, conn, fmt, ####__VA_ARGS__)
#define log_sstp_info2(conn, fmt, ...) log_sstp(log_info2, conn, fmt, ####__VA_ARGS__)
#define log_sstp_debug(conn, fmt, ...) log_sstp(log_debug, conn, fmt, ####__VA_ARGS__)
#define log_sstp_msg(conn, fmt, ...) log_sstp(log_msg, conn, fmt, ####__VA_ARGS__)

#define log_sstp_ppp(log_func, conn, fmt, ...)				\
	do {								\
		log_func("sstp (%s): " fmt,				\
			 conn->ctrl.ifname[0] ?	conn->ctrl.ifname :	\
			 conn->ctrl.calling_station_id,			\
			 ##__VA_ARGS__);				\
	} while (0)
#define log_sstp_ppp_error(conn, fmt, ...) log_sstp_ppp(log_ppp_error, conn, fmt, ####__VA_ARGS__)
#define log_sstp_ppp_warn(conn, fmt, ...) log_sstp_ppp(log_ppp_warn, conn, fmt, ####__VA_ARGS__)
#define log_sstp_ppp_info1(conn, fmt, ...) log_sstp_ppp(log_ppp_info1, conn, fmt, ####__VA_ARGS__)
#define log_sstp_ppp_info2(conn, fmt, ...) log_sstp_ppp(log_ppp_info2, conn, fmt, ####__VA_ARGS__)
#define log_sstp_ppp_debug(conn, fmt, ...) log_sstp_ppp(log_ppp_debug, conn, fmt, ####__VA_ARGS__)
#define log_sstp_ppp_msg(conn, fmt, ...) log_sstp_ppp(log_ppp_msg, conn, fmt, ####__VA_ARGS__)

#define PPP_SYNC	0 /* buggy yet */
#define PPP_BUF_SIZE	8192
#define PPP_F_ESCAPE	1
#define PPP_F_TOSS	2

enum {
	STATE_INIT = 0,
	STATE_STARTING,
	STATE_STARTED,
	STATE_FINISHED,
};

struct buffer_t {
	struct list_head entry;
	size_t len;
	unsigned char *head;
	unsigned char *tail;
	unsigned char *end;
	unsigned char data[0];
};

struct sstp_stream_t {
	union {
		int fd;
#ifdef CRYPTO_OPENSSL
		SSL *ssl;
#endif
	};
	ssize_t (*read)(struct sstp_stream_t *stream, void *buf, size_t count);
	ssize_t (*write)(struct sstp_stream_t *stream, const void *buf, size_t count);
	int (*close)(struct sstp_stream_t *stream);
	void (*free)(struct sstp_stream_t *stream);
};

struct sstp_conn_t {
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd, ppp_hnd;

	struct triton_timer_t timeout_timer;
	struct triton_timer_t hello_timer;

	struct sstp_stream_t *stream;
	int (*handler)(struct sstp_conn_t *conn, struct buffer_t *buf);

	int sstp_state;
	int nak_sent;
	int hello_sent;
	int hello_interval;
//	int bypass_auth:1;
//	char *http_cookie;
//	uint8_t auth_key[32];
	struct buffer_t *in;
	struct list_head out_queue;

	int ppp_state;
	int ppp_flags;
	struct buffer_t *ppp_in;
	struct list_head ppp_queue;

	struct ppp_t ppp;
	struct ap_ctrl ctrl;

#ifdef CRYPTO_OPENSSL
	SSL_CTX *ssl_ctx;
#endif
};

static struct sstp_serv_t {
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;

	uint8_t certificate_hash[32];
} serv;

static int conf_timeout = SSTP_NEGOTIOATION_TIMEOUT;
static int conf_hello_interval = SSTP_HELLO_TIMEOUT;
static int conf_verbose = 0;
static int conf_ppp_max_mtu = 1456;
static int conf_hash_protocol = CERT_HASH_PROTOCOL_SHA256;
//static int conf_bypass_auth = 0;
static const char *conf_ip_pool;
static const char *conf_ifname;
static int conf_ssl = 1;
static char *conf_ssl_ciphers = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
static char *conf_ssl_ca_file = NULL;
static char *conf_ssl_pemfile = NULL;

static mempool_t conn_pool;

static int sstp_write(struct triton_md_handler_t *h);
static inline void sstp_queue(struct sstp_conn_t *conn, struct buffer_t *buf);
static int sstp_send(struct sstp_conn_t *conn, struct buffer_t *buf);
static int sstp_abort(struct sstp_conn_t *conn, int disconnect);
static void sstp_disconnect(struct sstp_conn_t *conn);
static int sstp_handler(struct sstp_conn_t *conn, struct buffer_t *buf);

/*
 * FCS lookup table as calculated by genfcstab.
 */
static const uint16_t fcstab[256] = {
	0x0000,	0x1189,	0x2312,	0x329b,	0x4624,	0x57ad,	0x6536,	0x74bf,
	0x8c48,	0x9dc1,	0xaf5a,	0xbed3,	0xca6c,	0xdbe5,	0xe97e,	0xf8f7,
	0x1081,	0x0108,	0x3393,	0x221a,	0x56a5,	0x472c,	0x75b7,	0x643e,
	0x9cc9,	0x8d40,	0xbfdb,	0xae52,	0xdaed,	0xcb64,	0xf9ff,	0xe876,
	0x2102,	0x308b,	0x0210,	0x1399,	0x6726,	0x76af,	0x4434,	0x55bd,
	0xad4a,	0xbcc3,	0x8e58,	0x9fd1,	0xeb6e,	0xfae7,	0xc87c,	0xd9f5,
	0x3183,	0x200a,	0x1291,	0x0318,	0x77a7,	0x662e,	0x54b5,	0x453c,
	0xbdcb,	0xac42,	0x9ed9,	0x8f50,	0xfbef,	0xea66,	0xd8fd,	0xc974,
	0x4204,	0x538d,	0x6116,	0x709f,	0x0420,	0x15a9,	0x2732,	0x36bb,
	0xce4c,	0xdfc5,	0xed5e,	0xfcd7,	0x8868,	0x99e1,	0xab7a,	0xbaf3,
	0x5285,	0x430c,	0x7197,	0x601e,	0x14a1,	0x0528,	0x37b3,	0x263a,
	0xdecd,	0xcf44,	0xfddf,	0xec56,	0x98e9,	0x8960,	0xbbfb,	0xaa72,
	0x6306,	0x728f,	0x4014,	0x519d,	0x2522,	0x34ab,	0x0630,	0x17b9,
	0xef4e,	0xfec7,	0xcc5c,	0xddd5,	0xa96a,	0xb8e3,	0x8a78,	0x9bf1,
	0x7387,	0x620e,	0x5095,	0x411c,	0x35a3,	0x242a,	0x16b1,	0x0738,
	0xffcf,	0xee46,	0xdcdd,	0xcd54,	0xb9eb,	0xa862,	0x9af9,	0x8b70,
	0x8408,	0x9581,	0xa71a,	0xb693,	0xc22c,	0xd3a5,	0xe13e,	0xf0b7,
	0x0840,	0x19c9,	0x2b52,	0x3adb,	0x4e64,	0x5fed,	0x6d76,	0x7cff,
	0x9489,	0x8500,	0xb79b,	0xa612,	0xd2ad,	0xc324,	0xf1bf,	0xe036,
	0x18c1,	0x0948,	0x3bd3,	0x2a5a,	0x5ee5,	0x4f6c,	0x7df7,	0x6c7e,
	0xa50a,	0xb483,	0x8618,	0x9791,	0xe32e,	0xf2a7,	0xc03c,	0xd1b5,
	0x2942,	0x38cb,	0x0a50,	0x1bd9,	0x6f66,	0x7eef,	0x4c74,	0x5dfd,
	0xb58b,	0xa402,	0x9699,	0x8710,	0xf3af,	0xe226,	0xd0bd,	0xc134,
	0x39c3,	0x284a,	0x1ad1,	0x0b58,	0x7fe7,	0x6e6e,	0x5cf5,	0x4d7c,
	0xc60c,	0xd785,	0xe51e,	0xf497,	0x8028,	0x91a1,	0xa33a,	0xb2b3,
	0x4a44,	0x5bcd,	0x6956,	0x78df,	0x0c60,	0x1de9,	0x2f72,	0x3efb,
	0xd68d,	0xc704,	0xf59f,	0xe416,	0x90a9,	0x8120,	0xb3bb,	0xa232,
	0x5ac5,	0x4b4c,	0x79d7,	0x685e,	0x1ce1,	0x0d68,	0x3ff3,	0x2e7a,
	0xe70e,	0xf687,	0xc41c,	0xd595,	0xa12a,	0xb0a3,	0x8238,	0x93b1,
	0x6b46,	0x7acf,	0x4854,	0x59dd,	0x2d62,	0x3ceb,	0x0e70,	0x1ff9,
	0xf78f,	0xe606,	0xd49d,	0xc514,	0xb1ab,	0xa022,	0x92b9,	0x8330,
	0x7bc7,	0x6a4e,	0x58d5,	0x495c,	0x3de3,	0x2c6a,	0x1ef1,	0x0f78
};

/* buffer */

static inline void *buf_put(struct buffer_t *buf, int len)
{
	void *tmp = buf->tail;
	buf->tail += len;
	buf->len += len;
	return tmp;
}

static inline void *buf_put_data(struct buffer_t *buf, const void *data, int len)
{
	void *tmp = buf_put(buf, len);
	memcpy(tmp, data, len);
	return tmp;
}

static inline void *buf_push(struct buffer_t *buf, int len)
{
	buf->head -= len;
	buf->len += len;
	return buf->head;
}

static inline void *buf_pull(struct buffer_t *buf, int len)
{
	buf->head += len;
	buf->len -= len;
	return buf->head;
}

static inline int buf_headroom(const struct buffer_t *buf)
{
	return buf->head - buf->data;
}

static inline int buf_tailroom(const struct buffer_t *buf)
{
	return buf->end - buf->tail;
}

static inline void buf_reserve(struct buffer_t *buf, int len)
{
	buf->head += len;
	buf->tail += len;
}

static inline void buf_set_length(struct buffer_t *buf, int len)
{
	buf->tail = buf->head + len;
	buf->len = len;
}

static inline int buf_expand_tail(struct buffer_t *buf, int tailroom)
{
	if (buf->len == 0)
		buf->head = buf->tail = buf->data;
	else if (buf_tailroom(buf) < tailroom) {
		buf->head = memmove(buf->data, buf->head, buf->len);
		buf->tail = buf->head + buf->len;
	}
	return (buf_tailroom(buf) >= tailroom);
}

static struct buffer_t *alloc_buf(size_t size)
{
	struct buffer_t *buf = _malloc(sizeof(*buf) + size);

	if (!buf)
		return NULL;

	buf->head = buf->data;
	buf->end = buf->data + size;
	buf_set_length(buf, 0);
	return buf;
}

static void free_buf(struct buffer_t *buf)
{
	_free(buf);
}

/* socket stream */

static ssize_t stream_read(struct sstp_stream_t *stream, void *buf, size_t count)
{
	return read(stream->fd, buf, count);
}

static ssize_t stream_write(struct sstp_stream_t *stream, const void *buf, size_t count)
{
	return write(stream->fd, buf, count);
}

static int stream_close(struct sstp_stream_t *stream)
{
	return close(stream->fd);
}

static void stream_free(struct sstp_stream_t *stream)
{
	_free(stream);
}

static struct sstp_stream_t *stream_init(int fd)
{
	struct sstp_stream_t *stream = _malloc(sizeof(*stream));

	if (!stream)
		return NULL;

	stream->fd = fd;
	stream->read = stream_read;
	stream->write = stream_write;
	stream->close = stream_close;
	stream->free = stream_free;

	return stream;
}

/* ssl stream */

#ifdef CRYPTO_OPENSSL
#include <pthread.h>

static pthread_mutex_t *lock_cs;

static unsigned long pthreads_thread_id(void)
{
    return (unsigned long)pthread_self();
}

static void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&lock_cs[type]);
	else
		pthread_mutex_unlock(&lock_cs[type]);
}

static void CRYPTO_thread_setup(void)
{
	int i;

	lock_cs = _malloc(CRYPTO_num_locks() * sizeof(*lock_cs));
	if (!lock_cs)
		return;

	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&lock_cs[i], NULL);

	CRYPTO_set_id_callback(pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
}
 
static void CRYPTO_thread_cleanup(void)
{
	int i;

	if (!lock_cs)
		return;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_destroy(&lock_cs[i]);

	 _free(lock_cs);
}

static ssize_t ssl_stream_read(struct sstp_stream_t *stream, void *buf, size_t count)
{
	int ret, err;

	ERR_clear_error();
	ret = SSL_read(stream->ssl, buf, count);
	err = SSL_get_error(stream->ssl, ret);
	switch (err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return ret;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		/* fall through */
	case SSL_ERROR_SYSCALL:
	default:
		return -1;
	}
}

static ssize_t ssl_stream_write(struct sstp_stream_t *stream, const void *buf, size_t count)
{
	int ret, err;

	ERR_clear_error();
	ret = SSL_write(stream->ssl, buf, count);
	err = SSL_get_error(stream->ssl, ret);
	switch (err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return ret;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		errno = EAGAIN;
		/* fall through */
	case SSL_ERROR_SYSCALL:
	default:
		return -1;
	}
}

static int ssl_stream_close(struct sstp_stream_t *stream)
{
	SSL_shutdown(stream->ssl);
	return close(SSL_get_fd(stream->ssl));
}

static void ssl_stream_free(struct sstp_stream_t *stream)
{
	if (stream && stream->ssl)
		SSL_free(stream->ssl);
	_free(stream);
}

static struct sstp_stream_t *ssl_stream_init(int fd, SSL_CTX *ssl_ctx)
{
	struct sstp_stream_t *stream = _malloc(sizeof(*stream));

	if (!stream)
		return NULL;

	stream->ssl = SSL_new(ssl_ctx);
	if (!stream->ssl)
		goto error;

	SSL_set_verify(stream->ssl, SSL_VERIFY_NONE, NULL);
	SSL_set_mode(stream->ssl, SSL_MODE_AUTO_RETRY);
	SSL_set_accept_state(stream->ssl);
	SSL_set_fd(stream->ssl, fd);

	stream->read = ssl_stream_read;
	stream->write = ssl_stream_write;
	stream->close = ssl_stream_close;
	stream->free = ssl_stream_free;

	return stream;

error:
	ssl_stream_free(stream);
	return NULL;
}
#endif

/* http */

static char *http_getline(struct sstp_conn_t *conn, int *pos, char *buf, int size)
{
	unsigned char *src, *dst, c, pc;

	size = min(size - 1, conn->in->len - *pos);
	if (size <= 0)
		return NULL;

	src = conn->in->head + *pos;
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

	*pos = src - conn->in->head;

	return buf;
}

static int http_send_response(struct sstp_conn_t *conn, char *proto, char *status, char *headers)
{
	char datetime[sizeof("aaa, dd bbb yyyy HH:MM:SS GMT")], msg[1024];
	struct buffer_t *buf;
	time_t now = time(NULL);
	int n;

	strftime(datetime, sizeof(datetime), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&now));
	n = snprintf(msg, sizeof(msg),
		"%s %s\r\n"
		/* "Server: %s\r\n" */
		"Date: %s\r\n"
		"%s"
		"\r\n", proto, status, /* "accel-ppp",*/ datetime, headers ? : "");

	if (conf_verbose)
		log_sstp_info2(conn, "send [HTTP <%s %s>]\n", proto, status);

	buf = alloc_buf(n);
	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}
	buf_put_data(buf, msg, n);

	return sstp_send(conn, buf);
}

static int http_recv_request(struct sstp_conn_t *conn)
{
	char buf[1024];
	char *line, *method, *request, *proto;
	int pos = 0;

	if (conn->sstp_state != STATE_SERVER_CALL_DISCONNECTED)
		return -1;

	line = http_getline(conn, &pos, buf, sizeof(buf));
	if (!line)
		goto error;
	if (conf_verbose)
		log_sstp_info2(conn, "recv [HTTP <%s>]\n", line);

	method = strsep(&line, " ");
	request = strsep(&line, " ");
	proto = strsep(&line, " ");

	if (!method || !request || !proto) {
		http_send_response(conn, "HTTP/1.1", "400 Bad Request", NULL);
		goto error;
	}
	if (strncmp(proto, "HTTP/1", sizeof("HTTP/1") - 1) != 0) {
		http_send_response(conn, "HTTP/1.1", "505 HTTP Version Not Supported", NULL);
		goto error;
	}
	if (strcmp(method, SSTP_HTTP_METHOD) != 0) {
		http_send_response(conn, proto, "405 Method Not Allowed", NULL);
		goto error;
	}
	if (strcmp(request, SSTP_HTTP_URI) != 0) {
		http_send_response(conn, proto, "404 Not Found", NULL);
		goto error;
	}

	while ((line = http_getline(conn, &pos, buf, sizeof(buf))) != NULL) {
		if (*line == '\0')
			break;
		if (conf_verbose)
			log_sstp_info2(conn, "recv [HTTP <%s>]\n", line);
	} while (*line);

	if (http_send_response(conn, proto, "200 OK",
			"Content-Length: 18446744073709551615\r\n")) {
		goto error;
	}

	conn->sstp_state = STATE_SERVER_CONNECT_REQUEST_PENDING;

	return pos;

error:
	return -1;
}

static int http_handler(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	int n;

	n = http_recv_request(conn);
	if (n < 0)
		return -1;
	buf_pull(buf, n);

	if (conn->sstp_state == STATE_SERVER_CONNECT_REQUEST_PENDING)
		conn->handler = sstp_handler;

	return n;
}

/* ppp */

static int ppp_allocate_pty(int *master, int *slave, int flags)
{
	struct termios tios;
	int value, mfd, sfd;

	if (openpty(&mfd, &sfd, NULL, &tios, NULL) < 0) {
		log_ppp_error("sstp: allocate pty: %s\n", strerror(errno));
		return -1;
	}

	if (flags & O_CLOEXEC) {
		fcntl(mfd, F_SETFD, fcntl(mfd, F_GETFD) | FD_CLOEXEC);
		fcntl(sfd, F_SETFD, fcntl(sfd, F_GETFD) | FD_CLOEXEC);
		flags &= ~O_CLOEXEC;
	}

	tios.c_cflag &= ~(CSIZE | CSTOPB | PARENB);
	tios.c_cflag |= CS8 | CREAD | CLOCAL;
	tios.c_iflag  = IGNBRK | IGNPAR;
	tios.c_oflag  = 0;
	tios.c_lflag  = 0;
	tios.c_cc[VMIN] = 1;
	tios.c_cc[VTIME] = 0;
	if (tcsetattr(sfd, TCSAFLUSH, &tios) < 0) {
		log_ppp_warn("sstp: ppp: set pty attributes: %s\n", strerror(errno));
		goto error;
	}

#if PPP_SYNC
	value = N_SYNC_PPP;
#else
	value = N_PPP;
#endif
	if (ioctl(sfd, TIOCSETD, &value) < 0) {
		log_ppp_error("sstp: ppp: set pty line discipline: %s\n", strerror(errno));
		goto error;
	}

//	value = N_HDLC;
//	if (ioctl(mfd, TIOCSETD, &value) < 0) {
//		log_ppp_error("sstp: ppp: set pty line discipline: %s\n", strerror(errno));
//		goto error;
//	}

	if ((value = fcntl(mfd, F_GETFL)) < 0 || fcntl(mfd, F_SETFL, value | flags) < 0 ||
	    (value = fcntl(sfd, F_GETFL)) < 0 || fcntl(sfd, F_SETFL, value | flags) < 0) {
		log_ppp_error("sstp: ppp: set pty status flags: %s\n", strerror(errno));
		goto error;
	}

	*master = mfd;
	*slave = sfd;
	return 0;

error:
	close(mfd);
	close(sfd);
	return -1;
}

static void ppp_started(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct sstp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_ppp_debug("sstp: ppp: started\n");

	switch (conn->ppp_state) {
	case STATE_STARTING:
		conn->ppp_state = STATE_STARTED;
		break;
	}
}

static void ppp_finished(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct sstp_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_ppp_debug("sstp: ppp: finished\n");

	switch (conn->ppp_state) {
	case STATE_STARTING:
	case STATE_STARTED:
		conn->ppp_state = STATE_FINISHED;
		sstp_abort(conn, 1);
		break;
	}
}

static int ppp_read(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), ppp_hnd);
	struct buffer_t *buf;
	struct sstp_hdr *hdr;
	uint8_t pppbuf[PPP_BUF_SIZE];
	int n;
#if !PPP_SYNC
	uint8_t *src, byte;
	int i;

	buf = conn->ppp_in;
#endif
	while (1) {
		n = read(h->fd, pppbuf, sizeof(pppbuf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
			log_ppp_error("sstp: ppp: read: %s\n", strerror(errno));
			goto drop;
		} else if (n == 0) {
			if (conf_verbose)
				log_ppp_info2("sstp: ppp: disconnect from tty\n");
			goto drop;
		}

		switch (conn->sstp_state) {
		case STATE_SERVER_CALL_CONNECTED_PENDING:
		case STATE_SERVER_CALL_CONNECTED:
			break;
		default:
			continue;
		}

#if PPP_SYNC
		buf = alloc_buf(n + sizeof(*hdr));
		if (!buf) {
			log_ppp_error("sstp: ppp: no memory\n");
			goto drop;
		}
		hdr = buf_put(buf, sizeof(*hdr));
		buf_put_data(buf, pppbuf, n);
		INIT_SSTP_DATA_HDR(hdr, buf->len);
		sstp_queue(conn, buf);
#else
		src = pppbuf;
		if (!buf) {
		alloc:
			conn->ppp_in = buf = alloc_buf(SSTP_MAX_PACKET_SIZE + PPP_FCSLEN);
			if (!buf) {
				log_ppp_error("sstp: ppp: no memory\n");
				goto drop;
			}
			buf_reserve(buf, sizeof(*hdr));
		}

		while (n > 0) {
			if ((conn->ppp_flags & PPP_F_ESCAPE) && *src == PPP_ESCAPE)
				i = 1;
			else {
				for (i = 0; i < n &&
						src[i] != PPP_ESCAPE && src[i] != PPP_FLAG; i++);
			}
			if (i > 0 && (conn->ppp_flags & PPP_F_TOSS) == 0) {
				if (i <= buf_tailroom(buf)) {
					char *p = buf_put_data(buf, src, i);
					if (conn->ppp_flags & PPP_F_ESCAPE) {
						*p ^= PPP_TRANS;
						conn->ppp_flags &= ~PPP_F_ESCAPE;
					}
				} else
					conn->ppp_flags |= PPP_F_TOSS;
			}

			byte = src[i++];
			src += i;
			n -= i;

			switch (byte) {
			case PPP_FLAG:
				if (buf->len <= PPP_FCSLEN || conn->ppp_flags) {
					buf_set_length(buf, 0);
					conn->ppp_flags = 0;
					break;
				}
				buf_put(buf, -PPP_FCSLEN);
				hdr = buf_push(buf, sizeof(*hdr));
				INIT_SSTP_DATA_HDR(hdr, buf->len);
				sstp_queue(conn, buf);
				goto alloc;
			case PPP_ESCAPE:
				conn->ppp_flags |= PPP_F_ESCAPE;
				break;
			}
		}
#endif
	}
	return sstp_write(&conn->hnd);

drop:
	sstp_disconnect(conn);
	return 1;
}

static int ppp_write(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), ppp_hnd);
	struct buffer_t *buf;
	int n;

	while (!list_empty(&conn->ppp_queue)) {
		buf = list_first_entry(&conn->ppp_queue, typeof(*buf), entry);

		if (buf_headroom(buf) > 0)
			triton_md_disable_handler(h, MD_MODE_WRITE);

		while (buf->len) {
			n = write(conn->ppp_hnd.fd, buf->head, buf->len);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					break;
				if (conf_verbose && errno != EPIPE)
					log_ppp_info2("sstp: ppp: write: %s\n", strerror(errno));
				goto drop;
			} else if (n == 0)
				break;
			buf_pull(buf, n);
		}

		if (buf->len) {
			triton_md_enable_handler(h, MD_MODE_WRITE);
			break;
		}

		list_del(&buf->entry);
		free_buf(buf);
	}
	return 0;

drop:
	triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);
	return 1;
}

static inline void ppp_queue(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	list_add_tail(&buf->entry, &conn->ppp_queue);
}

static int ppp_send(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	ppp_queue(conn, buf);
	return ppp_write(&conn->ppp_hnd) ? -1 : 0;
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

static int sstp_send_msg_call_connect_ack(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_crypto_binding_request attr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "send [SSTP_MSG_CALL_CONNECT_ACK]\n");

	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	msg = buf_put(buf, sizeof(*msg));
	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_CONNECT_ACK, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_CRYPTO_BINDING_REQ, sizeof(msg->attr));
	msg->attr.hash_protocol_bitmask = conf_hash_protocol;
	//read(urandom_fd, msg->attr.nonce, sizeof(msg->attr.nonce));
	memset(msg->attr.nonce, 0, sizeof(msg->attr.nonce));

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_connect_nak(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
		uint16_t attr_value;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "send [SSTP_MSG_CALL_CONNECT_NAK]\n");

	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	msg = buf_put(buf, sizeof(*msg));
	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_CONNECT_NAK, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID;
	msg->attr.status = htonl(ATTRIB_STATUS_VALUE_NOT_SUPPORTED);
	msg->attr_value = 0;

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_abort(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "send [SSTP_MSG_CALL_ABORT]\n");

	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	msg = buf_put(buf, sizeof(*msg));
	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_ABORT, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_STATUS_INFO;
	msg->attr.status = htonl(ATTRIB_STATUS_INVALID_FRAME_RECEIVED);

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_disconnect(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_status_info attr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "send [SSTP_MSG_CALL_DISCONNECT]\n");

	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	msg = buf_put(buf, sizeof(*msg));
	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_DISCONNECT, 1, sizeof(*msg));
	INIT_SSTP_ATTR_HDR(&msg->attr.hdr, SSTP_ATTRIB_STATUS_INFO, sizeof(msg->attr));
	msg->attr.attrib_id = SSTP_ATTRIB_NO_ERROR;
	msg->attr.status = htonl(ATTRIB_STATUS_NO_ERROR);

	return sstp_send(conn, buf);
}

static int sstp_send_msg_call_disconnect_ack(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "send [SSTP_MSG_CALL_DISCONNECT_ACK]\n");

	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	msg = buf_put(buf, sizeof(*msg));
	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_CALL_DISCONNECT_ACK, 0, sizeof(*msg));

	return sstp_send(conn, buf);
}

static int sstp_send_msg_echo_request(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "send [SSTP_MSG_ECHO_REQUEST]\n");

	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	msg = buf_put(buf, sizeof(*msg));
	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_ECHO_REQUEST, 0, sizeof(*msg));

	return sstp_send(conn, buf);
}

static int sstp_send_msg_echo_response(struct sstp_conn_t *conn)
{
	struct {
		struct sstp_ctrl_hdr hdr;
	} __attribute__((packed)) *msg;
	struct buffer_t *buf = alloc_buf(sizeof(*msg));

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "send [SSTP_MSG_ECHO_RESPONSE]\n");

	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	msg = buf_put(buf, sizeof(*msg));
	INIT_SSTP_CTRL_HDR(&msg->hdr, SSTP_MSG_ECHO_RESPONSE, 0, sizeof(*msg));

	return sstp_send(conn, buf);
}

static int sstp_recv_msg_call_connect_request(struct sstp_conn_t *conn, struct sstp_ctrl_hdr *hdr)
{
	struct {
		struct sstp_ctrl_hdr hdr;
		struct sstp_attrib_encapsulated_protocol attr;
	} __attribute__((packed)) *msg = (void *)hdr;
	int master, slave;

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "recv [SSTP_MSG_CALL_CONNECT_REQUEST]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_SERVER_CONNECT_REQUEST_PENDING:
		break;
	default:
		return sstp_abort(conn, 0);
	}

	if (ntohs(msg->hdr.length) < sizeof(*msg) ||
	    ntohs(msg->hdr.num_attributes) < 1 ||
	    msg->attr.hdr.attribute_id != SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID ||
	    ntohs(msg->attr.hdr.length) < sizeof(msg->attr)) {
		return sstp_abort(conn, 0);
	}
	if (ntohs(msg->attr.protocol_id) != SSTP_ENCAPSULATED_PROTOCOL_PPP) {
		if (conn->nak_sent++ == 3) {
			log_sstp_ppp_warn(conn, "nak limit reached\n");
			return sstp_abort(conn, 0);
		}
		return sstp_send_msg_call_connect_nak(conn);
	}

	if (ppp_allocate_pty(&master, &slave, O_CLOEXEC | O_NONBLOCK) < 0)
		return -1;

	conn->ppp_hnd.fd = master;
	conn->ppp_hnd.read = ppp_read;
	conn->ppp_hnd.write = ppp_write;

	triton_md_register_handler(&conn->ctx, &conn->ppp_hnd);
	triton_md_enable_handler(&conn->ppp_hnd, MD_MODE_READ);

//	triton_event_fire(EV_CTRL_STARTED, &conn->ppp.ses);

	if (sstp_send_msg_call_connect_ack(conn))
		goto error;

	conn->sstp_state = STATE_SERVER_CALL_CONNECTED_PENDING;
	conn->ppp_state = STATE_STARTING;

	conn->ppp.fd = slave;
	if (establish_ppp(&conn->ppp)) {
		conn->ppp_state = STATE_FINISHED;
		goto error;
	}

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	return 0;

error:
	if (conn->ppp_hnd.tpd)
		triton_md_unregister_handler(&conn->ppp_hnd, 1);
	close(slave);
	return -1;
}

static int sstp_recv_msg_call_connected(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_sstp_ppp_info2(conn, "recv [SSTP_MSG_CALL_CONNECTED]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_SERVER_CALL_CONNECTED_PENDING:
		break;
	default:
		sstp_abort(conn, 0);
		return 0;
	}

	conn->sstp_state = STATE_SERVER_CALL_CONNECTED;

	if (conn->hello_interval) {
		conn->hello_timer.period = conn->hello_interval * 1000;
		triton_timer_add(&conn->ctx, &conn->hello_timer, 0);
	}

	return 0;
}

static int sstp_recv_msg_call_abort(struct sstp_conn_t *conn)
{
	int ret = 0;

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "recv [SSTP_MSG_CALL_ABORT]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_PENDING:
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		conn->sstp_state = STATE_CALL_ABORT_IN_PROGRESS_2;
		ret = sstp_send_msg_call_abort(conn);
		break;
	}

	conn->timeout_timer.period = SSTP_ABORT_TIMEOUT_2 * 1000;
	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);
	else
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	conn->sstp_state = STATE_CALL_ABORT_TIMEOUT_PENDING;

	return ret;
}

static int sstp_recv_msg_call_disconnect(struct sstp_conn_t *conn)
{
	int ret;

	if (conf_verbose)
		log_sstp_ppp_info2(conn, "recv [SSTP_MSG_CALL_DISCONNECT]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		if (conn->timeout_timer.tpd)
			triton_timer_del(&conn->timeout_timer);
		break;
	}

	conn->sstp_state = STATE_CALL_DISCONNECT_IN_PROGRESS_2;

	ret = sstp_send_msg_call_disconnect_ack(conn);

	conn->timeout_timer.period = SSTP_DISCONNECT_TIMEOUT_2 * 1000;
	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);
	else
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	conn->sstp_state = STATE_CALL_DISCONNECT_TIMEOUT_PENDING;

	return ret;
}

static int sstp_recv_msg_call_disconnect_ack(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_sstp_ppp_info2(conn, "recv [SSTP_MSG_CALL_DISCONNECT_ACK]\n");

	switch (conn->sstp_state) {
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		break;
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		return sstp_abort(conn, 0);
	}

	conn->sstp_state = STATE_SERVER_CALL_DISCONNECTED;
	triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);

	return 0;
}

static int sstp_recv_msg_echo_request(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_sstp_ppp_info2(conn, "recv [SSTP_MSG_ECHO_REQUEST]\n");

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		return sstp_abort(conn, 0);
	}

	return sstp_send_msg_echo_response(conn);
}

static int sstp_recv_msg_echo_response(struct sstp_conn_t *conn)
{
	if (conf_verbose)
		log_sstp_ppp_info2(conn, "recv [SSTP_MSG_ECHO_RESPONSE]\n");

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		break;
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
		return 0;
	default:
		return sstp_abort(conn, 0);
	}

	conn->hello_sent = 0;
	return 0;
}

static int sstp_recv_data_packet(struct sstp_conn_t *conn, struct sstp_hdr *hdr)
{
	struct buffer_t *buf;
	int size;
#if !PPP_SYNC
	uint8_t *src, *dst, byte;
	uint16_t fcs;
	int n;
#endif

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED_PENDING:
	case STATE_SERVER_CALL_CONNECTED:
		break;
	default:
		return 0;
	}

	size = ntohs(hdr->length) - sizeof(*hdr);
#if PPP_SYNC
	buf = alloc_buf(size);
	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	buf_put_data(buf, hdr->data, size);
#else
	buf = alloc_buf(size*2 + 2 + PPP_FCSLEN);
	if (!buf) {
		log_sstp_error(conn, "no memory\n");
		return -1;
	}

	src = hdr->data;
	dst = buf->tail;
	fcs = PPP_INITFCS;

	*dst++ = PPP_FLAG;
	for (n = size + PPP_FCSLEN; n > 0; n--) {
		if (n > PPP_FCSLEN) {
			byte = *src++;
			fcs = (fcs >> 8) ^ fcstab[(fcs ^ byte) & 0xff];
		} else if (n == PPP_FCSLEN) {
			fcs ^= PPP_INITFCS;
			byte = fcs & 0xff;
		} else if (n == PPP_FCSLEN - 1)
			byte = fcs >> 8;
		if (byte < 0x20 || byte == PPP_FLAG || byte == PPP_ESCAPE) {
			*dst++ = PPP_ESCAPE;
			*dst++ = byte ^ PPP_TRANS;
		} else
			*dst++ = byte;
	}
	*dst++ = PPP_FLAG;

	buf_put(buf, dst - buf->tail);
#endif

	return ppp_send(conn, buf);
}

static int sstp_recv_packet(struct sstp_conn_t *conn, struct sstp_hdr *hdr)
{
	struct sstp_ctrl_hdr *msg = (struct sstp_ctrl_hdr *)hdr;

	switch (hdr->reserved) {
	case SSTP_DATA_PACKET:
		return sstp_recv_data_packet(conn, hdr);
	case SSTP_CTRL_PACKET:
		if (ntohs(hdr->length) >= sizeof(*msg))
			break;
		log_sstp_ppp_error(conn, "recv [SSTP too short message]\n");
		return -1;
	default:
		log_sstp_ppp_warn(conn, "recv [SSTP unknown packet type %02x]\n", hdr->reserved);
		return 0;
	}

	if (conn->hello_timer.tpd) {
		conn->hello_timer.period = conn->hello_interval * 1000;
		triton_timer_mod(&conn->hello_timer, 0);
	}

	switch (ntohs(msg->message_type)) {
	case SSTP_MSG_CALL_CONNECT_REQUEST:
		return sstp_recv_msg_call_connect_request(conn, msg);
	case SSTP_MSG_CALL_CONNECT_ACK:
	case SSTP_MSG_CALL_CONNECT_NAK:
		return sstp_abort(conn, 0);
	case SSTP_MSG_CALL_CONNECTED:
		return sstp_recv_msg_call_connected(conn);
	case SSTP_MSG_CALL_ABORT:
		return sstp_recv_msg_call_abort(conn);
	case SSTP_MSG_CALL_DISCONNECT:
		return sstp_recv_msg_call_disconnect(conn);
	case SSTP_MSG_CALL_DISCONNECT_ACK:
		return sstp_recv_msg_call_disconnect_ack(conn);
	case SSTP_MSG_ECHO_REQUEST:
		return sstp_recv_msg_echo_request(conn);
	case SSTP_MSG_ECHO_RESPONSE:
		return sstp_recv_msg_echo_response(conn);
	default:
		log_sstp_ppp_warn(conn, "recv [SSTP unknown message type %04x]\n", ntohs(msg->message_type));
		return 0;
	}
}

static int sstp_handler(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	struct sstp_hdr *hdr;
	int n;

	while (buf->len >= sizeof(*hdr)) {
		hdr = (struct sstp_hdr *)buf->head;
		if (hdr->version != SSTP_VERSION) {
			log_sstp_ppp_error(conn, "recv [SSTP invalid version]\n");
			return -1;
		}

		n = ntohs(hdr->length);
		if (n > SSTP_MAX_PACKET_SIZE) {
			log_sstp_ppp_error(conn, "recv [SSTP too long packet]\n");
			return -1;
		} else if (n > buf->len)
			break;

		if (sstp_recv_packet(conn, hdr) < 0)
			return -1;
		buf_pull(buf, n);
	};

	return 0;
}

static int sstp_read(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct buffer_t *buf = conn->in;
	int n;

	while ((n = buf_tailroom(buf)) > 0) {
		n = conn->stream->read(conn->stream, buf->tail, n);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return 0;
			log_ppp_error("sstp: read: %s\n", strerror(errno));
			goto drop;
		} else if (n == 0) {
			if (conf_verbose)
				log_ppp_info2("sstp: disconnect by peer\n");
			goto drop;
		}
		buf_put(buf, n);

		n = conn->handler(conn, buf);
		if (n < 0)
			goto drop;

		buf_expand_tail(buf, SSTP_MAX_PACKET_SIZE);
	}
	return 0;

drop:
	sstp_disconnect(conn);
	return 1;
}

static int sstp_write(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct buffer_t *buf;
	int n;

	while (!list_empty(&conn->out_queue)) {
		buf = list_first_entry(&conn->out_queue, typeof(*buf), entry);
		if (buf_headroom(buf) > 0)
			triton_md_disable_handler(h, MD_MODE_WRITE);

		while (buf->len) {
			n = conn->stream->write(conn->stream, buf->head, buf->len);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					break;
				if (conf_verbose && errno != EPIPE)
					log_ppp_info2("sstp: write: %s\n", strerror(errno));
				goto drop;
			} else if (n == 0)
				break;
			buf_pull(buf, n);
		}

		if (buf->len) {
			triton_md_enable_handler(h, MD_MODE_WRITE);
			break;
		}

		list_del(&buf->entry);
		free_buf(buf);
	}
	return 0;

drop:
	triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);
	return 1;
}

static inline void sstp_queue(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	list_add_tail(&buf->entry, &conn->out_queue);
}

static int sstp_send(struct sstp_conn_t *conn, struct buffer_t *buf)
{
	sstp_queue(conn, buf);
	return sstp_write(&conn->hnd) ? -1 : 0;
}

static void sstp_msg_echo(struct triton_timer_t *t)
{
	struct sstp_conn_t *conn = container_of(t, typeof(*conn), hello_timer);
	struct ppp_idle idle;

	switch (conn->sstp_state) {
	case STATE_SERVER_CALL_CONNECTED:
		if (ioctl(conn->ppp.unit_fd, PPPIOCGIDLE, &idle) >= 0 &&
		    idle.recv_idle < conn->hello_interval) {
			t->period = (conn->hello_interval - idle.recv_idle) * 1000;
			triton_timer_mod(t, 0);
			break;
		}
		if (conn->hello_sent++) {
			log_ppp_warn("sstp: no echo reply\n");
			sstp_abort(conn, 0);
		} else
			sstp_send_msg_echo_request(conn);
		break;
	}
}

static void sstp_timeout(struct triton_timer_t *t)
{
	struct sstp_conn_t *conn = container_of(t, typeof(*conn), timeout_timer);

	triton_timer_del(t);

	switch (conn->sstp_state) {
	case STATE_CALL_ABORT_TIMEOUT_PENDING:
	case STATE_CALL_ABORT_PENDING:
	case STATE_CALL_DISCONNECT_TIMEOUT_PENDING:
	case STATE_CALL_DISCONNECT_ACK_PENDING:
		triton_context_call(&conn->ctx, (triton_event_func)sstp_disconnect, conn);
		break;
	default:
		sstp_abort(conn, 0);
		break;
	}
}

static void sstp_close(struct triton_context_t *ctx)
{
	struct sstp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	switch (conn->ppp_state) {
	case STATE_STARTING:
	case STATE_STARTED:
		conn->ppp_state = STATE_FINISHED;
		ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 1);
		sstp_abort(conn, 1);
		break;
	default:
		sstp_abort(conn, 0);
		break;
	}
}

static int sstp_abort(struct sstp_conn_t *conn, int disconnect)
{
	static const struct {
		int send_state;
		int exit_state;
		int timeout;
	} modes[2] = {
		{ STATE_CALL_ABORT_IN_PROGRESS_1, STATE_CALL_ABORT_PENDING, SSTP_ABORT_TIMEOUT_1 },
		{ STATE_CALL_DISCONNECT_IN_PROGRESS_1, STATE_CALL_DISCONNECT_ACK_PENDING, SSTP_DISCONNECT_TIMEOUT_1 }
	};
	int ret, idx = !!disconnect;

	conn->sstp_state = modes[idx].send_state;
	ret = idx ? sstp_send_msg_call_disconnect(conn) : sstp_send_msg_call_abort(conn);

	conn->timeout_timer.period = modes[idx].timeout * 1000;
	if (conn->timeout_timer.tpd)
		triton_timer_mod(&conn->timeout_timer, 0);
	else
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	conn->sstp_state = modes[idx].exit_state;

	return ret;
}

static void sstp_disconnect(struct sstp_conn_t *conn)
{
	struct buffer_t *buf;

	log_sstp_ppp_debug(conn, "disconnecting\n");

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);
	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	if (conn->hnd.tpd) {
		triton_md_unregister_handler(&conn->hnd, 0);
		conn->stream->close(conn->stream);
	}
	if (conn->ppp_hnd.tpd)
		triton_md_unregister_handler(&conn->ppp_hnd, 1);

	switch (conn->ppp_state) {
	case STATE_STARTING:
	case STATE_STARTED:
		conn->ppp_state = STATE_FINISHED;
		ap_session_terminate(&conn->ppp.ses, TERM_LOST_CARRIER, 1);
	}
//	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp.ses);

	conn->stream->free(conn->stream);
	free_buf(conn->in);
	free_buf(conn->ppp_in);

	list_splice_init(&conn->ppp_queue, &conn->out_queue);
	while (!list_empty(&conn->out_queue)) {
		buf = list_first_entry(&conn->out_queue, typeof(*buf), entry);
		list_del(&buf->entry);
		free_buf(buf);
	}

	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);

#ifdef CRYPTO_OPENSSL
	if (conn->ssl_ctx)
		SSL_CTX_free(conn->ssl_ctx);
#endif

	mempool_free(conn);

	log_info2("sstp: disconnected\n");
}

static void sstp_start(struct sstp_conn_t *conn)
{
	log_sstp_debug(conn, "start\n");

#ifdef CRYPTO_OPENSSL
	if (conf_ssl) {
		conn->ssl_ctx = SSL_CTX_new(SSLv23_server_method());
		if (!conn->ssl_ctx) {
			log_sstp_error(conn, "SSL_CTX error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		SSL_CTX_set_options(conn->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION);

		if (conf_ssl_ciphers &&
		    SSL_CTX_set_cipher_list(conn->ssl_ctx, conf_ssl_ciphers) != 1) {
			log_sstp_error(conn, "SSL cipher list error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}
		if (conf_ssl_ca_file &&
		    SSL_CTX_load_verify_locations(conn->ssl_ctx, conf_ssl_ca_file, NULL) != 1) {
			log_sstp_error(conn, "SSL ca file error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}
		if (!conf_ssl_pemfile ||
		    SSL_CTX_use_certificate_file(conn->ssl_ctx, conf_ssl_pemfile, SSL_FILETYPE_PEM) != 1 ||
		    SSL_CTX_use_PrivateKey_file(conn->ssl_ctx, conf_ssl_pemfile, SSL_FILETYPE_PEM) != 1 ||
		    SSL_CTX_check_private_key(conn->ssl_ctx) != 1) {
			log_sstp_error(conn, "SSL certificate error: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto error;
		}

		SSL_CTX_set_default_read_ahead(conn->ssl_ctx, 1);
		SSL_CTX_set_mode(conn->ssl_ctx, SSL_CTX_get_mode(conn->ssl_ctx) |
			SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);

		conn->stream = ssl_stream_init(conn->hnd.fd, conn->ssl_ctx);
	} else
#endif
		conn->stream = stream_init(conn->hnd.fd);
	if (!conn->stream) {
		log_sstp_error(conn, "stream open error: %s\n", strerror(errno));
		goto error;
	}

	triton_md_register_handler(&conn->ctx, &conn->hnd);
	triton_md_enable_handler(&conn->hnd, MD_MODE_READ);

	log_sstp_info2(conn, "started\n");
//	triton_event_fire(EV_CTRL_STARTING, &conn->ppp.ses);

	return;

error:
	sstp_disconnect(conn);
}

static int sstp_connect(struct triton_md_handler_t *h)
{
	struct sstp_conn_t *conn;
	struct sockaddr_in addr;
	socklen_t size = sizeof(addr);
	int sock, value;

	while (1) {
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

		
		log_info2("sstp: new connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

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

		value = 65536;
		if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) < 0) {
			log_error("sstp: failed to set send buffer: %s, closing connection...\n", strerror(errno));
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
		conn->hello_interval = conf_hello_interval;

		conn->sstp_state = STATE_SERVER_CALL_DISCONNECTED;
		conn->ppp_state = STATE_INIT;
		conn->handler = http_handler;

		//conn->bypass_auth = conf_bypass_auth;
		//conn->http_cookie = NULL:
		//conn->auth_key...

		conn->in = alloc_buf(SSTP_MAX_PACKET_SIZE*2);
		INIT_LIST_HEAD(&conn->out_queue);
		INIT_LIST_HEAD(&conn->ppp_queue);

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
		conn->ctrl.calling_station_id = _malloc(sizeof("255.255.255.255:65535"));
		conn->ctrl.called_station_id = _malloc(sizeof("255.255.255.255"));
		sprintf(conn->ctrl.calling_station_id, "%s:%d",
			 inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		getsockname(sock, &addr, &size);
		u_inet_ntoa(addr.sin_addr.s_addr, conn->ctrl.called_station_id);

		ppp_init(&conn->ppp);
		conn->ppp.ses.ctrl = &conn->ctrl;
		conn->ppp.ses.chan_name = conn->ctrl.calling_station_id;
		if (conf_ip_pool)
			conn->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);
		if (conf_ifname)
			conn->ppp.ses.ifname_rename = _strdup(conf_ifname);

		triton_context_register(&conn->ctx, &conn->ppp.ses);
		triton_context_call(&conn->ctx, (triton_event_func)sstp_start, conn);
		triton_context_wakeup(&conn->ctx);

		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
	}

	return 0;
}

static void sstp_serv_close(struct triton_context_t *ctx)
{
	struct sstp_serv_t *serv = container_of(ctx, typeof(*serv), ctx);

	triton_md_unregister_handler(&serv->hnd, 1);
	triton_context_unregister(ctx);

#ifdef CRYPTO_OPENSSL
	CRYPTO_thread_cleanup();
#endif
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
	conf_ifname = conf_get_opt("sstp", "ifname");

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

#ifdef CRYPTO_OPENSSL
	CRYPTO_thread_setup();
	SSL_load_error_strings();
	SSL_library_init();
#endif

	conn_pool = mempool_create(sizeof(struct sstp_conn_t));

	load_config();

	triton_context_register(&serv.ctx, NULL);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&serv.ctx);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(20, sstp_init);
