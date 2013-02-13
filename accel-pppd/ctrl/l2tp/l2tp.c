#include <unistd.h>
#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_pppox.h>

#include "triton.h"
#include "mempool.h"
#include "log.h"
#include "ppp.h"
#include "events.h"
#include "utils.h"
#include "iprange.h"
#include "cli.h"
#include "crypto.h"

#include "connlimit.h"

#include "memdebug.h"

#include "l2tp.h"
#include "attr_defs.h"

#ifndef SOL_PPPOL2TP
#define SOL_PPPOL2TP 273
#endif

#define STATE_WAIT_SCCRP 1
#define STATE_WAIT_SCCCN 2
#define STATE_WAIT_ICRP  3
#define STATE_WAIT_ICCN  4
#define STATE_WAIT_OCRP  5
#define STATE_WAIT_OCCN  6
#define STATE_ESTB       7
#define STATE_PPP        8
#define STATE_FIN        9
#define STATE_CLOSE      0

int conf_verbose = 0;
int conf_avp_permissive = 0;
static int conf_timeout = 60;
static int conf_rtimeout = 5;
static int conf_retransmit = 5;
static int conf_hello_interval = 60;
static int conf_dir300_quirk = 0;
static const char *conf_host_name = "accel-ppp";
static const char *conf_secret = NULL;
static int conf_mppe = MPPE_UNSET;

static unsigned int stat_active;
static unsigned int stat_starting;

struct l2tp_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct sockaddr_in addr;
};

struct l2tp_sess_t
{
	struct l2tp_conn_t *paren_conn;
	uint16_t sid;
	uint16_t peer_sid;

	int state1;
	uint16_t lns_mode:1;

	struct triton_context_t sctx;
	struct triton_timer_t timeout_timer;
	struct ap_ctrl ctrl;
	struct ppp_t ppp;
};

struct l2tp_conn_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout_timer;
	struct triton_timer_t rtimeout_timer;
	struct triton_timer_t hello_timer;

	int tunnel_fd;

	struct sockaddr_in peer_addr;
	struct sockaddr_in host_addr;
	uint16_t tid;
	uint16_t peer_tid;
	uint32_t framing_cap;
	uint16_t lns_mode:1;
	uint16_t challenge_len;
	uint8_t *challenge;

	int retransmit;
	uint16_t Ns, Nr;
	struct list_head send_queue;

	int state;
	void *sessions;
	unsigned int sess_count;
};

static pthread_mutex_t l2tp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct l2tp_conn_t **l2tp_conn;
static uint16_t l2tp_tid;

static mempool_t l2tp_conn_pool;
static mempool_t l2tp_sess_pool;

static void l2tp_timeout(struct triton_timer_t *t);
static void l2tp_rtimeout(struct triton_timer_t *t);
static void l2tp_send_HELLO(struct triton_timer_t *t);
static void l2tp_send_SCCRP(struct l2tp_conn_t *conn);
static int l2tp_send(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack, int log_debug);
static void __l2tp_send(struct l2tp_packet_t *pack);
static int l2tp_conn_read(struct triton_md_handler_t *);
static void l2tp_tunnel_session_freed(void *data);


static inline void comp_chap_md5(uint8_t *md5, uint8_t ident,
				 const void *secret, size_t secret_len,
				 const void *chall, size_t chall_len)
{
	MD5_CTX md5_ctx;

	memset(md5, 0, MD5_DIGEST_LENGTH);

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, &ident, sizeof(ident));
	MD5_Update(&md5_ctx, secret, secret_len);
	MD5_Update(&md5_ctx, chall, chall_len);
	MD5_Final(md5, &md5_ctx);
}

static inline int nsnr_cmp(uint16_t ns, uint16_t nr)
{
/*
 * RFC 2661, section 5.8:
 *
 * The sequence number in the header of a received message is considered
 * less than or equal to the last received number if its value lies in
 * the range of the last received number and the preceding 32767 values,
 * inclusive. For example, if the last received sequence number was 15,
 * then messages with sequence numbers 0 through 15, as well as 32784
 * through 65535, would be considered less than or equal.
 */
	uint16_t sub_nsnr = ns - nr;
	uint16_t ref = -32767;        /* 32769 */

	/* Compare Ns - Nr with -32767 (which equals 32769 for uint16_t):
	 *
	 * Ns == Nr  <==>  Ns - Nr == 0,
	 * Ns > Nr   <==>  Ns - Nr in ]0, 32769[   <==>  0 < Ns - Nr < ref
	 * Ns < Nr   <==>  Ns - Nr in [-32767, 0[  <==> (Ns - Nr) >= ref,
	 */
	return (sub_nsnr != 0 && sub_nsnr < ref) - (sub_nsnr >= ref);
}

static inline struct l2tp_conn_t *l2tp_tunnel_self(void)
{
	return container_of(triton_context_self(), struct l2tp_conn_t, ctx);
}

static inline struct l2tp_sess_t *l2tp_session_self(void)
{
	return container_of(triton_context_self(), struct l2tp_sess_t, sctx);
}

static void l2tp_conn_log(void (*print)(const char *fmt, ...),
			  const struct l2tp_conn_t *conn)
{
	char addr[17];

	u_inet_ntoa(conn->peer_addr.sin_addr.s_addr, addr);

	print("%s:%i: ", addr, ntohs(conn->peer_addr.sin_port));
}

static int sess_cmp(const void *a, const void *b)
{
	const struct l2tp_sess_t *sess_a = a;
	const struct l2tp_sess_t *sess_b = b;

	return (sess_a->sid > sess_b->sid) - (sess_a->sid < sess_b->sid);
}

static struct l2tp_sess_t *l2tp_tunnel_get_session(struct l2tp_conn_t *conn,
						   uint16_t sid)
{
	struct l2tp_sess_t sess = {.sid = sid, 0};
	struct l2tp_sess_t **res = NULL;

	res = tfind(&sess, &conn->sessions, sess_cmp);

	return (res) ? *res : NULL;
}

static int l2tp_tunnel_genchall(uint16_t chall_len,
				struct l2tp_conn_t *conn,
				struct l2tp_packet_t *pack)
{
	void *ptr = NULL;
	size_t urandlen;
	ssize_t rdlen;

	if (chall_len == 0
	    || conf_secret == NULL || strlen(conf_secret) == 0) {
		if (conn->challenge) {
			_free(conn->challenge);
			conn->challenge = NULL;
		}
		conn->challenge_len = 0;
		return 0;
	}

	if (conn->challenge_len != chall_len) {
		ptr = _realloc(conn->challenge, chall_len);
		if (ptr == NULL) {
			l2tp_conn_log(log_error, conn);
			log_error("l2tp: Challenge generation failure:"
				  " Memory allocation failed\n");
			goto err;
		}
		conn->challenge = ptr;
		conn->challenge_len = chall_len;
	}

	for (urandlen = 0; urandlen < chall_len; urandlen += rdlen) {
		rdlen = read(urandom_fd, conn->challenge + urandlen,
			     chall_len - urandlen);
		if (rdlen < 0) {
			if (errno == EINTR)
				rdlen = 0;
			else {
				l2tp_conn_log(log_error, conn);
				log_error("l2tp: Challenge generation failure:"
					  " Reading from urandom failed: %s\n",
					  strerror(errno));
				goto err;
			}
		} else if (rdlen == 0) {
			l2tp_conn_log(log_error, conn);
			log_error("l2tp: Challenge generation failure:"
				  " EOF reached while reading from urandom\n");
			goto err;
		}
	}

	if (l2tp_packet_add_octets(pack, Challenge, conn->challenge,
				   conn->challenge_len, 1) < 0)
		goto err;

	return 0;

err:
	if (conn->challenge) {
		_free(conn->challenge);
		conn->challenge = NULL;
	}
	conn->challenge_len = 0;
	return -1;
}

static int l2tp_tunnel_storechall(struct l2tp_conn_t *conn,
				  const struct l2tp_attr_t *chall)
{
	void *ptr = NULL;

	if (chall == NULL) {
		if (conn->challenge) {
			_free(conn->challenge);
			conn->challenge = NULL;
		}
		conn->challenge_len = 0;
		return 0;
	}

	if (conf_secret == NULL || strlen(conf_secret) == 0) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: Authentication required by peer,"
			  " but no secret has been set for this tunnel\n");
		goto err;
	}

	if (conn->challenge_len != chall->length) {
		ptr = realloc(conn->challenge, chall->length);
		if (ptr == NULL) {
			l2tp_conn_log(log_error, conn);
			log_error("l2tp: Impossible to store received"
				  " challenge: Memory allocation failed\n");
			goto err;
		}
		conn->challenge = ptr;
		conn->challenge_len = chall->length;
	}

	memcpy(conn->challenge, chall->val.octets, chall->length);

	return 0;

err:
	if (conn->challenge) {
		_free(conn->challenge);
		conn->challenge = NULL;
	}
	conn->challenge_len = 0;
	return -1;
}

static int l2tp_tunnel_genchallresp(uint8_t msgident,
				    const struct l2tp_conn_t *conn,
				    struct l2tp_packet_t *pack)
{
	uint8_t challresp[MD5_DIGEST_LENGTH];

	if (conn->challenge == NULL) {
		if (conf_secret && strlen(conf_secret) > 0) {
			l2tp_conn_log(log_warn, conn);
			log_warn("l2tp: No Challenge sent by peer\n");
		}
		return 0;
	}

	if (conf_secret == NULL || strlen(conf_secret) == 0) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: Challenge Response generation failure:"
			  " No secret set for this tunnel\n");
		return -1;
	}

	comp_chap_md5(challresp, msgident, conf_secret, strlen(conf_secret),
		      conn->challenge, conn->challenge_len);
	if (l2tp_packet_add_octets(pack, Challenge_Response, challresp,
				   MD5_DIGEST_LENGTH, 1) < 0)
		return -1;

	return 0;
}

static int l2tp_tunnel_checkchallresp(uint8_t msgident,
				      const struct l2tp_conn_t *conn,
				      const struct l2tp_attr_t *challresp)
{
	uint8_t challref[MD5_DIGEST_LENGTH];

	if (conf_secret == NULL || strlen(conf_secret) == 0) {
		if (challresp) {
			l2tp_conn_log(log_warn, conn);
			log_warn("l2tp: Unexpected Challenge Response sent"
				 " by peer\n");
		}
		return 0;
	}

	if (conn->challenge == NULL) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: Challenge missing\n");
		return -1;
	}

	if (challresp == NULL) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: No Challenge Response sent by peer\n");
		return -1;
	} else if (challresp->length != MD5_DIGEST_LENGTH) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: Inconsistent Challenge Response sent by"
			  " peer (invalid length %i)\n", challresp->length);
		return -1;
	}

	comp_chap_md5(challref, msgident, conf_secret, strlen(conf_secret),
		      conn->challenge, conn->challenge_len);
	if (memcmp(challref, challresp->val.octets, MD5_DIGEST_LENGTH) != 0) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: Invalid Challenge Response sent by peer\n");
		return -1;
	}

	return 0;
}

static int l2tp_send_StopCCN(struct l2tp_conn_t *conn,
			     uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {res, err};

	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
				 &conn->peer_addr);
	if (pack == NULL)
		goto out_err;
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, conn->tid, 1) < 0)
		goto out_err;
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0)
		goto out_err;

	return l2tp_send(conn, pack, 0);

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_CDN(struct l2tp_sess_t *sess, uint16_t res, uint16_t err)
{
	struct l2tp_packet_t *pack = NULL;
	struct l2tp_avp_result_code rc = {res, err};

	pack = l2tp_packet_alloc(2, Message_Type_Call_Disconnect_Notify,
				 &sess->paren_conn->peer_addr);
	if (pack == NULL)
		goto out_err;
	if (l2tp_packet_add_int16(pack, Assigned_Session_ID,
				  sess->sid, 1) < 0)
		goto out_err;
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc,
				   sizeof(rc), 1) < 0)
		goto out_err;

	pack->hdr.sid = htons(sess->peer_sid);

	triton_context_call(&sess->paren_conn->ctx, (triton_event_func)__l2tp_send, pack);

	return 0;

out_err:
	if (pack)
		l2tp_packet_free(pack);
	return -1;
}

static int l2tp_tunnel_disconnect(struct l2tp_conn_t *conn, int res, int err)
{
	log_ppp_debug("l2tp: terminate (%i, %i)\n", res, err);

	if (l2tp_send_StopCCN(conn, res, err) < 0)
		return -1;

	conn->state = STATE_FIN;

	return 0;
}

static void __l2tp_session_free(void *data)
{
	struct l2tp_sess_t *sess = data;

	switch (sess->state1) {
	case STATE_PPP:
		sess->state1 = STATE_CLOSE;
		ap_session_terminate(&sess->ppp.ses,
				     TERM_USER_REQUEST, 1);
		/* No cleanup here, "sess" must remain a valid session
		   pointer (even if it no l2tp_conn_t points to it anymore).
		   This is because the above call to ap_session_terminate()
		   ends up in calling the l2tp_ppp_finished() callback,
		   which expects a valid session pointer. It is then the
		   responsibility of l2tp_ppp_finished() to eventually
		   cleanup the session structure by calling again
		   __l2tp_session_free(). */
		return;
	case STATE_WAIT_ICCN:
	case STATE_WAIT_OCRP:
	case STATE_WAIT_OCCN:
	case STATE_ESTB:
		__sync_sub_and_fetch(&stat_starting, 1);
		break;
	}

	if (sess->state1 == STATE_ESTB || sess->state1 == STATE_CLOSE)
		/* Don't send event if session wasn't fully established */
		triton_event_fire(EV_CTRL_FINISHED, &sess->ppp.ses);

	log_ppp_info1("disconnected\n");

	if (sess->timeout_timer.tpd)
		triton_timer_del(&sess->timeout_timer);
	triton_context_unregister(&sess->sctx);

	if (sess->ppp.fd != -1)
		close(sess->ppp.fd);
	if (sess->ppp.ses.chan_name)
		_free(sess->ppp.ses.chan_name);
	if (sess->ctrl.calling_station_id)
		_free(sess->ctrl.calling_station_id);
	if (sess->ctrl.called_station_id)
		_free(sess->ctrl.called_station_id);

	triton_context_call(&sess->paren_conn->ctx,
			    l2tp_tunnel_session_freed, NULL);

	mempool_free(sess);
}

static void __l2tp_tunnel_free_session(void *data)
{
	struct l2tp_sess_t *sess = data;

	triton_context_call(&sess->sctx, __l2tp_session_free, sess);
}

static void l2tp_tunnel_free_session(void *sess)
{
	struct triton_context_t *ctx = triton_context_self();
	struct l2tp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	tdelete(sess, &conn->sessions, sess_cmp);
	__l2tp_tunnel_free_session(sess);
}

static void l2tp_tunnel_free_sessionid(void *data)
{
	uint16_t sid = (intptr_t)data;
	struct l2tp_conn_t *conn = l2tp_tunnel_self();
	struct l2tp_sess_t *sess = l2tp_tunnel_get_session(conn, sid);

	if (sess)
		l2tp_tunnel_free_session(sess);
}

static void l2tp_session_free(struct l2tp_sess_t *sess)
{
	intptr_t sid = sess->sid;

	triton_context_call(&sess->paren_conn->ctx,
			    l2tp_tunnel_free_sessionid, (void *)sid);
}

static void l2tp_tunnel_free(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	if (conn->state != STATE_CLOSE) {
		l2tp_conn_log(log_debug, conn);
		log_debug("tunnel_free\n");
		conn->state = STATE_CLOSE;
	}

	if (conn->sess_count != 0) {
		/*
		 * There are still sessions in this tunnel: remove the ones
		 * accessible from conn->sessions then exit.
		 *
		 * Each removed session will make an asynchronous call to
		 * l2tp_tunnel_session_freed(), which is responsible for
		 * calling l2tp_tunnel_free() again once the last session
		 * gets removed.
		 *
		 * There may be also sessions in this tunnel that are not
		 * referenced in conn->sessions. This can happen when a
		 * a session has been removed, but its cleanup function has
		 * not yet been scheduled. Such sessions will also call
		 * l2tp_tunnel_session_freed() after cleanup, so
		 * l2tp_tunnel_free() will be called again once every sessions
		 * have been cleaned up.
		 *
		 * This behaviour ensures that the parent tunnel of a session
		 * remains valid during this session's lifetime.
		 */
		if (conn->sessions) {
			tdestroy(conn->sessions, __l2tp_tunnel_free_session);
			conn->sessions = NULL;
		}
		return;
	}

	if (conn->hnd.tpd)
		triton_md_unregister_handler(&conn->hnd);

	if (conn->hnd.fd >= 0)
		close(conn->hnd.fd);

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	if (conn->rtimeout_timer.tpd)
		triton_timer_del(&conn->rtimeout_timer);

	if (conn->hello_timer.tpd)
		triton_timer_del(&conn->hello_timer);

	pthread_mutex_lock(&l2tp_lock);
	l2tp_conn[conn->tid] = NULL;
	pthread_mutex_unlock(&l2tp_lock);

	if (conn->tunnel_fd != -1)
		close(conn->tunnel_fd);

	if (conn->ctx.tpd)
		triton_context_unregister(&conn->ctx);

	while (!list_empty(&conn->send_queue)) {
		pack = list_entry(conn->send_queue.next, typeof(*pack), entry);
		list_del(&pack->entry);
		l2tp_packet_free(pack);
	}

	if (conn->challenge)
		_free(conn->challenge);

	mempool_free(conn);
}

static void l2tp_tunnel_session_freed(void *data)
{
	struct l2tp_conn_t *conn = l2tp_tunnel_self();

	if (--conn->sess_count == 0) {
		if (conn->state != STATE_CLOSE)
			l2tp_send_StopCCN(conn, 1, 0);
		l2tp_tunnel_free(conn);
	}
}

static int l2tp_session_disconnect(struct l2tp_sess_t *sess,
				   uint16_t res, uint16_t err)
{
	if (l2tp_send_CDN(sess, res, err) < 0)
		return -1;
	l2tp_session_free(sess);

	return 0;
}

static void l2tp_ppp_finished(struct ap_session *ses)
{
	struct l2tp_sess_t *sess = l2tp_session_self();

	log_ppp_debug("l2tp: ppp finished\n");
	__sync_sub_and_fetch(&stat_active, 1);
	if (sess->state1 != STATE_CLOSE) {
		sess->state1 = STATE_CLOSE;
		l2tp_send_CDN(sess, 2, 0);
		l2tp_session_free(sess);
	} else {
		/* Called by __l2tp_session_free() via ap_session_terminate().
		   Now, call __l2tp_session_free() again to finish cleanup. */
		__l2tp_session_free(sess);
	}
}

static void l2tp_ppp_started(struct ap_session *ses)
{
	log_ppp_debug("l2tp: ppp started\n");
}

static void l2tp_session_timeout(struct triton_timer_t *t)
{
	struct l2tp_sess_t *sess = container_of(t, typeof(*sess),
						timeout_timer);

	log_ppp_debug("l2tp: session timeout\n");
	l2tp_session_free(sess);
}

static struct l2tp_sess_t *l2tp_tunnel_new_session(struct l2tp_conn_t *conn)
{
	struct l2tp_sess_t *sess = NULL;
	struct l2tp_sess_t **sess_search = NULL;
	ssize_t rdlen = 0;

	sess = mempool_alloc(l2tp_sess_pool);
	if (sess == NULL) {
		log_warn("l2tp: Impossible to allocate new session for"
			 " tunnel %hu: memory allocation error\n", conn->tid);
		goto out_err;
	}
	memset(sess, 0, sizeof(*sess));

	rdlen = read(urandom_fd, &sess->sid, sizeof(sess->sid));
	if (rdlen != sizeof(sess->sid)) {
		log_warn("l2tp: Impossible to allocate new session for"
			 " tunnel %hu: could not get random number (%s)\n",
			 conn->tid,
			 (rdlen < 0) ? strerror(errno) : "short read");
		goto out_err;
	}
	if (sess->sid == 0) {
		log_warn("l2tp: Impossible to allocate new session for"
			 " tunnel %hu: could not get a valid session ID\n",
			 conn->tid);
		goto out_err;
	}

	sess_search = tsearch(sess, &conn->sessions, sess_cmp);
	if (*sess_search != sess) {
		log_warn("l2tp: Impossible to allocate new session for"
			 " tunnel %hu: could not find any unused session ID\n",
			 conn->tid);
		goto out_err;
	}

	return sess;

out_err:
	if (sess)
		mempool_free(sess);
	return NULL;
}

static void l2tp_sess_close(struct triton_context_t *ctx)
{
	struct l2tp_sess_t *sess = container_of(ctx, typeof(*sess), sctx);

	l2tp_session_disconnect(sess, 3, 0);
}

static struct l2tp_sess_t *l2tp_tunnel_alloc_session(struct l2tp_conn_t *conn)
{
	struct l2tp_sess_t *sess = NULL;

	sess = l2tp_tunnel_new_session(conn);
	if (sess == NULL)
		return NULL;

	sess->paren_conn = conn;
	sess->peer_sid = 0;
	sess->state1 = STATE_CLOSE;
	sess->lns_mode = conn->lns_mode;

	sess->sctx.before_switch = log_switch;
	sess->sctx.close = l2tp_sess_close;

	sess->ctrl.ctx = &sess->sctx;
	sess->ctrl.type = CTRL_TYPE_L2TP;
	sess->ctrl.ppp = 1;
	sess->ctrl.name = "l2tp";
	sess->ctrl.started = l2tp_ppp_started;
	sess->ctrl.finished = l2tp_ppp_finished;
	sess->ctrl.terminate = ppp_terminate;
	sess->ctrl.max_mtu = 1420;
	sess->ctrl.mppe = conf_mppe;
	sess->ctrl.calling_station_id = _malloc(17);
	sess->ctrl.called_station_id = _malloc(17);
	u_inet_ntoa(conn->peer_addr.sin_addr.s_addr,
		    sess->ctrl.calling_station_id);
	u_inet_ntoa(conn->host_addr.sin_addr.s_addr,
		    sess->ctrl.called_station_id);
	sess->timeout_timer.expire = l2tp_session_timeout;
	sess->timeout_timer.period = conf_timeout * 1000;

	ppp_init(&sess->ppp);
	sess->ppp.ses.ctrl = &sess->ctrl;
	sess->ppp.fd = -1;

	return sess;
}

static int l2tp_tunnel_confirm_session(struct l2tp_sess_t *sess)
{
	struct l2tp_conn_t *conn = l2tp_tunnel_self();

	if (triton_context_register(&sess->sctx, &sess->ppp.ses) < 0)
		return -1;
	triton_context_wakeup(&sess->sctx);
	__sync_add_and_fetch(&stat_starting, 1);
	++conn->sess_count;

	return 0;
}

static int l2tp_tunnel_cancel_session(struct l2tp_sess_t *sess)
{
	tdelete(sess, &sess->paren_conn->sessions, sess_cmp);
	if (sess->ctrl.calling_station_id)
		_free(sess->ctrl.calling_station_id);
	if (sess->ctrl.called_station_id)
		_free(sess->ctrl.called_station_id);
	mempool_free(sess);

	return 0;
}

static void l2tp_conn_close(struct triton_context_t *ctx)
{
	struct l2tp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	l2tp_tunnel_disconnect(conn, 0, 0);
	l2tp_tunnel_free(conn);
}

static int l2tp_tunnel_start(struct l2tp_conn_t *conn,
			     triton_event_func start_func,
			     void *start_param)
{
	if (triton_context_register(&conn->ctx, NULL) < 0)
		return -1;
	triton_md_register_handler(&conn->ctx, &conn->hnd);
	if (triton_md_enable_handler(&conn->hnd, MD_MODE_READ) < 0)
		goto out_err;
	triton_context_wakeup(&conn->ctx);
	if (triton_context_call(&conn->ctx, start_func, start_param) < 0)
		goto out_err;

	return 0;

out_err:
	triton_md_unregister_handler(&conn->hnd);
	triton_context_unregister(&conn->ctx);

	return -1;
}

static struct l2tp_conn_t *l2tp_tunnel_alloc(const struct sockaddr_in *peer,
					     const struct sockaddr_in *host,
					     uint32_t framing_cap,
					     int lns_mode)
{
	struct l2tp_conn_t *conn;
	socklen_t hostaddrlen = sizeof(conn->host_addr);
	uint16_t tid;
	int flag;

	conn = mempool_alloc(l2tp_conn_pool);
	if (!conn) {
		log_emerg("l2tp: out of memory\n");
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));
	INIT_LIST_HEAD(&conn->send_queue);

	conn->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (conn->hnd.fd < 0) {
		log_error("l2tp: socket: %s\n", strerror(errno));
		mempool_free(conn);
		return NULL;
	}

	flag = fcntl(conn->hnd.fd, F_GETFD);
	if (flag < 0) {
		log_error("l2tp: fcntl(F_GETFD): %s\n", strerror(errno));
		goto out_err;
	}
	flag = fcntl(conn->hnd.fd, F_SETFD, flag | FD_CLOEXEC);
	if (flag < 0) {
		log_error("l2tp: failed to set close-on-exec flag:"
			  " fcntl(F_SETFD): %s\n", strerror(errno));
		goto out_err;
	}

	flag = 1;
	if (setsockopt(conn->hnd.fd, SOL_SOCKET, SO_REUSEADDR,
		       &flag, sizeof(flag)) < 0) {
		log_error("l2tp: setsockopt(SO_REUSEADDR): %s\n",
			  strerror(errno));
		goto out_err;
	}
	if (bind(conn->hnd.fd, host, sizeof(*host))) {
		log_error("l2tp: bind: %s\n", strerror(errno));
		goto out_err;
	}

	if (connect(conn->hnd.fd, (struct sockaddr *)peer, sizeof(*peer))) {
		log_error("l2tp: connect: %s\n", strerror(errno));
		goto out_err;
	}

	flag = fcntl(conn->hnd.fd, F_GETFL);
	if (flag < 0) {
		log_error("l2tp: fcntl(F_GETFL): %s\n", strerror(errno));
		goto out_err;
	}
	flag = fcntl(conn->hnd.fd, F_SETFL, flag | O_NONBLOCK);
	if (flag < 0) {
		log_error("l2tp: failed to set nonblocking mode:"
			  " fcntl(F_SETFL): %s\n", strerror(errno));
		goto out_err;
	}

	pthread_mutex_lock(&l2tp_lock);
	for (tid = l2tp_tid + 1; tid != l2tp_tid; tid++) {
		if (tid == L2TP_MAX_TID)
			tid = 1;
		if (!l2tp_conn[tid]) {
			l2tp_conn[tid] = conn;
			conn->tid = tid;
			break;
		}
	}
	pthread_mutex_unlock(&l2tp_lock);

	if (!conn->tid) {
		if (conf_verbose)
			log_warn("l2tp: no free tid available\n");
		goto out_err;
	}

	if (getsockname(conn->hnd.fd, &conn->host_addr, &hostaddrlen) < 0) {
		log_error("l2tp: getsockname: %s\n", strerror(errno));
		goto out_err;
	}
	if (hostaddrlen != sizeof(conn->host_addr)) {
		log_error("l2tp: getsockname: invalid address length: %i\n",
			  hostaddrlen);
		goto out_err;
	}

	memcpy(&conn->peer_addr, peer, sizeof(*peer));
	conn->framing_cap = framing_cap;

	conn->ctx.before_switch = log_switch;
	conn->ctx.close = l2tp_conn_close;
	conn->hnd.read = l2tp_conn_read;
	conn->timeout_timer.expire = l2tp_timeout;
	conn->timeout_timer.period = conf_timeout * 1000;
	conn->rtimeout_timer.expire = l2tp_rtimeout;
	conn->rtimeout_timer.period = conf_rtimeout * 1000;
	conn->hello_timer.expire = l2tp_send_HELLO;
	conn->hello_timer.period = conf_hello_interval * 1000;

	conn->tunnel_fd = -1;

	conn->sessions = NULL;
	conn->sess_count = 0;
	conn->lns_mode = lns_mode;

	return conn;

out_err:
	close(conn->hnd.fd);
	mempool_free(conn);
	return NULL;
}

static inline int l2tp_tunnel_update_peerport(struct l2tp_conn_t *conn,
					      uint16_t port_nbo)
{
	in_port_t old_port = conn->peer_addr.sin_port;
	int res;

	conn->peer_addr.sin_port = port_nbo;
	res = connect(conn->hnd.fd, &conn->peer_addr, sizeof(conn->peer_addr));
	if (res < 0) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: Impossible to update peer port from"
			  " %hu to %hu: connect() failed: %s\n",
			  ntohs(old_port), ntohs(port_nbo), strerror(errno));
		conn->peer_addr.sin_port = old_port;
	}

	return res;
}

static int l2tp_session_connect(struct l2tp_sess_t *sess)
{
	struct sockaddr_pppol2tp pppox_addr;
	struct l2tp_conn_t *conn = sess->paren_conn;
	int lns_mode = sess->lns_mode;
	int flg;
	char addr[17];
	char chan_name[64];

	sess->ppp.fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (sess->ppp.fd < 0) {
		log_ppp_error("l2tp: socket(AF_PPPOX): %s\n", strerror(errno));
		goto out_err;
	}

	flg = fcntl(sess->ppp.fd, F_GETFD);
	if (flg < 0) {
		log_ppp_error("l2tp: fcntl(F_GETFD): %s\n", strerror(errno));
		goto out_err;
	}
	flg = fcntl(sess->ppp.fd, F_SETFD, flg | FD_CLOEXEC);
	if (flg < 0) {
		log_ppp_error("l2tp: fcntl(F_SETFD): %s\n", strerror(errno));
		goto out_err;
	}

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = conn->hnd.fd;
	memcpy(&pppox_addr.pppol2tp.addr, &conn->peer_addr,
	       sizeof(conn->peer_addr));
	pppox_addr.pppol2tp.s_tunnel = conn->tid;
	pppox_addr.pppol2tp.d_tunnel = conn->peer_tid;
	pppox_addr.pppol2tp.s_session = sess->sid;
	pppox_addr.pppol2tp.d_session = sess->peer_sid;

	if (connect(sess->ppp.fd, (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_ppp_error("l2tp: connect(session): %s\n", strerror(errno));
		goto out_err;
	}

	if (setsockopt(sess->ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE,
		       &lns_mode, sizeof(lns_mode))) {
		log_ppp_error("l2tp: setsockopt: %s\n", strerror(errno));
		goto out_err;
	}

	u_inet_ntoa(conn->peer_addr.sin_addr.s_addr, addr);
	sprintf(chan_name, "%s:%i session %i",
		addr, ntohs(conn->peer_addr.sin_port), sess->peer_sid);
	sess->ppp.ses.chan_name = _strdup(chan_name);

	triton_event_fire(EV_CTRL_STARTED, &sess->ppp.ses);

	if (establish_ppp(&sess->ppp))
		goto out_err;

	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);

	sess->state1 = STATE_PPP;

	return 0;

out_err:
	if (sess->ppp.fd >= 0) {
		close(sess->ppp.fd);
		sess->ppp.fd = -1;
	}
	return -1;
}

static int l2tp_tunnel_connect(struct l2tp_conn_t *conn)
{
	struct sockaddr_pppol2tp pppox_addr;
	int flg;

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = conn->hnd.fd;
	memcpy(&pppox_addr.pppol2tp.addr, &conn->peer_addr,
	       sizeof(conn->peer_addr));
	pppox_addr.pppol2tp.s_tunnel = conn->tid;
	pppox_addr.pppol2tp.d_tunnel = conn->peer_tid;

	conn->tunnel_fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (conn->tunnel_fd < 0) {
		log_ppp_error("l2tp: socket(AF_PPPOX): %s\n", strerror(errno));
		goto out_err;
	}

	flg = fcntl(conn->tunnel_fd, F_GETFD);
	if (flg < 0) {
		log_ppp_error("l2tp: fcntl(F_GETFD): %s\n", strerror(errno));
		goto out_err;
	}
	flg = fcntl(conn->tunnel_fd, F_SETFD, flg | FD_CLOEXEC);
	if (flg < 0) {
		log_ppp_error("l2tp: fcntl(F_SETFD): %s\n", strerror(errno));
		goto out_err;
	}

	if (connect(conn->tunnel_fd, (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_ppp_error("l2tp: connect(tunnel): %s\n", strerror(errno));
		goto out_err;
	}

	if (conf_hello_interval)
		triton_timer_add(&conn->ctx, &conn->hello_timer, 0);

	return 0;

out_err:
	if (conn->tunnel_fd >= 0) {
		close(conn->tunnel_fd);
		conn->tunnel_fd = -1;
	}
	return -1;
}

static void l2tp_retransmit(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = list_entry(conn->send_queue.next, typeof(*pack), entry);
	pack->hdr.Nr = htons(conn->Nr);
	if (conf_verbose) {
		l2tp_conn_log(log_debug, conn);
		log_debug("send ");
		l2tp_packet_print(pack, log_debug);
	}
	l2tp_packet_send(conn->hnd.fd, pack);
}

static void l2tp_rtimeout(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn), rtimeout_timer);
	struct l2tp_packet_t *pack;

	if (!list_empty(&conn->send_queue)) {
		log_ppp_debug("l2tp: retransmit (%i)\n", conn->retransmit);
		if (++conn->retransmit <= conf_retransmit) {
			pack = list_entry(conn->send_queue.next, typeof(*pack), entry);
			pack->hdr.Nr = htons(conn->Nr);
			if (conf_verbose) {
				log_ppp_debug("send ");
				l2tp_packet_print(pack, log_ppp_debug);
			}
			if (l2tp_packet_send(conn->hnd.fd, pack) == 0)
				return;
		} else
			l2tp_tunnel_free(conn);
	}
}

static void l2tp_timeout(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn), timeout_timer);
	log_ppp_debug("l2tp: timeout\n");
	l2tp_tunnel_free(conn);
}

static int l2tp_send(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack, int debug)
{
	conn->retransmit = 0;

	pack->hdr.tid = htons(conn->peer_tid);
	//pack->hdr.sid = htons(conn->peer_sid);
	pack->hdr.Nr = htons(conn->Nr);
	pack->hdr.Ns = htons(conn->Ns);

	if (!list_empty(&pack->attrs))
		conn->Ns++;

	if (conf_verbose) {
		if (debug) {
			l2tp_conn_log(log_debug, conn);
			log_debug("send ");
			l2tp_packet_print(pack, log_debug);
		} else {
			l2tp_conn_log(log_info2, conn);
			log_info2("send ");
			l2tp_packet_print(pack, log_info2);
		}
	}

	if (l2tp_packet_send(conn->hnd.fd, pack))
		goto out_err;

	if (!list_empty(&pack->attrs)) {
		list_add_tail(&pack->entry, &conn->send_queue);
		if (!conn->rtimeout_timer.tpd)
			triton_timer_add(&conn->ctx, &conn->rtimeout_timer, 0);
	} else
		l2tp_packet_free(pack);
	
	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static void __l2tp_send(struct l2tp_packet_t *pack)
{
	struct l2tp_conn_t *conn = container_of(triton_context_self(), typeof(*conn), ctx);

	if (l2tp_send(conn, pack, 0))
		l2tp_tunnel_free(conn);
}

static int l2tp_send_ZLB(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, 0, &conn->peer_addr);
	if (!pack)
		return -1;

	if (l2tp_send(conn, pack, 1))
		return -1;

	return 0;
}

static void l2tp_send_HELLO(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn), hello_timer);
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Hello, &conn->peer_addr);
	if (!pack) {
		l2tp_tunnel_free(conn);
		return;
	}

	if (l2tp_send(conn, pack, 1))
		l2tp_tunnel_free(conn);
}

static void l2tp_send_SCCRQ(void *peer_addr)
{
	struct l2tp_conn_t *conn = l2tp_tunnel_self();
	struct l2tp_packet_t *pack = NULL;

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Request,
				 &conn->peer_addr);
	if (pack == NULL)
		goto err;

	if (l2tp_packet_add_int16(pack, Protocol_Version,
				  L2TP_V2_PROTOCOL_VERSION, 1) < 0)
		goto pack_err;
	if (l2tp_packet_add_string(pack, Host_Name, conf_host_name, 1) < 0)
		goto pack_err;
	if (l2tp_packet_add_int32(pack, Framing_Capabilities,
				  conn->framing_cap, 1) < 0)
		goto pack_err;
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, conn->tid, 1) < 0)
		goto pack_err;
	if (l2tp_packet_add_string(pack, Vendor_Name, "accel-ppp", 0) < 0)
		goto pack_err;

	if (l2tp_tunnel_genchall(MD5_DIGEST_LENGTH, conn, pack) < 0)
		goto pack_err;

	/* Peer may reply with arbitrary source port */
	if (l2tp_tunnel_update_peerport(conn, 0) < 0)
		goto err;

	if (l2tp_send(conn, pack, 0) < 0)
		goto err;

	if (!conn->timeout_timer.tpd)
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
	else
		triton_timer_mod(&conn->timeout_timer, 0);

	conn->state = STATE_WAIT_SCCRP;

	return;

pack_err:
	l2tp_packet_free(pack);
err:
	l2tp_tunnel_free(conn);
}

static void l2tp_send_SCCRP(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Reply,
				 &conn->peer_addr);
	if (!pack)
		goto out;
	
	if (l2tp_packet_add_int16(pack, Protocol_Version, L2TP_V2_PROTOCOL_VERSION, 1))
		goto out_err;
	if (l2tp_packet_add_string(pack, Host_Name, conf_host_name, 1))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Framing_Capabilities, conn->framing_cap, 1))
		goto out_err;
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, conn->tid, 1))
		goto out_err;
	if (l2tp_packet_add_string(pack, Vendor_Name, "accel-ppp", 0))
		goto out_err;

	if (l2tp_tunnel_genchallresp(Message_Type_Start_Ctrl_Conn_Reply,
				     conn, pack) < 0)
		goto out_err;
	if (l2tp_tunnel_genchall(MD5_DIGEST_LENGTH, conn, pack) < 0)
		goto out_err;

	if (l2tp_send(conn, pack, 0))
		goto out;

	if (!conn->timeout_timer.tpd)
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
	else
		triton_timer_mod(&conn->timeout_timer, 0);

	conn->state = STATE_WAIT_SCCCN;

	return;

out_err:
	l2tp_packet_free(pack);
out:
	l2tp_tunnel_free(conn);
}

static int l2tp_send_SCCCN(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack = NULL;

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Connected,
				 &conn->peer_addr);
	if (pack == NULL)
		goto err;

	if (l2tp_tunnel_genchallresp(Message_Type_Start_Ctrl_Conn_Connected,
				     conn, pack) < 0)
		goto pack_err;
	l2tp_tunnel_storechall(conn, NULL);

	if (l2tp_send(conn, pack, 0) < 0)
		goto err;

	return 0;

pack_err:
	l2tp_packet_free(pack);
err:
	return -1;
}

static int l2tp_send_ICRQ(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Request,
				 &sess->paren_conn->peer_addr);
	if (pack == NULL)
		return -1;

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, sess->sid, 1))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Call_Serial_Number, 0, 1))
		goto out_err;

	if (l2tp_send(sess->paren_conn, pack, 0))
		return -1;

	if (!sess->timeout_timer.tpd)
		triton_timer_add(&sess->sctx, &sess->timeout_timer, 0);
	else
		triton_timer_mod(&sess->timeout_timer, 0);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_ICRP(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Reply,
				 &sess->paren_conn->peer_addr);
	if (!pack)
		return -1;

	pack->hdr.sid = htons(sess->peer_sid);
	
	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, sess->sid, 1))
		goto out_err;

	l2tp_send(sess->paren_conn, pack, 0);

	if (!sess->timeout_timer.tpd)
		triton_timer_add(&sess->sctx, &sess->timeout_timer, 0);
	else
		triton_timer_mod(&sess->timeout_timer, 0);
	
	sess->state1 = STATE_WAIT_ICCN;
	
	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_ICCN(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Connected,
				 &sess->paren_conn->peer_addr);
	if (pack == 0)
		return -1;

	pack->hdr.sid = htons(sess->peer_sid);

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, sess->sid, 1) < 0)
		goto out_err;
	if (l2tp_packet_add_int32(pack, TX_Speed, 1000, 1) < 0)
		goto out_err;
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1) < 0)
		goto out_err;

	if (l2tp_send(sess->paren_conn, pack, 0) < 0)
		return -1;

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_send_OCRQ(struct l2tp_sess_t *sess)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Request,
				 &sess->paren_conn->peer_addr);
	if (!pack)
		return -1;

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, sess->sid, 1))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Call_Serial_Number, 0, 1))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Minimum_BPS, 100, 1))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Maximum_BPS, 100000, 1))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Bearer_Type, 3, 1))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Framing_Type, 3, 1))
		goto out_err;
	if (l2tp_packet_add_string(pack, Called_Number, "", 1))
		goto out_err;

	if (l2tp_send(sess->paren_conn, pack, 0))
		return -1;

	if (!sess->timeout_timer.tpd)
		triton_timer_add(&sess->sctx, &sess->timeout_timer, 0);
	else
		triton_timer_mod(&sess->timeout_timer, 0);

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static int l2tp_recv_SCCRQ(const struct l2tp_serv_t *serv,
			   const struct l2tp_packet_t *pack,
			   const struct in_pktinfo *pkt_info)
{
	struct l2tp_attr_t *attr;
	struct l2tp_attr_t *protocol_version = NULL;
	struct l2tp_attr_t *assigned_tid = NULL;
	struct l2tp_attr_t *assigned_cid = NULL;
	struct l2tp_attr_t *framing_cap = NULL;
	struct l2tp_attr_t *router_id = NULL;
	struct l2tp_attr_t *challenge = NULL;
	struct l2tp_conn_t *conn = NULL;
	struct sockaddr_in host_addr = { 0 };

	if (ap_shutdown)
		return 0;
	
	if (triton_module_loaded("connlimit") && connlimit_check(cl_key_from_ipv4(pack->addr.sin_addr.s_addr)))
		return 0;

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
			case Protocol_Version:
				protocol_version = attr;
				break;
			case Framing_Capabilities:
				framing_cap = attr;
				break;
			case Assigned_Tunnel_ID:
				assigned_tid = attr;
				break;
			case Challenge:
				challenge = attr;
				break;
			case Assigned_Connection_ID:
				assigned_cid = attr;
				break;
			case Router_ID:
				router_id = attr;
				break;
			case Message_Digest:
				if (conf_verbose)
					log_warn("l2tp: Message-Digest is not supported\n");
				return -1;
		}
	}

	if (assigned_tid) {
		if (!protocol_version) {
			if (conf_verbose)
				log_warn("l2tp: SCCRQ: no Protocol-Version present in message\n");
			return -1;
		}
		if (protocol_version->val.uint16 != L2TP_V2_PROTOCOL_VERSION) {
			if (conf_verbose)
				log_warn("l2tp: protocol version %02x is not supported\n", protocol_version->val.uint16);
			return -1;
		}
		if (!framing_cap) {
			if (conf_verbose)
				log_warn("l2tp: SCCRQ: no Framing-Capabilities present in message\n");
			return -1;
		}

		host_addr.sin_family = AF_INET;
		host_addr.sin_addr = pkt_info->ipi_addr;
		host_addr.sin_port = 0;

		conn = l2tp_tunnel_alloc(&pack->addr, &host_addr,
					 framing_cap->val.uint32, 1);
		if (conn == NULL)
			return -1;

		if (conf_verbose) {
			log_switch(&conn->ctx, NULL);
			log_ppp_info2("recv ");
			l2tp_packet_print(pack, log_ppp_info2);
		}

		if (l2tp_tunnel_storechall(conn, challenge) < 0) {
			l2tp_tunnel_free(conn);
			return -1;
		}

		conn->peer_tid = assigned_tid->val.uint16;
		conn->Nr = 1;

		if (l2tp_tunnel_start(conn, (triton_event_func)l2tp_send_SCCRP, conn) < 0) {
			l2tp_tunnel_free(conn);
			return -1;
		}

	} else if (assigned_cid) {
		// not yet implemented
		return 0;
	} else {
		if (conf_verbose)
			log_warn("l2tp: SCCRQ: no Assigned-Tunnel-ID or Assigned-Connection-ID present in message\n");
		return -1;
	}

	if (conf_secret && strlen(conf_secret) > 0 && conn->challenge == NULL) {
		if (conf_verbose)
			log_warn("l2tp: SCCRQ: no Challenge present in message\n");
	}

	return 0;
}

static int l2tp_recv_SCCRP(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *protocol_version = NULL;
	struct l2tp_attr_t *assigned_tid = NULL;
	struct l2tp_attr_t *framing_cap = NULL;
	struct l2tp_attr_t *challenge = NULL;
	struct l2tp_attr_t *challenge_resp = NULL;
	struct l2tp_attr_t *unknown_attr = NULL;
	struct l2tp_attr_t *attr = NULL;

	if (conn->state != STATE_WAIT_SCCRP) {
		l2tp_conn_log(log_warn, conn);
		log_warn("l2tp: unexpected SCCRP\n");
		return -1;
	}

	triton_timer_del(&conn->timeout_timer);

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case Host_Name:
		case Bearer_Capabilities:
		case Firmware_Revision:
		case Vendor_Name:
		case Recv_Window_Size:
			break;
		case Protocol_Version:
			protocol_version = attr;
			break;
		case Framing_Capabilities:
			framing_cap = attr;
			break;
		case Assigned_Tunnel_ID:
			assigned_tid = attr;
			break;
		case Challenge:
			challenge = attr;
			break;
		case Challenge_Response:
			challenge_resp = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else {
				l2tp_conn_log(log_warn, conn);
				log_warn("l2tp: SCCRP:"
					 " unknown attribute %i\n",
					 attr->attr->id);
			}
			break;
		}
	}

	if (assigned_tid == NULL) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: SCCRP: missing mandatory AVP:"
			  " Assigned Tunnel ID\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	/* Set peer_tid as soon as possible so that StopCCCN
	   will be sent to the right tunnel in case of error */
	conn->peer_tid = assigned_tid->val.uint16;

	if (unknown_attr) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: SCCRP: unknown mandatory attribute %i\n",
			  unknown_attr->attr->id);
		l2tp_tunnel_disconnect(conn, 2, 8);
		return -1;
	}
	if (framing_cap == NULL) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: SCCRP: missing mandatory AVP:"
			  " Framing Capabilities\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (protocol_version == NULL) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: SCCRP: missing mandatory AVP:"
			  " Protocol Version\n");
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (protocol_version->val.uint16 != L2TP_V2_PROTOCOL_VERSION) {
		l2tp_conn_log(log_error, conn);
		log_error("l2tp: SCCRP: unknown protocol version %hhu.%hhu\n",
			  protocol_version->val.uint16 >> 8,
			  protocol_version->val.uint16 & 0x00FF);
		l2tp_tunnel_disconnect(conn, 5, 0);
		return -1;
	}

	if (l2tp_tunnel_checkchallresp(Message_Type_Start_Ctrl_Conn_Reply,
				       conn, challenge_resp) < 0) {
		l2tp_tunnel_disconnect(conn, 4, 0);
		return -1;
	}
	if (l2tp_tunnel_storechall(conn, challenge) < 0) {
		l2tp_tunnel_disconnect(conn, 2, 4);
		return -1;
	}

	if (l2tp_tunnel_connect(conn) < 0) {
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	if (l2tp_send_SCCCN(conn) < 0) {
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}

	conn->state = STATE_ESTB;

	return 0;
}

static int l2tp_recv_SCCCN(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr = NULL;
	struct l2tp_attr_t *challenge_resp = NULL;

	if (conn->state != STATE_WAIT_SCCCN) {
		log_ppp_warn("l2tp: unexpected SCCCN\n");
		return 0;
	}

	triton_timer_del(&conn->timeout_timer);

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
			break;
		case Challenge_Response:
			challenge_resp = attr;
			break;
		default:
			if (attr->M) {
				l2tp_conn_log(log_error, conn);
				log_error("l2tp: SCCCN:"
					  " unknown attribute %i\n",
					  attr->attr->id);
				l2tp_tunnel_disconnect(conn, 2, 8);
				return -1;
			}
		}
	}

	if (l2tp_tunnel_checkchallresp(Message_Type_Start_Ctrl_Conn_Connected,
				       conn, challenge_resp) < 0) {
		l2tp_tunnel_disconnect(conn, 4, 0);
		return -1;
	}
	l2tp_tunnel_storechall(conn, NULL);

	if (l2tp_tunnel_connect(conn) < 0) {
		l2tp_tunnel_disconnect(conn, 2, 0);
		return -1;
	}
	conn->state = STATE_ESTB;
	l2tp_send_ZLB(conn);

	return 0;
}

static int l2tp_recv_StopCCN(struct l2tp_conn_t *conn,
			     const struct l2tp_packet_t *pack)
{
	l2tp_send_ZLB(conn);
	return -1;
}

static int l2tp_recv_HELLO(struct l2tp_conn_t *conn,
			   const struct l2tp_packet_t *pack)
{
	if (l2tp_send_ZLB(conn))
		return -1;
	
	return 0;
}

static int l2tp_recv_ICRQ(struct l2tp_conn_t *conn,
			  const struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr;
	struct l2tp_attr_t *assigned_sid = NULL;
	struct l2tp_sess_t *sess = NULL;
	uint16_t res = 0;
	uint16_t err = 0;

	if (conn->state != STATE_ESTB && conn->lns_mode) {
		log_ppp_warn("l2tp: unexpected ICRQ\n");
		return 0;
	}

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_ppp_warn("l2tp: no more session available\n");
		return 0;
	}

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
			case Assigned_Session_ID:
				assigned_sid = attr;
				break;
			case Message_Type:
			case Call_Serial_Number:
			case Bearer_Type:
			case Calling_Number:
			case Called_Number:
			case Sub_Address:
			case Physical_Channel_ID:
				break;
			default:
				if (attr->M) {
					if (conf_verbose) {
						log_ppp_warn("l2tp: ICRQ: unknown attribute %i\n", attr->attr->id);
					}
					res = 2;
					err = 8;
				}
				break;
		}
	}

	if (!assigned_sid) {
		if (conf_verbose)
			log_ppp_warn("l2tp: ICRQ: no Assigned-Session-ID attribute present in message\n");
		res = 2;
		err = 6;
		goto out_reject;
	}

	sess->peer_sid = assigned_sid->val.uint16;

	if (err)
		goto out_reject;

	if (l2tp_tunnel_confirm_session(sess) < 0) {
		res = 2;
		err = 4;
		goto out_reject;
	}
	if (l2tp_send_ICRP(sess))
		return -1;

	return 0;

out_reject:
	l2tp_send_CDN(sess, res, err);
	l2tp_tunnel_cancel_session(sess);
	return -1;
}

static int l2tp_recv_ICRP(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *assigned_sid = NULL;
	struct l2tp_attr_t *unknown_attr = NULL;
	struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_ICRP) {
		log_ppp_warn("l2tp: unexpected ICCN\n");
		return -1;
	}

	triton_timer_del(&sess->timeout_timer);

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_ppp_warn("l2tp: ICRP:"
					     " unknown attribute %i\n",
					     attr->attr->id);
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_ppp_error("l2tp: ICRP: missing mandatory AVP:"
			      " Assigned Session ID\n");
		l2tp_session_disconnect(sess, 2, 6);
		return -1;
	}

	/* Set peer_sid as soon as possible so that CDN
	   will be sent to the right tunnel in case of error */
	sess->peer_sid = assigned_sid->val.uint16;

	if (unknown_attr) {
		log_ppp_error("l2tp: ICRP: unknown mandatory attribute %i\n",
			      unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);
		return -1;
	}

	if (l2tp_send_ICCN(sess) < 0) {
		log_ppp_error("l2tp: ICRP: Error while sending ICCN\n");
		l2tp_session_disconnect(sess, 2, 6);
		return -1;
	}

	sess->state1 = STATE_ESTB;

	if (l2tp_session_connect(sess) < 0) {
		log_ppp_error("l2tp: ICRP: Error while connection session\n");
		l2tp_session_disconnect(sess, 2, 6);
		return -1;
	}

	return 0;
}

static int l2tp_recv_ICCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	if (sess->state1 != STATE_WAIT_ICCN) {
		log_ppp_warn("l2tp: unexpected ICCN\n");
		return 0;
	}

	sess->state1 = STATE_ESTB;

	if (l2tp_session_connect(sess)) {
		if (l2tp_session_disconnect(sess, 2, 4) < 0)
			return -1;
		return 0;
	}

	if (l2tp_send_ZLB(sess->paren_conn))
		return -1;

	triton_timer_del(&sess->timeout_timer);

	return 0;
}

static int l2tp_recv_OCRP(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *assigned_sid = NULL;
	struct l2tp_attr_t *unknown_attr = NULL;
	struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_OCRP) {
		log_ppp_warn("l2tp: unexpected OCRP\n");
		return -1;
	}

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
		case Message_Type:
			break;
		case Assigned_Session_ID:
			assigned_sid = attr;
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_ppp_warn("l2tp: OCRP:"
					     " unknown attribute %i\n",
					     attr->attr->id);
			break;
		}
	}

	if (assigned_sid == NULL) {
		log_ppp_error("l2tp: OCRP: missing mandatory AVP:"
			      " Assigned Session ID\n");
		l2tp_session_disconnect(sess, 2, 6);
		return -1;
	}

	/* Set peer_sid as soon as possible so that CDN
	   will be sent to the right tunnel in case of error */
	sess->peer_sid = assigned_sid->val.uint16;

	if (unknown_attr) {
		log_ppp_error("l2tp: OCRP: unknown mandatory attribute %i\n",
			      unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);
		return -1;
	}

	sess->state1 = STATE_WAIT_OCCN;

	return 0;
}

static int l2tp_recv_OCCN(struct l2tp_sess_t *sess,
			  const struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *unknown_attr = NULL;
	struct l2tp_attr_t *attr = NULL;

	if (sess->state1 != STATE_WAIT_OCCN) {
		log_ppp_warn("l2tp: unexpected OCCN\n");
		return 0;
	}

	triton_timer_del(&sess->timeout_timer);

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch (attr->attr->id) {
		case Message_Type:
		case TX_Speed:
		case Framing_Type:
			break;
		default:
			if (attr->M)
				unknown_attr = attr;
			else
				log_ppp_warn("l2tp: OCCN:"
					     " unknown attribute %i\n",
					     attr->attr->id);
			break;
		}
	}

	if (unknown_attr) {
		log_ppp_error("l2tp: OCCN: unknown mandatory attribute %i\n",
			      unknown_attr->attr->id);
		l2tp_session_disconnect(sess, 2, 8);
		return -1;
	}

	sess->state1 = STATE_ESTB;

	if (l2tp_session_connect(sess) < 0) {
		l2tp_session_disconnect(sess, 2, 4);
		return -1;
	}

	if (l2tp_send_ZLB(sess->paren_conn) < 0)
		return -1;

	return 0;
}

static int l2tp_recv_CDN(struct l2tp_sess_t *sess,
			 const struct l2tp_packet_t *pack)
{
	if (ntohs(pack->hdr.sid) != sess->sid) {
		if (conf_verbose)
			log_warn("l2tp: sid %i is incorrect\n", ntohs(pack->hdr.sid));
		return 0;
	}

	l2tp_send_ZLB(sess->paren_conn);
	l2tp_session_free(sess);

	return 0;
}

static int l2tp_recv_SLI(struct l2tp_conn_t *conn,
			 const struct l2tp_packet_t *pack)
{
	return 0;
}

static void l2tp_session_incall(void *data)
{
	struct l2tp_sess_t *sess = data;

	if (l2tp_send_ICRQ(sess) < 0) {
		log_ppp_error("l2tp: impossible to place call:"
			      " error while sending ICRQ\n");
		return;
	}
	sess->state1 = STATE_WAIT_ICRP;
}

static void l2tp_session_outcall(void *data)
{
	struct l2tp_sess_t *sess = data;

	if (l2tp_send_OCRQ(sess) < 0) {
		log_ppp_error("l2tp: impossible to place call:"
			      " error while sending OCRQ\n");
		return;
	}
	sess->state1 = STATE_WAIT_OCRP;
}

static void l2tp_tunnel_create_session(void *data)
{
	struct l2tp_conn_t *conn = data;
	struct l2tp_sess_t *sess = NULL;

	if (conn->state != STATE_ESTB) {
		log_ppp_error("l2tp: impossible to place call:"
			      " tunnel is not connected\n");
		return;
	}

	sess = l2tp_tunnel_alloc_session(conn);
	if (sess == NULL) {
		log_ppp_error("l2tp: impossible to place call:"
			      " no more session available\n");
		return;
	}
	if (l2tp_tunnel_confirm_session(sess) < 0) {
		log_ppp_error("l2tp: impossible to place call:"
			      " session initialisation failed\n");
		l2tp_tunnel_cancel_session(sess);
		return;
	}
	if (conn->lns_mode)
		triton_context_call(&sess->sctx, l2tp_session_outcall, sess);
	else
		triton_context_call(&sess->sctx, l2tp_session_incall, sess);
}

static void l2tp_session_recv(void *data)
{
	struct triton_context_t *ctx = triton_context_self();
	struct l2tp_sess_t *sess = container_of(ctx, typeof(*sess), sctx);
	struct l2tp_packet_t *pack = data;
	struct l2tp_attr_t *msg_type = NULL;

	msg_type = list_entry(pack->attrs.next, typeof(*msg_type), entry);

	switch (msg_type->val.uint16) {
	case Message_Type_Incoming_Call_Connected:
		l2tp_recv_ICCN(sess, pack);
		break;
	case Message_Type_Incoming_Call_Reply:
		l2tp_recv_ICRP(sess, pack);
		break;
	case Message_Type_Outgoing_Call_Reply:
		l2tp_recv_OCRP(sess, pack);
		break;
	case Message_Type_Outgoing_Call_Connected:
		l2tp_recv_OCCN(sess, pack);
		break;
	case Message_Type_Call_Disconnect_Notify:
		l2tp_recv_CDN(sess, pack);
		break;
	default:
		if (conf_verbose) {
			log_warn("l2tp: unexpected Message-Type %hu\n",
				 msg_type->val.uint16);
		}
		if (msg_type->M) {
			l2tp_session_disconnect(sess, 2, 8);
		}
		break;
	}

	l2tp_packet_free(pack);
}

static int l2tp_conn_read(struct triton_md_handler_t *h)
{
	struct l2tp_conn_t *conn = container_of(h, typeof(*conn), hnd);
	struct l2tp_sess_t *sess = NULL;
	struct l2tp_packet_t *pack, *p;
	struct l2tp_attr_t *msg_type;
	int res;

	while (1) {
		res = l2tp_recv(h->fd, &pack, NULL);
		if (res) {
			if (res == -2)
				/* No peer listening, tear down connection */
				l2tp_tunnel_free(conn);
			return 0;
		}

		if (!pack)
			continue;

		if (conn->peer_addr.sin_port == 0) {
			/* Get peer's first reply source port and use it as
			   destination port for further outgoing messages */
			res = l2tp_tunnel_update_peerport(conn,
							  pack->addr.sin_port);
			if (res < 0)
				goto drop;
		}

		if (ntohs(pack->hdr.tid) != conn->tid && (pack->hdr.tid || !conf_dir300_quirk)) {
			if (conf_verbose) {
				l2tp_conn_log(log_warn, conn);
				log_warn("incorrect tid %i in tunnel %i\n", ntohs(pack->hdr.tid), conn->tid);
			}
			l2tp_packet_free(pack);
			continue;
		}

		res = nsnr_cmp(ntohs(pack->hdr.Ns), conn->Nr);
		if (res < 0) {
			/* Duplicate message */
			l2tp_conn_log(log_debug, conn);
			log_debug("Duplicate message (packet Ns/Nr: %hu/%hu,"
				  " tunnel Ns/Nr: %hu/%hu)\n",
				  ntohs(pack->hdr.Ns), ntohs(pack->hdr.Nr),
				  conn->Ns, conn->Nr);
			if (!list_empty(&conn->send_queue))
				l2tp_retransmit(conn);
			else if (l2tp_send_ZLB(conn))
				goto drop;
			l2tp_packet_free(pack);
			continue;
		} else if (res > 0) {
			/* Out of order message */
			l2tp_conn_log(log_debug, conn);
			log_debug("Reordered message (packet Ns/Nr: %hu/%hu,"
				  " tunnel Ns/Nr: %hu/%hu)\n",
				  ntohs(pack->hdr.Ns), ntohs(pack->hdr.Nr),
				  conn->Ns, conn->Nr);
			l2tp_packet_free(pack);
			continue;
		} else {
			if (!list_empty(&pack->attrs))
				conn->Nr++;
			if (!list_empty(&conn->send_queue)) {
				p = list_entry(conn->send_queue.next, typeof(*pack), entry);
				list_del(&p->entry);
				l2tp_packet_free(p);
				conn->retransmit = 0;
			}
			if (!list_empty(&conn->send_queue))
				triton_timer_mod(&conn->rtimeout_timer, 0);
			else {
				if (conn->rtimeout_timer.tpd)
					triton_timer_del(&conn->rtimeout_timer);
				if (conn->state == STATE_FIN)
					goto drop;
			}
		}

		if (list_empty(&pack->attrs)) {
			l2tp_packet_free(pack);
			continue;
		}

		msg_type = list_entry(pack->attrs.next, typeof(*msg_type), entry);

		if (msg_type->attr->id != Message_Type) {
			if (conf_verbose) {
				l2tp_conn_log(log_error, conn);
				log_error("first attribute is not Message-Type, dropping connection...\n");
			}
			goto drop;
		}

		if (conf_verbose) {
			if (msg_type->val.uint16 == Message_Type_Hello) {
				l2tp_conn_log(log_debug, conn);
				log_debug("recv ");
				l2tp_packet_print(pack, log_debug);
			} else {
				l2tp_conn_log(log_info2, conn);
				log_info2("recv ");
				l2tp_packet_print(pack, log_info2);
			}
		}

		switch (msg_type->val.uint16) {
			case Message_Type_Start_Ctrl_Conn_Reply:
				if (l2tp_recv_SCCRP(conn, pack))
					goto drop;
				break;
			case Message_Type_Start_Ctrl_Conn_Connected:
				if (l2tp_recv_SCCCN(conn, pack))
					goto drop;
				break;
			case Message_Type_Stop_Ctrl_Conn_Notify:
				if (l2tp_recv_StopCCN(conn, pack))
					goto drop;
				break;
			case Message_Type_Hello:
				if (l2tp_recv_HELLO(conn, pack))
					goto drop;
				break;
			case Message_Type_Incoming_Call_Request:
				if (l2tp_recv_ICRQ(conn, pack))
					goto drop;
				break;
			case Message_Type_Incoming_Call_Connected:
			case Message_Type_Incoming_Call_Reply:
			case Message_Type_Outgoing_Call_Reply:
			case Message_Type_Outgoing_Call_Connected:
			case Message_Type_Call_Disconnect_Notify:
				sess = l2tp_tunnel_get_session(conn, ntohs(pack->hdr.sid));
				if (sess == NULL)
					goto drop;
				triton_context_call(&sess->sctx, l2tp_session_recv, pack);
				continue;
			case Message_Type_Set_Link_Info:
				if (l2tp_recv_SLI(conn, pack))
					goto drop;
				break;
			case Message_Type_Start_Ctrl_Conn_Request:
			case Message_Type_Outgoing_Call_Request:
			case Message_Type_WAN_Error_Notify:
				if (conf_verbose)
					log_warn("l2tp: unexpected Message-Type %i\n", msg_type->val.uint16);
				break;
			default:
				if (conf_verbose)
					log_warn("l2tp: unknown Message-Type %i\n", msg_type->val.uint16);
				if (msg_type->M) {
					if (l2tp_tunnel_disconnect(conn, 2, 8))
						goto drop;
				}
		}

		l2tp_packet_free(pack);
	}

drop:
	l2tp_packet_free(pack);
	l2tp_tunnel_free(conn);
	return -1;
}

static int l2tp_udp_read(struct triton_md_handler_t *h)
{
	struct l2tp_serv_t *serv = container_of(h, typeof(*serv), hnd);
	struct l2tp_packet_t *pack;
	struct l2tp_attr_t *msg_type;
	struct in_pktinfo pkt_info;

	while (1) {
		if (l2tp_recv(h->fd, &pack, &pkt_info))
			break;

		if (!pack)
			continue;

		if (iprange_client_check(pack->addr.sin_addr.s_addr)) {
			log_warn("l2tp: IP is out of client-ip-range, droping connection...\n");
			goto skip;
		}

		if (pack->hdr.tid)
			goto skip;

		if (list_empty(&pack->attrs)) {
			if (conf_verbose)
				log_warn("l2tp: to Message-Type attribute present\n");
			goto skip;
		}

		msg_type = list_entry(pack->attrs.next, typeof(*msg_type), entry);
		if (msg_type->attr->id != Message_Type) {
			if (conf_verbose)
				log_warn("l2tp: first attribute is not Message-Type\n");
			goto skip;
		}

		if (msg_type->val.uint16 == Message_Type_Start_Ctrl_Conn_Request)
			l2tp_recv_SCCRQ(serv, pack, &pkt_info);
		else {
			if (conf_verbose) {
				log_warn("recv (unexpected) ");
				l2tp_packet_print(pack, log_ppp_warn);
			}
		}
skip:
		l2tp_packet_free(pack);
	}

	return 0;
}

static void l2tp_udp_close(struct triton_context_t *ctx)
{
	struct l2tp_serv_t *serv = container_of(ctx, typeof(*serv), ctx);
	triton_md_unregister_handler(&serv->hnd);
	close(serv->hnd.fd);
	triton_context_unregister(&serv->ctx);
}

static struct l2tp_serv_t udp_serv =
{
	.hnd.read = l2tp_udp_read,
	.ctx.close = l2tp_udp_close,
	.ctx.before_switch = log_switch,
};

/*static struct l2tp_serv_t ip_serv =
{
	.hnd.read=l2t_ip_read,
	.ctx.close=l2tp_ip_close,
};*/

static void start_udp_server(void)
{
	struct sockaddr_in addr;
	const char *opt;
	int flag = 1;

	udp_serv.hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (udp_serv.hnd.fd < 0) {
		log_emerg("l2tp: socket: %s\n", strerror(errno));
		return;
	}
	
	fcntl(udp_serv.hnd.fd, F_SETFD, fcntl(udp_serv.hnd.fd, F_GETFD) | FD_CLOEXEC);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(L2TP_PORT);

	opt = conf_get_opt("l2tp", "bind");
	if (opt)
		addr.sin_addr.s_addr = inet_addr(opt);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(udp_serv.hnd.fd, SOL_SOCKET, SO_REUSEADDR, &udp_serv.hnd.fd, sizeof(udp_serv.hnd.fd));
	setsockopt(udp_serv.hnd.fd, SOL_SOCKET, SO_NO_CHECK, &udp_serv.hnd.fd, sizeof(udp_serv.hnd.fd));

	if (bind (udp_serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
		log_emerg("l2tp: bind: %s\n", strerror(errno));
		close(udp_serv.hnd.fd);
		return;
	}

	if (fcntl(udp_serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
		log_emerg("l2tp: failed to set nonblocking mode: %s\n", strerror(errno));
		close(udp_serv.hnd.fd);
		return;
	}

	if (setsockopt(udp_serv.hnd.fd, IPPROTO_IP, IP_PKTINFO, &flag, sizeof(flag))) {
		log_emerg("l2tp: setsockopt(IP_PKTINFO): %s\n", strerror(errno));
		close(udp_serv.hnd.fd);
		return;
	}

	memcpy(&udp_serv.addr, &addr, sizeof(addr));

	triton_context_register(&udp_serv.ctx, NULL);
	triton_md_register_handler(&udp_serv.ctx, &udp_serv.hnd);
	triton_md_enable_handler(&udp_serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&udp_serv.ctx);
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "l2tp:\r\n");
	cli_sendv(client, "  starting: %u\r\n", stat_starting);
	cli_sendv(client, "  active: %u\r\n", stat_active);

	return CLI_CMD_OK;
}

static int l2tp_create_tunnel_exec(const char *cmd, char * const *fields,
				   int fields_cnt, void *client)
{
	struct l2tp_conn_t *conn = NULL;
	struct sockaddr_in peer = {
		.sin_family = AF_UNSPEC
	};
	struct sockaddr_in host = {
		.sin_family = AF_UNSPEC
	};
	const char *opt = NULL;
	int lns_mode = 0;
	int indx;

	opt = conf_get_opt("l2tp", "bind");
	if (opt)
		if (inet_aton(opt, &host.sin_addr) == 0) {
			host.sin_family = AF_INET;
			host.sin_port = 0;
		}

	for (indx = 3; indx + 1 < fields_cnt; ++indx) {
		if (strcmp("mode", fields[indx]) == 0) {
			++indx;
			if (strcmp("lns", fields[indx]) == 0)
				lns_mode = 1;
			else if (strcmp("lac", fields[indx]) == 0)
				lns_mode = 0;
			else
				return CLI_CMD_INVAL;
		} else if (strcmp("peer-addr", fields[indx]) == 0) {
			++indx;
			peer.sin_family = AF_INET;
			peer.sin_port = htons(L2TP_PORT);
			if (inet_aton(fields[indx], &peer.sin_addr) == 0)
				return CLI_CMD_INVAL;
		} else if (strcmp("host-addr", fields[indx]) == 0) {
			++indx;
			host.sin_family = AF_INET;
			host.sin_port = 0;
			if (inet_aton(fields[indx], &host.sin_addr) == 0)
				return CLI_CMD_INVAL;
		} else
			return CLI_CMD_SYNTAX;
	}

	if (indx != fields_cnt)
		/* Missing argument for option */
		return CLI_CMD_SYNTAX;

	if (peer.sin_family == AF_UNSPEC)
		return CLI_CMD_SYNTAX;

	if (iprange_client_check(peer.sin_addr.s_addr) < 0) {
		char addr[17];
		u_inet_ntoa(peer.sin_addr.s_addr, addr);
		cli_sendv(client, "Peer address %s out of IP range\r\n", addr);
		return CLI_CMD_INVAL;
	}

	conn = l2tp_tunnel_alloc(&peer, &host, 3, lns_mode);
	if (conn == NULL)
		return CLI_CMD_FAILED;

	l2tp_tunnel_start(conn, l2tp_send_SCCRQ, &peer);

	return CLI_CMD_OK;
}

static int l2tp_create_session_exec(const char *cmd, char * const *fields,
				    int fields_cnt, void *client)
{
	struct l2tp_conn_t *conn = NULL;
	long int tid;
	int res;

	if (fields_cnt != 5)
		return CLI_CMD_SYNTAX;

	if (strcmp("tid", fields[3]) != 0)
		return CLI_CMD_SYNTAX;

	if (u_readlong(&tid, fields[4], 1, L2TP_MAX_TID - 1) < 0)
		return CLI_CMD_INVAL;

	pthread_mutex_lock(&l2tp_lock);
	conn = l2tp_conn[tid];
	if (conn) {
		triton_context_call(&conn->ctx,
				    l2tp_tunnel_create_session, conn);
		res = CLI_CMD_OK;
	} else
		res = CLI_CMD_INVAL;
	pthread_mutex_unlock(&l2tp_lock);

	return res;
}

static void l2tp_create_tunnel_help(char * const *fields, int fields_cnt,
				    void *client)
{
	cli_send(client,
		 "l2tp create tunnel peer-addr <ip_addr> [host-addr <ip_addr>]"
		 " [mode <lac|lns>]"
		 " - initiate new tunnel to peer\r\n");
}

static void l2tp_create_session_help(char * const *fields, int fields_cnt,
				     void *client)
{
	cli_send(client,
		 "l2tp create session tid <tid>"
		 " - place new call in tunnel <tid>\r\n");
}

void __export l2tp_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("l2tp", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_verbose = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "avp_permissive");
	if (opt && atoi(opt) >= 0)
		conf_avp_permissive = atoi(opt) > 0;

	opt = conf_get_opt("l2tp", "hello-interval");
	if (opt && atoi(opt) > 0)
		conf_hello_interval = atoi(opt);

	opt = conf_get_opt("l2tp", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("l2tp", "rtimeout");
	if (opt && atoi(opt) > 0)
		conf_rtimeout = atoi(opt);

	opt = conf_get_opt("l2tp", "retransmit");
	if (opt && atoi(opt) > 0)
		conf_retransmit = atoi(opt);

	opt = conf_get_opt("l2tp", "host-name");
	if (opt)
		conf_host_name = opt;
	else
		conf_host_name = "accel-ppp";

	opt = conf_get_opt("l2tp", "secret");
	if (opt)
		conf_secret = opt;

	opt = conf_get_opt("l2tp", "dir300_quirk");
	if (opt)
		conf_dir300_quirk = atoi(opt);
	
	conf_mppe = MPPE_UNSET;
	opt = conf_get_opt("l2tp", "mppe");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_mppe = MPPE_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_mppe = MPPE_ALLOW;
		else if (strcmp(opt, "prefer") == 0)
			conf_mppe = MPPE_PREFER;
		else if (strcmp(opt, "require") == 0)
			conf_mppe = MPPE_REQUIRE;
	}
}

static void l2tp_init(void)
{
	if (system("modprobe -q pppol2tp || modprobe -q l2tp_ppp"))
		log_warn("unable to load l2tp kernel module\n");
	
	l2tp_conn = malloc(L2TP_MAX_TID * sizeof(void *));
	memset(l2tp_conn, 0, L2TP_MAX_TID * sizeof(void *));

	l2tp_conn_pool = mempool_create(sizeof(struct l2tp_conn_t));
	l2tp_sess_pool = mempool_create(sizeof(struct l2tp_sess_t));

	load_config();

	start_udp_server();

	cli_register_simple_cmd2(&show_stat_exec, NULL, 2, "show", "stat");
	cli_register_simple_cmd2(l2tp_create_tunnel_exec,
				 l2tp_create_tunnel_help, 3,
				 "l2tp", "create", "tunnel");
	cli_register_simple_cmd2(l2tp_create_session_exec,
				 l2tp_create_session_help, 3,
				 "l2tp", "create", "session");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(22, l2tp_init);
