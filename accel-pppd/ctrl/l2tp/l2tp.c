#include <unistd.h>
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

#define STATE_WAIT_SCCCN 1
#define STATE_WAIT_ICRQ  2
#define STATE_WAIT_ICCN  3
#define STATE_WAIT_OCRP  4
#define STATE_WAIT_OCCN  5
#define STATE_ESTB       6
#define STATE_PPP        7
#define STATE_FIN        8
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
	int state2;

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

	struct sockaddr_in lac_addr;
	struct sockaddr_in lns_addr;
	uint16_t tid;
	uint16_t peer_tid;
	uint32_t framing_cap;
	uint16_t challenge_len;
	l2tp_value_t challenge;

	int retransmit;
	uint16_t Ns, Nr;
	struct list_head send_queue;

	int state;
	struct l2tp_sess_t sess;
};

static pthread_mutex_t l2tp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct l2tp_conn_t **l2tp_conn;
static uint16_t l2tp_tid;

static mempool_t l2tp_conn_pool;

static void l2tp_timeout(struct triton_timer_t *t);
static void l2tp_rtimeout(struct triton_timer_t *t);
static void l2tp_send_HELLO(struct triton_timer_t *t);
static void l2tp_send_SCCRP(struct l2tp_conn_t *conn);
static int l2tp_send(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack, int log_debug);
static int l2tp_conn_read(struct triton_md_handler_t *);

static void l2tp_session_free(struct l2tp_conn_t *conn)
{
	switch (conn->sess.state1) {
	case STATE_PPP:
		__sync_sub_and_fetch(&stat_active, 1);
		ap_session_terminate(&conn->sess.ppp.ses,
				     TERM_USER_REQUEST, 1);
		break;
	case STATE_WAIT_ICCN:
	case STATE_ESTB:
		__sync_sub_and_fetch(&stat_starting, 1);
		break;
	default:
		return;
	}

	if (conn->sess.ppp.fd != -1)
		close(conn->sess.ppp.fd);

	triton_event_fire(EV_CTRL_FINISHED, &conn->sess.ppp.ses);

	log_ppp_info1("disconnected\n");

	if (conn->sess.ppp.ses.chan_name)
		_free(conn->sess.ppp.ses.chan_name);
	_free(conn->sess.ctrl.calling_station_id);
	_free(conn->sess.ctrl.called_station_id);

	conn->sess.state1 = STATE_CLOSE;
}

static void l2tp_tunnel_free(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	if (conn->state == STATE_CLOSE)
		return;

	l2tp_session_free(conn);

	triton_md_unregister_handler(&conn->hnd);
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

	triton_context_unregister(&conn->ctx);

	while (!list_empty(&conn->send_queue)) {
		pack = list_entry(conn->send_queue.next, typeof(*pack), entry);
		list_del(&pack->entry);
		l2tp_packet_free(pack);
	}

	if (conn->challenge_len)
	    _free(conn->challenge.octets);

	conn->state = STATE_CLOSE;

	mempool_free(conn);
}

static int l2tp_terminate(struct l2tp_conn_t *conn, int res, int err)
{
	struct l2tp_packet_t *pack;
	struct l2tp_avp_result_code rc = {res, err};

	log_ppp_debug("l2tp: terminate (%i, %i)\n", res, err);

	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify,
				 &conn->lac_addr);
	if (!pack)
		return -1;
	
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, conn->tid, 1))
		goto out_err;
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc, sizeof(rc), 0))
		goto out_err;

	l2tp_send(conn, pack, 0);

	conn->state = STATE_FIN;

	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

static void l2tp_ppp_started(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct l2tp_sess_t *sess = container_of(ppp, typeof(*sess), ppp);
	struct l2tp_conn_t *conn = sess->paren_conn;

	log_ppp_debug("l2tp: ppp started\n");
	
	if (conf_hello_interval)
		triton_timer_add(&conn->ctx, &conn->hello_timer, 0);
}

static void l2tp_ppp_finished(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct l2tp_sess_t *sess = container_of(ppp, typeof(*sess), ppp);
	struct l2tp_conn_t *conn = sess->paren_conn;

	log_ppp_debug("l2tp: ppp finished\n");

	if (conn->sess.state1 == STATE_PPP) {
		__sync_sub_and_fetch(&stat_active, 1);
		if (l2tp_terminate(conn, 0, 0))
			triton_context_call(&conn->ctx, (triton_event_func)l2tp_tunnel_free, conn);
	}
}

static int l2tp_session_alloc(struct l2tp_conn_t *conn)
{
	conn->sess.paren_conn = conn;
	conn->sess.sid = 1;
	conn->sess.peer_sid = 0;
	conn->sess.state1 = STATE_CLOSE;
	conn->sess.state2 = STATE_CLOSE;

	conn->sess.ctrl.ctx = &conn->ctx;
	conn->sess.ctrl.type = CTRL_TYPE_L2TP;
	conn->sess.ctrl.ppp = 1;
	conn->sess.ctrl.name = "l2tp";
	conn->sess.ctrl.started = l2tp_ppp_started;
	conn->sess.ctrl.finished = l2tp_ppp_finished;
	conn->sess.ctrl.terminate = ppp_terminate;
	conn->sess.ctrl.max_mtu = 1420;
	conn->sess.ctrl.mppe = conf_mppe;
	conn->sess.ctrl.calling_station_id = _malloc(17);
	conn->sess.ctrl.called_station_id = _malloc(17);
	u_inet_ntoa(conn->lac_addr.sin_addr.s_addr,
		    conn->sess.ctrl.calling_station_id);
	u_inet_ntoa(conn->lns_addr.sin_addr.s_addr,
		    conn->sess.ctrl.called_station_id);

	ppp_init(&conn->sess.ppp);
	conn->sess.ppp.ses.ctrl = &conn->sess.ctrl;
	conn->sess.ppp.fd = -1;

	__sync_add_and_fetch(&stat_starting, 1);

	return 0;
}

static void l2tp_conn_close(struct triton_context_t *ctx)
{
	struct l2tp_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	if (conn->sess.state1 == STATE_PPP) {
		__sync_sub_and_fetch(&stat_active, 1);
		ap_session_terminate(&conn->sess.ppp.ses, TERM_ADMIN_RESET, 1);
	}
	
	if (l2tp_terminate(conn, 0, 0))
		l2tp_tunnel_free(conn);
}

static int l2tp_tunnel_alloc(struct l2tp_serv_t *serv, struct l2tp_packet_t *pack, struct in_pktinfo *pkt_info, struct l2tp_attr_t *assigned_tid, 
    struct l2tp_attr_t *framing_cap, struct l2tp_attr_t *challenge)
{
	struct l2tp_conn_t *conn;
	struct sockaddr_in addr;
	uint16_t tid;
	//char *opt;
	int flag = 1;

	conn = mempool_alloc(l2tp_conn_pool);
	if (!conn) {
		log_emerg("l2tp: out of memory\n");
		return -1;
	}

	memset(conn, 0, sizeof(*conn));
	INIT_LIST_HEAD(&conn->send_queue);

	conn->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (conn->hnd.fd < 0) {
		log_error("l2tp: socket: %s\n", strerror(errno));
		mempool_free(conn);
		return -1;
	}
	
	fcntl(conn->hnd.fd, F_SETFD, fcntl(conn->hnd.fd, F_GETFD) | FD_CLOEXEC);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = pkt_info->ipi_addr;
	addr.sin_port = htons(L2TP_PORT);

  setsockopt(conn->hnd.fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	if (bind(conn->hnd.fd, &addr, sizeof(addr))) {
		log_error("l2tp: bind: %s\n", strerror(errno));
		goto out_err;
	}
	
	if (connect(conn->hnd.fd, (struct sockaddr *)&pack->addr, sizeof(addr))) {
		log_error("l2tp: connect: %s\n", strerror(errno));
		goto out_err;
	}
 
	if (fcntl(conn->hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("l2tp: failed to set nonblocking mode: %s\n", strerror(errno));
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
		mempool_free(conn);
		return -1;
	}

	memcpy(&conn->lac_addr, &pack->addr, sizeof(pack->addr));
	memcpy(&conn->lns_addr, &addr, sizeof(addr));
	conn->peer_tid = assigned_tid->val.uint16;
	conn->framing_cap = framing_cap->val.uint32;

	/* If challenge set in SCCRQ, we need to calculate response for SCCRP */
	if (challenge && challenge->length <= 16) {
		char state = 2; /* SCCRP, TODO: define them in some .h? */
		MD5_CTX md5_ctx;
		uint8_t md5[MD5_DIGEST_LENGTH];

		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx, &state, 1);
		MD5_Update(&md5_ctx, conf_secret, strlen(conf_secret));
		MD5_Update(&md5_ctx, challenge->val.octets, challenge->length);
		MD5_Final(md5, &md5_ctx);

		conn->challenge_len = MD5_DIGEST_LENGTH;
		conn->challenge.octets = _malloc(MD5_DIGEST_LENGTH);
		memcpy(conn->challenge.octets, &md5, MD5_DIGEST_LENGTH);
	}

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

	triton_context_register(&conn->ctx, NULL);
	triton_md_register_handler(&conn->ctx, &conn->hnd);
	triton_md_enable_handler(&conn->hnd, MD_MODE_READ);
	triton_context_wakeup(&conn->ctx);

	if (conf_verbose) {
		log_switch(&conn->ctx, NULL);
		log_ppp_info2("recv ");
		l2tp_packet_print(pack, log_ppp_info2);
	}

	l2tp_session_alloc(conn);
	triton_context_call(&conn->ctx, (triton_event_func)l2tp_send_SCCRP, conn);

	return 0;

out_err:
	close(conn->hnd.fd);
	mempool_free(conn);
	return -1;
}

static int l2tp_session_connect(struct l2tp_conn_t *conn)
{
	struct sockaddr_pppol2tp pppox_addr;
	int arg = 1;
	int flg;

	conn->sess.ppp.fd = socket(AF_PPPOX, SOCK_DGRAM, PX_PROTO_OL2TP);
	if (conn->sess.ppp.fd < 0) {
		log_ppp_error("l2tp: socket(AF_PPPOX): %s\n", strerror(errno));
		goto out_err;
	}

	flg = fcntl(conn->sess.ppp.fd, F_GETFD);
	if (flg < 0) {
		log_ppp_error("l2tp: fcntl(F_GETFD): %s\n", strerror(errno));
		goto out_err;
	}
	flg = fcntl(conn->sess.ppp.fd, F_SETFD, flg | FD_CLOEXEC);
	if (flg < 0) {
		log_ppp_error("l2tp: fcntl(F_SETFD): %s\n", strerror(errno));
		goto out_err;
	}

	memset(&pppox_addr, 0, sizeof(pppox_addr));
	pppox_addr.sa_family = AF_PPPOX;
	pppox_addr.sa_protocol = PX_PROTO_OL2TP;
	pppox_addr.pppol2tp.fd = conn->hnd.fd;
	memcpy(&pppox_addr.pppol2tp.addr, &conn->lac_addr, sizeof(conn->lac_addr));
	pppox_addr.pppol2tp.s_tunnel = conn->tid;
	pppox_addr.pppol2tp.d_tunnel = conn->peer_tid;
	pppox_addr.pppol2tp.s_session = conn->sess.sid;
	pppox_addr.pppol2tp.d_session = conn->sess.peer_sid;

	if (connect(conn->sess.ppp.fd, (struct sockaddr *)&pppox_addr, sizeof(pppox_addr)) < 0) {
		log_ppp_error("l2tp: connect(session): %s\n", strerror(errno));
		goto out_err;
	}

	if (setsockopt(conn->sess.ppp.fd, SOL_PPPOL2TP, PPPOL2TP_SO_LNSMODE, &arg, sizeof(arg))) {
		log_ppp_error("l2tp: setsockopt: %s\n", strerror(errno));
		goto out_err;
	}

	conn->sess.ppp.ses.chan_name = _strdup(inet_ntoa(conn->lac_addr.sin_addr));

	triton_event_fire(EV_CTRL_STARTED, &conn->sess.ppp.ses);

	if (establish_ppp(&conn->sess.ppp))
		goto out_err;

	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);

	conn->sess.state1 = STATE_PPP;

	return 0;

out_err:
	if (conn->sess.ppp.fd >= 0) {
		close(conn->sess.ppp.fd);
		conn->sess.ppp.fd = -1;
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
	memcpy(&pppox_addr.pppol2tp.addr, &conn->lac_addr, sizeof(conn->lac_addr));
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

	return 0;

out_err:
	if (conn->tunnel_fd >= 0) {
		close(conn->tunnel_fd);
		conn->tunnel_fd = -1;
	}
	return -1;
}

static void l2tp_rtimeout(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn), rtimeout_timer);
	struct l2tp_packet_t *pack;

	if (!list_empty(&conn->send_queue)) {
		log_ppp_debug("l2tp: retransmit (%i)\n", conn->retransmit);
		if (++conn->retransmit <= conf_retransmit) {
			pack = list_entry(conn->send_queue.next, typeof(*pack), entry);
			pack->hdr.Nr = htons(conn->Nr + 1);
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

static int l2tp_send(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack, int log_debug)
{
	conn->retransmit = 0;

	pack->hdr.tid = htons(conn->peer_tid);
	//pack->hdr.sid = htons(conn->peer_sid);
	pack->hdr.Nr = htons(conn->Nr + 1);
	pack->hdr.Ns = htons(conn->Ns);

	if (!list_empty(&pack->attrs))
		conn->Ns++;

	if (conf_verbose) {
		if (log_debug) {
			log_ppp_debug("send ");
			l2tp_packet_print(pack, log_ppp_debug);
		} else {
			log_ppp_info2("send ");
			l2tp_packet_print(pack, log_ppp_info2);
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

static int l2tp_send_ZLB(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, 0, &conn->lac_addr);
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

	pack = l2tp_packet_alloc(2, Message_Type_Hello, &conn->lac_addr);
	if (!pack) {
		l2tp_tunnel_free(conn);
		return;
	}

	if (l2tp_send(conn, pack, 1))
		l2tp_tunnel_free(conn);
}

static void l2tp_send_SCCRP(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Reply, &conn->lac_addr);
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
	/* If challenge response available */
	if (conn->challenge_len) {
	    if (l2tp_packet_add_octets(pack, Challenge_Response, conn->challenge.octets, 16, 1))
		goto out_err;
	}

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

static int l2tp_send_ICRP(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Incoming_Call_Reply, &conn->lac_addr);
	if (!pack)
		return -1;

	pack->hdr.sid = htons(conn->sess.peer_sid);
	
	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, conn->sess.sid, 1))
		goto out_err;

	l2tp_send(conn, pack, 0);

	if (!conn->timeout_timer.tpd)
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
	else
		triton_timer_mod(&conn->timeout_timer, 0);
	
	conn->sess.state1 = STATE_WAIT_ICCN;
	
	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}

/*static int l2tp_send_OCRQ(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Request, &conn->lac_addr);
	if (!pack)
		return -1;
	
	pack->hdr.sid = htons(conn->peer_sid);

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, conn->sess.sid, 1))
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

	if (l2tp_send(conn, pack, 0))
		return -1;

	if (!conn->timeout_timer.tpd)
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);
	else
		triton_timer_mod(&conn->timeout_timer, 0);
	
	conn->state2 = STATE_WAIT_OCRP;
	
	return 0;

out_err:
	l2tp_packet_free(pack);
	return -1;
}*/


static int l2tp_recv_SCCRQ(struct l2tp_serv_t *serv, struct l2tp_packet_t *pack, struct in_pktinfo *pkt_info)
{
	struct l2tp_attr_t *attr;
	struct l2tp_attr_t *protocol_version = NULL;
	struct l2tp_attr_t *assigned_tid = NULL;
	struct l2tp_attr_t *assigned_cid = NULL;
	struct l2tp_attr_t *framing_cap = NULL;
	struct l2tp_attr_t *router_id = NULL;
	struct l2tp_attr_t *challenge = NULL;
	
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
		
		if (l2tp_tunnel_alloc(serv, pack, pkt_info, assigned_tid, framing_cap, challenge))
			return -1;

	} else if (assigned_cid) {
		// not yet implemented
		return 0;
	} else {
		if (conf_verbose)
			log_warn("l2tp: SCCRQ: no Assigned-Tunnel-ID or Assigned-Connection-ID present in message\n");
		return -1;
	}

	if (conf_secret && !challenge) {
		if (conf_verbose)
			log_warn("l2tp: SCCRQ: no Challenge present in message\n");
		return -1;
	}

	return 0;
}

static int l2tp_recv_SCCCN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	if (conn->state == STATE_WAIT_SCCCN) {
		triton_timer_mod(&conn->timeout_timer, 0);
		if (l2tp_tunnel_connect(conn) < 0) {
			l2tp_terminate(conn, 2, 0);
			return -1;
		}
		conn->state = STATE_ESTB;
	}
	else
		log_ppp_warn("l2tp: unexpected SCCCN\n");
	
	return 0;
}

static int l2tp_recv_StopCCN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	l2tp_send_ZLB(conn);
	return -1;
}

static int l2tp_recv_HELLO(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	if (l2tp_send_ZLB(conn))
		return -1;
	
	return 0;
}

static int l2tp_recv_ICRQ(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr;
	struct l2tp_attr_t *assigned_sid = NULL;

	if (conn->state != STATE_ESTB) {
		log_ppp_warn("l2tp: unexpected ICRQ\n");
		return 0;
	}

	if (conn->sess.state1 != STATE_CLOSE) {
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
						if (l2tp_terminate(conn, 2, 8))
							return -1;
						return 0;
					}
				}
		}
	}

	if (!assigned_sid) {
		if (conf_verbose)
			log_ppp_warn("l2tp: ICRQ: no Assigned-Session-ID attribute present in message\n");
		if (l2tp_terminate(conn, 2, 0))
			return -1;
	}

	conn->sess.peer_sid = assigned_sid->val.uint16;

	if (l2tp_send_ICRP(conn))
		return -1;
		
	/*if (l2tp_send_OCRQ(conn))
		return -1;*/
	
	return 0;
}

static int l2tp_recv_ICCN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	if (conn->sess.state1 != STATE_WAIT_ICCN) {
		log_ppp_warn("l2tp: unexpected ICCN\n");
		return 0;
	}

	conn->sess.state1 = STATE_ESTB;

	if (l2tp_session_connect(conn)) {
		if (l2tp_terminate(conn, 2, 0))
			return -1;
		return 0;
	}

	if (l2tp_send_ZLB(conn))
		return -1;
	
	triton_timer_del(&conn->timeout_timer);

	return 0;
}

static int  l2tp_recv_OCRP(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	if (conn->sess.state2 != STATE_WAIT_OCRP) {
		log_ppp_warn("l2tp: unexpected OCRP\n");
		return 0;
	}

	conn->sess.state2 = STATE_WAIT_OCCN;

	return 0;
}

static int l2tp_recv_OCCN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	if (conn->sess.state2 != STATE_WAIT_OCCN) {
		log_ppp_warn("l2tp: unexpected OCCN\n");
		return 0;
	}

	conn->sess.state2 = STATE_ESTB;

	return 0;
}

static int l2tp_recv_CDN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	if (ntohs(pack->hdr.sid) != conn->sess.sid) {
		if (conf_verbose)
			log_warn("l2tp: sid %i is incorrect\n", ntohs(pack->hdr.sid));
		return 0;
	}

	l2tp_session_free(conn);
	if (l2tp_terminate(conn, 0, 0))
		return -1;
	
	return 0;
}

static int l2tp_recv_SLI(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	return 0;
}

static int l2tp_conn_read(struct triton_md_handler_t *h)
{
	struct l2tp_conn_t *conn = container_of(h, typeof(*conn), hnd);
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

		if (ntohs(pack->hdr.tid) != conn->tid && (pack->hdr.tid || !conf_dir300_quirk)) {
			if (conf_verbose)
				log_warn("l2tp: incorrect tid %i in tunnel %i\n", ntohs(pack->hdr.tid), conn->tid);
			l2tp_packet_free(pack);
			continue;
		}

		if (ntohs(pack->hdr.Ns) == conn->Nr + 1) {
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
		} else {
			if (ntohs(pack->hdr.Ns) < conn->Nr + 1 || (ntohs(pack->hdr.Ns > 32767 && conn->Nr + 1 < 32767))) {
				log_ppp_debug("duplicate packet\n");
				if (l2tp_send_ZLB(conn))
					goto drop;
			} else
				log_ppp_debug("reordered packet\n");
			l2tp_packet_free(pack);
			continue;
		}

		if (list_empty(&pack->attrs)) {
			l2tp_packet_free(pack);
			continue;
		}

		msg_type = list_entry(pack->attrs.next, typeof(*msg_type), entry);

		if (msg_type->attr->id != Message_Type) {
			if (conf_verbose)
				log_ppp_error("l2tp: first attribute is not Message-Type, dropping connection...\n");
			goto drop;
		}

		if (conf_verbose) {
			if (msg_type->val.uint16 == Message_Type_Hello) {
				log_ppp_debug("recv ");
				l2tp_packet_print(pack, log_ppp_debug);
			} else {
				log_ppp_info2("recv ");
				l2tp_packet_print(pack, log_ppp_info2);
			}
		}

		switch (msg_type->val.uint16) {
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
				if (l2tp_recv_ICCN(conn, pack))
					goto drop;
				break;
			case Message_Type_Outgoing_Call_Reply:
				if (l2tp_recv_OCRP(conn, pack))
					goto drop;
				break;
			case Message_Type_Outgoing_Call_Connected:
				if (l2tp_recv_OCCN(conn, pack))
					goto drop;
				break;
			case Message_Type_Call_Disconnect_Notify:
				if (l2tp_recv_CDN(conn, pack))
					goto drop;
				break;
			case Message_Type_Set_Link_Info:
				if (l2tp_recv_SLI(conn, pack))
					goto drop;
				break;
			case Message_Type_Start_Ctrl_Conn_Request:
			case Message_Type_Start_Ctrl_Conn_Reply:
			case Message_Type_Outgoing_Call_Request:
			case Message_Type_Incoming_Call_Reply:
			case Message_Type_WAN_Error_Notify:
				if (conf_verbose)
					log_warn("l2tp: unexpected Message-Type %i\n", msg_type->val.uint16);
				break;
			default:
				if (conf_verbose)
					log_warn("l2tp: unknown Message-Type %i\n", msg_type->val.uint16);
				if (msg_type->M) {
					if (l2tp_terminate(conn, 2, 8))
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
	char *opt;
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

void __export l2tp_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("l2tp", "verbose");
	if (opt && atoi(opt) > 0)
		conf_verbose = 1;

	opt = conf_get_opt("l2tp", "avp_permissive");
	if (opt && atoi(opt) > 0)
		conf_avp_permissive = 1;

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

	load_config();

	start_udp_server();

	cli_register_simple_cmd2(&show_stat_exec, NULL, 2, "show", "stat");
	
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(22, l2tp_init);
