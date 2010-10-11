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

#include "triton.h"
#include "mempool.h"
#include "log.h"
#include "ppp.h"
#include "events.h"
#include "utils.h"

#include "memdebug.h"

#include "l2tp.h"
#include "attr_defs.h"

#define STATE_WAIT_SCCCN 1
#define STATE_WAIT_OCRQ  2
#define STATE_WAIT_OCCN  3
#define STATE_PPP        4
#define STATE_CLOSE      0

int conf_verbose = 0;
int conf_timeout = 5;
int conf_retransmit = 5;
const char *conf_host_name = "accel-pptp";

struct l2tp_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct sockaddr_in addr;
};

struct l2tp_conn_t
{
	struct triton_context_t ctx;
	struct triton_timer_t timeout_timer;
	struct triton_timer_t echo_timer;

	pthread_mutex_t lock;

	int sock;
	struct sockaddr_in addr;
	uint16_t tid;
	uint16_t sid;
	uint16_t peer_tid;
	uint16_t peer_sid;
	uint32_t framing_cap;

	struct l2tp_packet_t *last_pack;
	int retransmit;
	uint16_t Ns, Nr;
	struct list_head recv_queue;
	struct list_head send_queue;

	int state;

	struct ppp_ctrl_t ctrl;
	struct ppp_t ppp;
};

static pthread_mutex_t l2tp_lock = PTHREAD_MUTEX_INITIALIZER;
static struct l2tp_conn_t **l2tp_conn;
static uint16_t l2tp_tid;

static mempool_t l2tp_conn_pool;

static void l2tp_timeout(struct triton_timer_t *t);
static void l2tp_send_SCCRP(struct l2tp_conn_t *conn);
static void l2tp_send(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack);

static struct l2tp_conn_t *l2tp_conn_lookup(uint16_t tid)
{
	struct l2tp_conn_t *conn;
	pthread_mutex_lock(&conn->lock);
	conn = l2tp_conn[tid];
	if (conn)
		pthread_mutex_lock(&conn->lock);
	pthread_mutex_unlock(&conn->lock);

	return conn;
}

static void l2tp_disconnect(struct l2tp_conn_t *conn)
{
	close(conn->sock);

	if (conn->timeout_timer.tpd)
		triton_timer_del(&conn->timeout_timer);

	if (conn->echo_timer.tpd)
		triton_timer_del(&conn->echo_timer);

	if (conn->state == STATE_PPP) {
		conn->state = STATE_CLOSE;
		ppp_terminate(&conn->ppp, 1);
	}

	pthread_mutex_lock(&l2tp_lock);
	pthread_mutex_lock(&conn->lock);
	l2tp_conn[conn->tid] = NULL;
	pthread_mutex_unlock(&l2tp_lock);
	pthread_mutex_unlock(&conn->lock);

	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp);
	
	if (conf_verbose)
		log_ppp_info("disconnected\n");

	triton_context_unregister(&conn->ctx);

	if (conn->last_pack)
		l2tp_packet_free(conn->last_pack);

	if (conn->ppp.chan_name)
		_free(conn->ppp.chan_name);
	
	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);
	
	mempool_free(conn);
}

static void l2tp_terminate(struct l2tp_conn_t *conn, int res, int err)
{
	struct l2tp_packet_t *pack;
	struct l2tp_avp_result_code rc = {res, err};

	pack = l2tp_packet_alloc(2, Message_Type_Stop_Ctrl_Conn_Notify, &conn->addr);
	if (!pack) {
		l2tp_disconnect(conn);
		return;
	}
	
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, conn->tid))
		goto out_err;
	if (l2tp_packet_add_octets(pack, Result_Code, (uint8_t *)&rc, sizeof(rc)))
		goto out_err;

	l2tp_send(conn, pack);

	return;

out_err:
	l2tp_packet_free(pack);
	l2tp_disconnect(conn);
}

static void l2tp_alloc(struct l2tp_serv_t *serv, struct l2tp_packet_t *pack, struct l2tp_attr_t *assigned_tid, struct l2tp_attr_t *framing_cap)
{
	struct l2tp_conn_t *conn;
	uint16_t tid;

	conn = mempool_alloc(l2tp_conn_pool);
	if (!conn) {
		log_emerg("l2tp: out of memory\n");
		return;
	}

	memset(conn, 0, sizeof(*conn));

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
		return;
	}

	INIT_LIST_HEAD(&conn->recv_queue);
	INIT_LIST_HEAD(&conn->send_queue);

	conn->sock = dup(serv->hnd.fd);
	memcpy(&conn->addr, &pack->addr, sizeof(pack->addr));
	conn->peer_tid = assigned_tid->val.uint16;
	conn->framing_cap = framing_cap->val.uint32;

	conn->timeout_timer.expire = l2tp_timeout;
	conn->timeout_timer.period = conf_timeout * 1000;
	conn->ctrl.ctx = &conn->ctx;
	conn->ctrl.name = "l2tp";

	conn->ctrl.calling_station_id = _malloc(17);
	conn->ctrl.called_station_id = _malloc(17);
	u_inet_ntoa(conn->addr.sin_addr.s_addr, conn->ctrl.calling_station_id);
	u_inet_ntoa(serv->addr.sin_addr.s_addr, conn->ctrl.called_station_id);

	ppp_init(&conn->ppp);
	conn->ppp.ctrl = &conn->ctrl;

	triton_context_register(&conn->ctx, &conn->ppp);
	triton_context_wakeup(&conn->ctx);

	if (conf_verbose) {
		log_switch(&conn->ctx, &conn->ppp);
		log_ppp_info("recv ");
		l2tp_packet_print(pack);
	}

	triton_context_call(&conn->ctx, (triton_event_func)l2tp_send_SCCRP, conn);
}

static int l2tp_connect(struct l2tp_conn_t *conn)
{

	return 0;
}

static void l2tp_timeout(struct triton_timer_t *t)
{
	struct l2tp_conn_t *conn = container_of(t, typeof(*conn), timeout_timer);
	struct l2tp_packet_t *pack;

	if (!list_empty(&conn->send_queue)) {
		log_ppp_debug("l2tp: retransmit (%i)\n", conn->retransmit);
		if (++conn->retransmit <= conf_retransmit) {
			pack = list_entry(conn->send_queue.next, typeof(*pack), entry);
			pack->hdr.Nr = htons(conn->Nr + 1);
			if (conf_verbose) {
				log_ppp_info("send ");
				l2tp_packet_print(conn->last_pack);
			}
			if (l2tp_packet_send(conn->sock, conn->last_pack) == 0)
				return;
		}
	}
	
	l2tp_disconnect(conn);
}

static void l2tp_send(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	conn->retransmit = 0;

	pack->hdr.tid = htons(conn->peer_tid);
	pack->hdr.sid = htons(conn->peer_sid);
	pack->hdr.Nr = htons(conn->Nr + 1);
	pack->hdr.Ns = htons(conn->Ns++);

	if (conf_verbose) {
		log_ppp_info("send ");
		l2tp_packet_print(conn->last_pack);
	}

	if (l2tp_packet_send(conn->sock, pack))
		goto out_err;

	if (!conn->timeout_timer.tpd)
		triton_timer_add(&conn->ctx, &conn->timeout_timer, 0);

	if (!list_empty(&pack->attrs))
		list_add_tail(&pack->entry, &conn->send_queue);
	
	return;

out_err:
	l2tp_packet_free(pack);
	l2tp_disconnect(conn);
}

static void l2tp_send_ZLB(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, 0, &conn->addr);
	if (!pack) {
		l2tp_disconnect(conn);
		return;
	}

	l2tp_send(conn, pack);

	return;
}

static void l2tp_send_SCCRP(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Start_Ctrl_Conn_Reply, &conn->addr);
	if (!pack) {
		l2tp_disconnect(conn);
		return;
	}
	
	if (l2tp_packet_add_int16(pack, Protocol_Version, L2TP_V2_PROTOCOL_VERSION))
		goto out_err;
	if (l2tp_packet_add_string(pack, Host_Name, conf_host_name))
		goto out_err;
	if (l2tp_packet_add_int32(pack, Framing_Capabilities, conn->framing_cap))
		goto out_err;
	if (l2tp_packet_add_int16(pack, Assigned_Tunnel_ID, conn->tid))
		goto out_err;


	l2tp_send(conn, pack);

	conn->state = STATE_WAIT_SCCCN;

	return;

out_err:
	l2tp_packet_free(pack);
	l2tp_disconnect(conn);
}

static void l2tp_send_OCRP(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;

	pack = l2tp_packet_alloc(2, Message_Type_Outgoing_Call_Reply, &conn->addr);
	if (!pack) {
		l2tp_disconnect(conn);
		return;
	}
	
	conn->sid = 1;

	if (l2tp_packet_add_int16(pack, Assigned_Session_ID, conn->sid))
		goto out_err;

	l2tp_send(conn, pack);

	return;

out_err:
	l2tp_packet_free(pack);
	l2tp_disconnect(conn);
}

static void l2tp_recv_SCCRQ(struct l2tp_serv_t *serv, struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr;
	struct l2tp_attr_t *protocol_version = NULL;
	struct l2tp_attr_t *assigned_tid = NULL;
	struct l2tp_attr_t *assigned_cid = NULL;
	struct l2tp_attr_t *framing_cap = NULL;
	struct l2tp_attr_t *router_id = NULL;
	
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
				if (conf_verbose)
					log_warn("l2tp: Challenge in SCCRQ is not supported\n");
				return;
			case Assigned_Connection_ID:
				assigned_cid = attr;
				break;
			case Router_ID:
				router_id = attr;
				break;
			case Message_Digest:
				if (conf_verbose)
					log_warn("l2tp: Message-Digest is not supported\n");
				return;
		}
	}

	if (assigned_tid) {
		if (!protocol_version) {
			if (conf_verbose)
				log_warn("l2tp: SCCRQ: no Protocol-Version present in message\n");
			return;
		}
		if (protocol_version->val.uint16 != L2TP_V2_PROTOCOL_VERSION) {
			if (conf_verbose)
				log_warn("l2tp: protocol version %02x is not supported\n", protocol_version->val.uint16);
			return;
		}
		if (!framing_cap) {
			if (conf_verbose)
				log_warn("l2tp: SCCRQ: no Framing-Capabilities present in message\n");
			return;
		}
		
		l2tp_alloc(serv, pack, assigned_tid, framing_cap);

	} else if (assigned_cid) {
		// not yet implemented
		return;
	} else {
		if (conf_verbose)
			log_warn("l2tp: SCCRQ: no Assigned-Tunnel-ID or Assigned-Connection-ID present in message\n");
		return;
	}
}

static void l2tp_recv_SCCCN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	if (conn->state == STATE_WAIT_SCCCN) {
		l2tp_send_ZLB(conn);
		conn->state = STATE_WAIT_OCRQ;
	}
	else
		log_ppp_warn("l2tp: unexpected SCCCN\n");
}

static void l2tp_recv_StopCCN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{

}

static void l2tp_recv_HELLO(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{

}

static void l2tp_recv_OCRQ(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr;
	struct l2tp_attr_t *assigned_sid = NULL;

	if (conn->state != STATE_WAIT_OCRQ) {
		log_ppp_warn("l2tp: unexpected OCRQ\n");
		return;
	}

	list_for_each_entry(attr, &pack->attrs, entry) {
		switch(attr->attr->id) {
			case Assigned_Session_ID:
				assigned_sid = attr;
				break;
			case Call_Serial_Number:
			case Minimum_BPS:
			case Maximum_BPS:
			case Bearer_Type:
			case Framing_Type:
			case Called_Number:
			case Sub_Address:
				break;
			default:
				if (attr->M) {
					if (conf_verbose) {
						log_ppp_warn("l2tp: OCRQ: unknown attribute %i\n", attr->attr->id);
						l2tp_terminate(conn, 2, 8);
						return;
					}
				}
		}
	}

	if (!assigned_sid) {
		if (conf_verbose)
			log_ppp_warn("l2tp: OCRQ: no Assigned-Session-ID attribute present in message\n");
		l2tp_terminate(conn, 2, 0);
		return;
	}

	l2tp_send_OCRP(conn);

	conn->peer_sid = assigned_sid->val.uint16;

	l2tp_connect(conn);
}

static void l2tp_recv_OCCN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{

}

static void l2tp_recv_CDN(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{

}

static void l2tp_recv_SLI(struct l2tp_conn_t *conn, struct l2tp_packet_t *pack)
{

}

static void l2tp_ctx_recv(struct l2tp_conn_t *conn)
{
	struct l2tp_packet_t *pack;
	struct l2tp_attr_t *msg_type;

	pthread_mutex_lock(&conn->lock);
	if (list_empty(&conn->recv_queue)) {
		pthread_mutex_unlock(&conn->lock);
		return;
	}
	pack = list_entry(conn->recv_queue.next, typeof(*pack), entry);
	list_del(&pack->entry);
	pthread_mutex_unlock(&conn->lock);

	if (conf_verbose) {
		log_ppp_info("recv ");
		l2tp_packet_print(pack);
	}

	if (ntohs(pack->hdr.Ns) == conn->Nr + 1) {
		conn->Nr++;
		if (!list_empty(&conn->send_queue)) {
			pack = list_entry(conn->send_queue.next, typeof(*pack), entry);
			list_del(&pack->entry);
			l2tp_packet_free(pack);
			conn->retransmit = 0;
		}
		if (!list_empty(&conn->send_queue))
			triton_timer_mod(&conn->timeout_timer, 0);
		else if (conn->timeout_timer.tpd)
			triton_timer_del(&conn->timeout_timer);
	} else {
		if (ntohs(pack->hdr.Ns) < conn->Nr + 1 || (ntohs(pack->hdr.Ns > 32767 && conn->Nr + 1 < 32767))) {
			log_ppp_debug("duplicate packet\n");
			l2tp_send_ZLB(conn);
		} else
			log_ppp_debug("reordered packet\n");
		l2tp_packet_free(pack);
		return;
	}

	if (list_empty(&pack->attrs)) {
		l2tp_packet_free(pack);
		return;
	}

	msg_type = list_entry(pack->attrs.next, typeof(*msg_type), entry);

	if (msg_type->attr->id != Message_Type) {
		if (conf_verbose)
			log_ppp_error("l2tp: first attribute is not Message-Type, dropping connection...\n");
		goto drop;
	}

	switch (msg_type->val.uint16) {
		case Message_Type_Start_Ctrl_Conn_Connected:
			l2tp_recv_SCCCN(conn, pack);
			break;
		case Message_Type_Stop_Ctrl_Conn_Notify:
			l2tp_recv_StopCCN(conn, pack);
			break;
		case Message_Type_Hello:
			l2tp_recv_HELLO(conn, pack);
			break;
		case Message_Type_Outgoing_Call_Request:
			l2tp_recv_OCRQ(conn, pack);
			break;
		case Message_Type_Outgoing_Call_Connected:
			l2tp_recv_OCCN(conn, pack);
			break;
		case Message_Type_Call_Disconnect_Notify:
			l2tp_recv_CDN(conn, pack);
			break;
		case Message_Type_Set_Link_Info:
			l2tp_recv_SLI(conn, pack);
			break;
		case Message_Type_Start_Ctrl_Conn_Reply:
		case Message_Type_Outgoing_Call_Reply:
		case Message_Type_Incoming_Call_Request:
		case Message_Type_Incoming_Call_Reply:
		case Message_Type_Incoming_Call_Connected:
		case Message_Type_WAN_Error_Notify:
			if (conf_verbose)
				log_warn("l2tp: unexpected Message-Type %i\n", msg_type->val.uint16);
			break;
		default:
			if (conf_verbose)
				log_warn("l2tp: unknown Message-Type %i\n", msg_type->val.uint16);
			if (msg_type->M)
				l2tp_terminate(conn, 2, 8);
	}

	l2tp_packet_free(pack);

	return;

drop:
	l2tp_packet_free(pack);
	l2tp_disconnect(conn);
}

static int l2tp_udp_read(struct triton_md_handler_t *h)
{
	struct l2tp_serv_t *serv = container_of(h, typeof(*serv), hnd);
	struct l2tp_packet_t *pack;
	struct l2tp_attr_t *msg_type;
	struct l2tp_conn_t *conn = NULL;

	while (1) {
		pack = NULL;

		if (l2tp_recv(h->fd, &pack))
			break;

		if (!pack)
			continue;

		if (pack->hdr.ver == 2 && pack->hdr.tid) {
				conn = l2tp_conn_lookup(ntohs(pack->hdr.tid));
				if (!conn) {
					if (conf_verbose)
						log_warn("l2tp: tunnel %i not found\n", ntohs(pack->hdr.tid));
					goto skip;
				}
				
				list_add_tail(&pack->entry, &conn->recv_queue);
				triton_context_call(&conn->ctx, (triton_event_func)l2tp_ctx_recv, conn);
				pthread_mutex_unlock(&conn->lock);
				continue;
		}

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
				l2tp_recv_SCCRQ(serv, pack);
		else {
			if (conf_verbose) {
				log_warn("recv (unexpected) ");
				l2tp_packet_print(pack);
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
}

static struct l2tp_serv_t udp_serv =
{
	.hnd.read=l2tp_udp_read,
	.ctx.close=l2tp_udp_close,
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

	udp_serv.hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
  if (udp_serv.hnd.fd < 0) {
    log_emerg("l2tp: socket: %s\n", strerror(errno));
    return;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons(L2TP_PORT);

	opt = conf_get_opt("l2tp", "bind");
	if (opt)
		addr.sin_addr.s_addr = inet_addr(opt);
	else
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
  
  setsockopt(udp_serv.hnd.fd, SOL_SOCKET, SO_REUSEADDR, &udp_serv.hnd.fd, 4);  
  if (bind (udp_serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    log_emerg("l2tp: failed to bind socket: %s\n", strerror(errno));
		close(udp_serv.hnd.fd);
    return;
  }

	if (fcntl(udp_serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_emerg("pptp: failed to set nonblocking mode: %s\n", strerror(errno));
		close(udp_serv.hnd.fd);
    return;
	}

	memcpy(&udp_serv.addr, &addr, sizeof(addr));

	triton_context_register(&udp_serv.ctx, NULL);
	triton_md_register_handler(&udp_serv.ctx, &udp_serv.hnd);
	triton_md_enable_handler(&udp_serv.hnd, MD_MODE_READ);
	triton_context_wakeup(&udp_serv.ctx);
}

static void __init l2tp_init(void)
{
	char *opt;

	l2tp_conn = malloc(L2TP_MAX_TID * sizeof(void *));
	memset(l2tp_conn, 0, L2TP_MAX_TID * sizeof(void *));

	l2tp_conn_pool = mempool_create(sizeof(struct l2tp_conn_t));

	opt = conf_get_opt("l2tp", "verbose");
	if (opt && atoi(opt) > 0)
		conf_verbose = 1;

	start_udp_server();
}

