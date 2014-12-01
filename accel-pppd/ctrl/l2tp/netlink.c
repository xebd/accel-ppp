#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include "l2tp_kernel.h"
#include "triton.h"

static int family;

void l2tp_nl_delete_tunnel(int tid)
{
	struct nl_sock *nl_sock;
	struct nl_msg *msg;

	nl_sock = nl_socket_alloc();
	msg = nlmsg_alloc();

	genl_connect(nl_sock);

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST, L2TP_CMD_TUNNEL_DELETE, L2TP_GENL_VERSION);
	nla_put_u32(msg, L2TP_ATTR_CONN_ID, tid);

	nl_send_auto_complete(nl_sock, msg);
	nl_recvmsgs_default(nl_sock);

	nlmsg_free(msg);
	nl_close(nl_sock);
	nl_socket_free(nl_sock);
}

void l2tp_nl_create_tunnel(int fd, int tid, int peer_tid)
{
	struct nl_sock *nl_sock;
	struct nl_msg *msg;

	nl_sock = nl_socket_alloc();
	msg = nlmsg_alloc();

	genl_connect(nl_sock);

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST, L2TP_CMD_TUNNEL_CREATE, L2TP_GENL_VERSION);
	nla_put_u16(msg, L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP);
	nla_put_u8(msg, L2TP_ATTR_PROTO_VERSION, 2);
	nla_put_u32(msg, L2TP_ATTR_CONN_ID, tid);
	nla_put_u32(msg, L2TP_ATTR_PEER_CONN_ID, peer_tid);
	nla_put_u32(msg, L2TP_ATTR_FD, fd);
	//nla_put_u32(msg, L2TP_ATTR_DEBUG, 0xffffffff);

	nl_send_auto_complete(nl_sock, msg);
	nl_recvmsgs_default(nl_sock);

	nlmsg_free(msg);
	nl_close(nl_sock);
	nl_socket_free(nl_sock);
}

void l2tp_nl_create_session(int tid, int sid, int peer_sid)
{
	struct nl_sock *nl_sock;
	struct nl_msg *msg;

	nl_sock = nl_socket_alloc();
	msg = nlmsg_alloc();

	genl_connect(nl_sock);

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST, L2TP_CMD_SESSION_CREATE, L2TP_GENL_VERSION);
	nla_put_u32(msg, L2TP_ATTR_CONN_ID, tid);
	nla_put_u32(msg, L2TP_ATTR_SESSION_ID, sid);
	nla_put_u32(msg, L2TP_ATTR_PEER_SESSION_ID, peer_sid);
	nla_put_u16(msg, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_PPP);
	nla_put_u8(msg, L2TP_ATTR_LNS_MODE, 1);
	//nla_put_u32(msg, L2TP_ATTR_DEBUG, 0xffffffff);

	nl_send_auto_complete(nl_sock, msg);
	nl_recvmsgs_default(nl_sock);

	nlmsg_free(msg);
	nl_close(nl_sock);
	nl_socket_free(nl_sock);
}

static void init(void)
{
	struct nl_sock *nl_sock = nl_socket_alloc();

	genl_connect(nl_sock);

	family = genl_ctrl_resolve(nl_sock, L2TP_GENL_NAME);

	nl_close(nl_sock);
	nl_socket_free(nl_sock);
}

DEFINE_INIT(21, init);
