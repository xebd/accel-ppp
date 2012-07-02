#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>


#include "ipoe.h"

int main(int argc, char **argv)
{
#if LIBNL2
	struct nl_sock *h;
#else
	struct nl_handle *h;
#endif
	struct nl_msg *msg;
	int family;
	in_addr_t local;
	int err;

	if (argc != 2) {
		printf("usage: ipses-delete <addr>\n");
		return 1;
	}

	local = inet_addr(argv[1]);

#if LIBNL2
	h = nl_socket_alloc();
#else
	h = nl_handle_alloc();
#endif
	genl_connect(h);
	family = genl_ctrl_resolve(h, IPOE_GENL_NAME);

	msg = nlmsg_alloc();
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST, IPOE_CMD_DELETE, IPOE_GENL_VERSION);
	nla_put_u32(msg, IPOE_ATTR_PEER_ADDR, local);
	
	nl_send_auto_complete(h, msg);
	err = nl_recvmsgs_default(h);
#if LIBNL2
	printf("recv: %s\n", nl_geterror(err));
#else
	nl_perror("recv");
#endif

	nlmsg_free(msg);
	nl_close(h);

	return 0;
}
