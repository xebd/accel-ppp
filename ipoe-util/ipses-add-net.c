#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
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
	in_addr_t local, remote;
	int err;
	uint32_t addr;
	int m;

	if (argc != 3) {
		printf("usage: ipses-add-net <addr> <mask>\n");
		return 1;
	}

	addr = inet_addr(argv[1]);
	m = atoi(argv[2]);

#if LIBNL2
	h = nl_socket_alloc();
#else
	h = nl_handle_alloc();
#endif
	genl_connect(h);
	family = genl_ctrl_resolve(h, IPOE_GENL_NAME);

	msg = nlmsg_alloc();
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST, IPOE_CMD_ADD_NET, IPOE_GENL_VERSION);
	nla_put_u32(msg, IPOE_ATTR_ADDR, addr);
	nla_put_u64(msg, IPOE_ATTR_MASK, (1 << m) - 1);
	
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

