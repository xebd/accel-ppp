#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>

#include "libnetlink.h"
#include "iplink.h"
#include "triton.h"
#include "log.h"

struct arg
{
	iplink_list_func func;
	void *arg;
};

static int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr *tb[IFLA_MAX + 1];
	struct arg *a = arg;

	if (n->nlmsg_type != RTM_NEWLINK)
		return 0;

	if (n->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
		return -1;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), IFLA_PAYLOAD(n));

	if (tb[IFLA_IFNAME] == NULL)
		return 0;
	
	//printf("%i %s\n", ifi->ifi_index, RTA_DATA(tb[IFLA_IFNAME]));

	return a->func(ifi->ifi_index, ifi->ifi_flags, RTA_DATA(tb[IFLA_IFNAME]), a->arg);
}

int __export iplink_list(iplink_list_func func, void *arg)
{
	struct rtnl_handle rth;
	struct arg a = { .func = func, .arg = arg };

	if (rtnl_open(&rth, 0)) {
		log_emerg("iplink: cannot open rtnetlink\n");
		return -1;
	}

	if (rtnl_wilddump_request(&rth, AF_PACKET, RTM_GETLINK) < 0) {
		log_emerg("iplink: cannot send dump request\n");
		goto out_err;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &a, NULL, NULL) < 0) {
		log_emerg("iplink: dump terminated\n");
		goto out_err;
	}

	rtnl_close(&rth);

	return 0;

out_err:
	rtnl_close(&rth);

	return -1;
}

