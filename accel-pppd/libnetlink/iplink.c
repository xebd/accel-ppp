#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <pthread.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>

#include "triton.h"
#include "log.h"

#include "libnetlink.h"
#include "iplink.h"

#include "memdebug.h"

struct arg
{
	iplink_list_func func;
	void *arg;
};

static pthread_key_t rth_key;
static __thread struct rtnl_handle *rth;

static void open_rth(void)
{
	rth = _malloc(sizeof(*rth));

	if (!rth)
		return;
	
	memset(rth, 0, sizeof(*rth));

	if (rtnl_open(rth, 0)) {
		log_ppp_error("radius: cannot open rtnetlink\n");
		_free(rth);
		rth = NULL;
		return;
	}

	pthread_setspecific(rth_key, rth);
}

static void free_rth(void *arg)
{
	struct rtnl_handle *rth = arg;

	rtnl_close(rth);

	_free(rth);
}

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

int __export iplink_get_stats(int ifindex, struct rtnl_link_stats *stats)
{
	struct iplink_req {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[4096];
	} req;
	struct ifinfomsg *ifi;
	int len;
	struct rtattr *tb[IFLA_MAX + 1];

	if (!rth)
		open_rth();
	
	if (!rth)
		return -1;

	memset(&req, 0, sizeof(req) - 1024);
	
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.n.nlmsg_type = RTM_GETLINK;
	req.i.ifi_family = AF_PACKET;
	req.i.ifi_index = ifindex;

	if (rtnl_talk(rth, &req.n, 0, 0, &req.n, NULL, NULL, 0) < 0)
		return -1;

	if (req.n.nlmsg_type != RTM_NEWLINK)
		return -1;

	ifi = NLMSG_DATA(&req.n);

	len = req.n.nlmsg_len;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_STATS])
		memcpy(stats, RTA_DATA(tb[IFLA_STATS]), sizeof(*stats));
	else
		return -1;
	
	return 0;
}

static void init(void)
{
	pthread_key_create(&rth_key, free_rth);
}

DEFINE_INIT(100, init);
