#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/genetlink.h>

#include "triton.h"
#include "log.h"
#include "genl.h"
#include "libnetlink.h"

#include "ipoe.h"
#include "if_ipoe.h"

#include "memdebug.h"

#define PKT_ATTR_MAX 256

static struct rtnl_handle rth;
static struct triton_md_handler_t mc_hnd;
static int ipoe_genl_id;

void ipoe_nl_delete_nets(void)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_DEL_NET;

	addattr32(nlh, 1024, IPOE_ATTR_ADDR, 0);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_error("ipoe: nl_del_net: error talking to kernel\n");
}

void ipoe_nl_add_net(uint32_t addr, int mask)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_ADD_NET;

	mask = (0xffffffff) << (32 - mask);

	addattr32(nlh, 1024, IPOE_ATTR_ADDR, addr);
	addattr32(nlh, 1024, IPOE_ATTR_MASK, mask);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_error("ipoe: nl_add_net: error talking to kernel\n");
}

void ipoe_nl_delete_bypass_nets(void)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_DEL_BYPASS_NET;

	addattr32(nlh, 1024, IPOE_ATTR_ADDR, 0);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_error("ipoe: nl_del_net: error talking to kernel\n");
}

void ipoe_nl_add_bypass_net(uint32_t addr, int mask)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_ADD_BYPASS_NET;

	mask = (0xffffffff) << (32 - mask);

	addattr32(nlh, 1024, IPOE_ATTR_ADDR, addr);
	addattr32(nlh, 1024, IPOE_ATTR_MASK, mask);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_error("ipoe: nl_add_bypass_net: error talking to kernel\n");
}

int ipoe_nl_add_exclude(uint32_t addr, int mask)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	int ret = 0;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_ppp_error("ipoe: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_ADD_EXCLUDE;


	addattr32(nlh, 1024, IPOE_ATTR_ADDR, addr);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_ppp_error("ipoe: nl_add_net: error talking to kernel\n");
		ret = -1;
	}

	rtnl_close(&rth);

	return ret;
}

void ipoe_nl_del_exclude(uint32_t addr)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_ppp_error("ipoe: cannot open generic netlink socket\n");
		return;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_DEL_EXCLUDE;

	addattr32(nlh, 1024, IPOE_ATTR_ADDR, addr);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_ppp_error("ipoe: nl_add_net: error talking to kernel\n");

	rtnl_close(&rth);
}

void ipoe_nl_delete_interfaces(void)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_DEL_IF;

	addattr32(nlh, 1024, IPOE_ATTR_IFINDEX, -1);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_error("ipoe: nl_del_iface: error talking to kernel\n");
}

void ipoe_nl_add_interface(int ifindex)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_ADD_IF;

	addattr32(nlh, 1024, IPOE_ATTR_IFINDEX, ifindex);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_error("ipoe: nl_add_iface: error talking to kernel\n");
}


int ipoe_nl_create(uint32_t peer_addr, uint32_t addr, const char *ifname, uint8_t *hwaddr)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct rtattr *tb[IPOE_ATTR_MAX + 1];
	struct rtattr *attrs;
	int len;
	int ret = -1;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	union {
		uint8_t hwaddr[6];
		uint64_t u64;
	} u;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_ppp_error("ipoe: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_CREATE;

	if (peer_addr)
		addattr32(nlh, 1024, IPOE_ATTR_PEER_ADDR, peer_addr);

	if (addr)
		addattr32(nlh, 1024, IPOE_ATTR_ADDR, addr);

	if (hwaddr) {
		memcpy(u.hwaddr, hwaddr, 6);
		addattr_l(nlh, 1024, IPOE_ATTR_HWADDR, &u.u64, 8);
	}

	if (ifname)
		addattr_l(nlh, 1024, IPOE_ATTR_IFNAME, ifname, strlen(ifname) + 1);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_ppp_error("ipoe: nl_create: error talking to kernel\n");

	if (nlh->nlmsg_type != ipoe_genl_id) {
		log_ppp_error("ipoe: not a IPoE message %d\n", nlh->nlmsg_type);
		goto out;
	}

	ghdr = NLMSG_DATA(nlh);

	if (ghdr->cmd != IPOE_CMD_CREATE) {
		log_ppp_error("ipoe: unknown IPoE command %d\n", ghdr->cmd);
		goto out;
	}

	len = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		log_ppp_error("ipoe: wrong IPoE message len %d\n", len);
		goto out;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	parse_rtattr(tb, IPOE_ATTR_MAX, attrs, len);

	if (!tb[IPOE_ATTR_IFINDEX]) {
		log_ppp_error("ipoe: missing IPOE_ATTR_IFINDEX attribute\n");
		goto out;
	}

	ret = *(uint32_t *)(RTA_DATA(tb[IPOE_ATTR_IFINDEX]));

out:
	rtnl_close(&rth);

	return ret;
}

int ipoe_nl_modify(int ifindex, uint32_t peer_addr, uint32_t addr, const char *ifname, uint8_t *hwaddr)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	int ret = 0;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	union {
		uint8_t hwaddr[6];
		uint64_t u64;
	} u;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_ppp_error("ipoe: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_MODIFY;

	addattr32(nlh, 1024, IPOE_ATTR_IFINDEX, ifindex);
	addattr32(nlh, 1024, IPOE_ATTR_PEER_ADDR, peer_addr);
	addattr32(nlh, 1024, IPOE_ATTR_ADDR, addr);

	if (hwaddr) {
		memcpy(u.hwaddr, hwaddr, 6);
		addattr_l(nlh, 1024, IPOE_ATTR_HWADDR, &u.u64, 8);
	}

	if (ifname)
		addattr_l(nlh, 1024, IPOE_ATTR_IFNAME, ifname, strlen(ifname) + 1);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_ppp_error("ipoe: nl_create: error talking to kernel\n");
		ret = -1;
	}

	rtnl_close(&rth);

	return ret;
}

static int dump_session(const struct sockaddr_nl *addr, struct nlmsghdr *n, void *arg)
{
	struct list_head *list = arg;
	struct ipoe_session_info *info;
	struct rtattr *tb[IPOE_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *attrs;

	if (ghdr->cmd != IPOE_CMD_GET) {
		log_error("ipoe: dump_session: got unexpected command %d\n", ghdr->cmd);
		return 0;
	}

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0 ) {
		log_error("ipoe: dump_session: wrong message length %i\n", len);
		return -1;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	parse_rtattr(tb, IPOE_ATTR_MAX, attrs, len);

	info = _malloc(sizeof(*info));
	if (!info) {
		log_emerg("out of memory\n");
		return -1;
	}

	memset(info, 0, sizeof(*info));

	if (tb[IPOE_ATTR_IFINDEX])
		info->ifindex = *(uint32_t *)(RTA_DATA(tb[IPOE_ATTR_IFINDEX]));
	else {
		log_error("ipoe: dump_session: IPOE_ATTR_IFINDEX is absent\n");
		_free(info);
		return 0;
	}

	if (tb[IPOE_ATTR_ADDR])
		info->addr = *(uint32_t *)(RTA_DATA(tb[IPOE_ATTR_ADDR]));

	if (tb[IPOE_ATTR_PEER_ADDR])
		info->peer_addr = *(uint32_t *)(RTA_DATA(tb[IPOE_ATTR_PEER_ADDR]));

	list_add_tail(&info->entry, list);

	return 0;
}

void ipoe_nl_get_sessions(struct list_head *list)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	nlh->nlmsg_type = ipoe_genl_id;
	nlh->nlmsg_seq = rth.dump = ++rth.seq;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_GET;

	if (rtnl_send(&rth, (char *)nlh, nlh->nlmsg_len) < 0) {
		log_emerg("ipoe: failed to send dump request: %s\n", strerror(errno));
		return;
	}

	rtnl_dump_filter(&rth, dump_session, list, NULL, NULL);
}

void ipoe_nl_delete(int ifindex)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_ppp_error("ipoe: cannot open generic netlink socket\n");
		return;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_DELETE;

	addattr32(nlh, 128, IPOE_ATTR_IFINDEX, ifindex);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 )
		log_ppp_error("ipoe: nl_delete: error talking to kernel\n");

	rtnl_close(&rth);
}

int ipoe_nl_add_vlan_mon(int ifindex, long *mask, int len)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return -1;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_ADD_VLAN_MON;

	addattr32(nlh, 1024, IPOE_ATTR_IFINDEX, ifindex);
	addattr_l(nlh, 1024, IPOE_ATTR_VLAN_MASK, mask, len);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("ipoe: nl_add_vlan_mon: error talking to kernel\n");
		return -1;
	}

	return 0;
}

int ipoe_nl_add_vlan_mon_vid(int ifindex, int vid)
{
	struct rtnl_handle rth;
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;
	int r = 0;

	if (rtnl_open_byproto(&rth, 0, NETLINK_GENERIC)) {
		log_error("ipoe: cannot open generic netlink socket\n");
		return -1;
	}

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_ADD_VLAN_MON_VID;

	addattr32(nlh, 1024, IPOE_ATTR_IFINDEX, ifindex);
	addattr32(nlh, 1024, IPOE_ATTR_ADDR, vid);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("ipoe: nl_add_vlan_mon_vid: error talking to kernel\n");
		r = -1;
	}

	rtnl_close(&rth);

	return r;
}


int ipoe_nl_del_vlan_mon(int ifindex)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *ghdr;
	struct {
		struct nlmsghdr n;
		char buf[1024];
	} req;

	if (rth.fd == -1)
		return -1;

	nlh = &req.n;
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_type = ipoe_genl_id;

	ghdr = NLMSG_DATA(&req.n);
	ghdr->cmd = IPOE_CMD_DEL_VLAN_MON;

	addattr32(nlh, 1024, IPOE_ATTR_IFINDEX, ifindex);

	if (rtnl_talk(&rth, nlh, 0, 0, nlh, NULL, NULL, 0) < 0 ) {
		log_error("ipoe: nl_del_vlan_mon: error talking to kernel\n");
		return -1;
	}

	return 0;
}


static void ipoe_up_handler(const struct sockaddr_nl *addr, struct nlmsghdr *h)
{
	struct rtattr *tb[PKT_ATTR_MAX + 1];
	struct rtattr *tb2[IPOE_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(h);
	int len = h->nlmsg_len;
	struct rtattr *attrs;
	int i;
	int ifindex;
	struct iphdr *iph;
	struct ethhdr *eth;

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		log_warn("ipoe: wrong controller message length %d\n", len);
		return;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	parse_rtattr(tb, PKT_ATTR_MAX, attrs, len);

	for (i = 1; i < PKT_ATTR_MAX; i++) {
		if (!tb[i])
			break;

		parse_rtattr_nested(tb2, IPOE_ATTR_MAX, tb[i]);

		if (!tb2[IPOE_ATTR_ETH_HDR] || !tb2[IPOE_ATTR_IP_HDR] || !tb2[IPOE_ATTR_IFINDEX])
			continue;

		ifindex = *(uint32_t *)(RTA_DATA(tb2[IPOE_ATTR_IFINDEX]));
		iph = (struct iphdr *)(RTA_DATA(tb2[IPOE_ATTR_IP_HDR]));
		eth = (struct ethhdr *)(RTA_DATA(tb2[IPOE_ATTR_ETH_HDR]));

		ipoe_recv_up(ifindex, eth, iph);
	}
}

static void ipoe_vlan_mon_handler(const struct sockaddr_nl *addr, struct nlmsghdr *h)
{
	struct rtattr *tb[PKT_ATTR_MAX + 1];
	struct rtattr *tb2[IPOE_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(h);
	int len = h->nlmsg_len;
	struct rtattr *attrs;
	int i;
	int ifindex, vid;

	len -= NLMSG_LENGTH(GENL_HDRLEN);

	if (len < 0) {
		log_warn("ipoe: wrong controller message length %d\n", len);
		return;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	parse_rtattr(tb, PKT_ATTR_MAX, attrs, len);

	for (i = 1; i < PKT_ATTR_MAX; i++) {
		if (!tb[i])
			break;

		parse_rtattr_nested(tb2, IPOE_ATTR_MAX, tb[i]);

		if (!tb2[IPOE_ATTR_IFINDEX] || !tb2[IPOE_ATTR_ADDR])
			continue;

		ifindex = *(uint32_t *)(RTA_DATA(tb2[IPOE_ATTR_IFINDEX]));
		vid = *(uint32_t *)(RTA_DATA(tb2[IPOE_ATTR_ADDR]));

		ipoe_vlan_notify(ifindex, vid);
	}
}


static int ipoe_mc_read(struct triton_md_handler_t *h)
{
	int status;
	struct nlmsghdr *hdr;
	struct genlmsghdr *ghdr;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
			.msg_name = &nladdr,
			.msg_namelen = sizeof(nladdr),
			.msg_iov = &iov,
			.msg_iovlen = 1,
	};
	char   buf[8192];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(h->fd, &msg, 0);

		if (status < 0) {
			if (errno == EAGAIN)
				break;
			log_error("ipoe: netlink error: %s\n", strerror(errno));
			if (errno == ENOBUFS)
				continue;
			return 0;
		}

		if (status == 0) {
			log_error("ipoe: EOF on netlink\n");
			return 0;
		}

		if (msg.msg_namelen != sizeof(nladdr)) {
			log_error("ipoe: netlink sender address length == %d\n", msg.msg_namelen);
			return 0;
		}

		for (hdr = (struct nlmsghdr*)buf; status >= sizeof(*hdr); ) {
			int len = hdr->nlmsg_len;
			int l = len - sizeof(*h);

			if (l<0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					log_warn("ipoe: truncated netlink message\n");
					continue;
				}
				log_error("ipoe: malformed netlink message\n");
				continue;
			}

			ghdr = NLMSG_DATA(hdr);

			if (ghdr->cmd == IPOE_REP_PKT)
				ipoe_up_handler(&nladdr, hdr);
			else if (ghdr->cmd == IPOE_VLAN_NOTIFY)
				ipoe_vlan_mon_handler(&nladdr, hdr);

			status -= NLMSG_ALIGN(len);
			hdr = (struct nlmsghdr*)((char*)hdr + NLMSG_ALIGN(len));
		}

		if (msg.msg_flags & MSG_TRUNC) {
			log_warn("ipoe: netlink message truncated\n");
			continue;
		}

		if (status) {
			log_error("ipoe: netlink remnant of size %d\n", status);
			return 0;
		}
	}

	return 0;
}

static void ipoe_mc_close(struct triton_context_t *ctx)
{
	triton_md_unregister_handler(&mc_hnd, 0);
	triton_context_unregister(ctx);
}

static struct triton_context_t mc_ctx = {
		.close = ipoe_mc_close,
};

static struct triton_md_handler_t mc_hnd = {
		.read = ipoe_mc_read,
};

static void init(void)
{
	int mcg_id = genl_resolve_mcg(IPOE_GENL_NAME, IPOE_GENL_MCG_PKT, &ipoe_genl_id);
	if (mcg_id == -1) {
		log_warn("ipoe: unclassified packet handling is disabled\n");
		rth.fd = -1;
		return;
	}

	if (rtnl_open_byproto(&rth, 1 << (mcg_id - 1), NETLINK_GENERIC)) {
		log_error("ipoe: cannot open generic netlink socket\n");
		rth.fd = -1;
		return;
	}

	fcntl(rth.fd, F_SETFL, O_NONBLOCK);
	fcntl(rth.fd, F_SETFD, fcntl(rth.fd, F_GETFD) | FD_CLOEXEC);

	triton_context_register(&mc_ctx, NULL);
	mc_hnd.fd = rth.fd;
	triton_md_register_handler(&mc_ctx, &mc_hnd);
	triton_md_enable_handler(&mc_hnd, MD_MODE_READ);
	triton_context_wakeup(&mc_ctx);

	ipoe_nl_del_exclude(0);
}

DEFINE_INIT(19, init);
