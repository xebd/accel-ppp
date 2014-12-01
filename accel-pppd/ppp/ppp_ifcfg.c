#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "triton.h"
#include "events.h"
#include "ppp.h"
#include "ipdb.h"
#include "log.h"

// from /usr/include/linux/ipv6.h
struct in6_ifreq {
        struct in6_addr ifr6_addr;
        __u32           ifr6_prefixlen;
        int             ifr6_ifindex;
};

static void devconf(struct ppp_t *ppp, const char *attr, const char *val)
{
	int fd;
	char fname[PATH_MAX];

	sprintf(fname, "/proc/sys/net/ipv6/conf/%s/%s", ppp->ifname, attr);
	fd = open(fname, O_WRONLY);
	if (!fd) {
		log_ppp_error("ppp: failed to open '%s': %s\n", fname, strerror(errno));
		return;
	}

	write(fd, val, strlen(val));

	close(fd);
}

static void build_addr(struct ipv6db_addr_t *a, uint64_t intf_id, struct in6_addr *addr)
{
	memcpy(addr, &a->addr, sizeof(*addr));

	if (a->prefix_len <= 64)
		*(uint64_t *)(addr->s6_addr + 8) = intf_id;
	else
		*(uint64_t *)(addr->s6_addr + 8) |= intf_id & ((1 << (128 - a->prefix_len)) - 1);
}

void ppp_ifup(struct ppp_t *ppp)
{
	struct ipv6db_addr_t *a;
	struct ifreq ifr;
	struct in6_ifreq ifr6;
	struct npioctl np;
	struct sockaddr_in addr;

	triton_event_fire(EV_SES_ACCT_START, ppp);
	if (ppp->stop_time)
		return;

	triton_event_fire(EV_SES_PRE_UP, ppp);
	if (ppp->stop_time)
		return;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ppp->ifname);

	if (ppp->ses.ipv4) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = ppp->ses.ipv4->addr;
		memcpy(&ifr.ifr_addr,&addr,sizeof(addr));

		if (ioctl(sock_fd, SIOCSIFADDR, &ifr))
			log_ppp_error("ppp: failed to set IPv4 address: %s\n", strerror(errno));

		addr.sin_addr.s_addr = ppp->ses.ipv4->peer_addr;
		memcpy(&ifr.ifr_dstaddr,&addr,sizeof(addr));

		if (ioctl(sock_fd, SIOCSIFDSTADDR, &ifr))
			log_ppp_error("ppp: failed to set peer IPv4 address: %s\n", strerror(errno));
	}

	if (ppp->ses.ipv6) {
		devconf(ppp, "accept_ra", "0");
		devconf(ppp, "autoconf", "0");
		devconf(ppp, "forwarding", "1");

		memset(&ifr6, 0, sizeof(ifr6));
		ifr6.ifr6_addr.s6_addr32[0] = htons(0xfe80);
		*(uint64_t *)(ifr6.ifr6_addr.s6_addr + 8) = ppp->ses.ipv6->intf_id;
		ifr6.ifr6_prefixlen = 64;
		ifr6.ifr6_ifindex = ppp->ifindex;

		if (ioctl(sock6_fd, SIOCSIFADDR, &ifr6))
			log_ppp_error("ppp: failed to set LL IPv6 address: %s\n", strerror(errno));

		list_for_each_entry(a, &ppp->ses.ipv6->addr_list, entry) {
			if (a->prefix_len == 128)
				continue;

			build_addr(a, ppp->ses.ipv6->intf_id, &ifr6.ifr6_addr);
			ifr6.ifr6_prefixlen = a->prefix_len;

			if (ioctl(sock6_fd, SIOCSIFADDR, &ifr6))
				log_ppp_error("ppp: failed to add IPv6 address: %s\n", strerror(errno));
		}
	}

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr))
		log_ppp_error("ppp: failed to get interface flags: %s\n", strerror(errno));

	ifr.ifr_flags |= IFF_UP | IFF_POINTOPOINT;

	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr))
		log_ppp_error("ppp: failed to set interface flags: %s\n", strerror(errno));

	if (ppp->ses.ipv4) {
		np.protocol = PPP_IP;
		np.mode = NPMODE_PASS;

		if (ioctl(ppp->unit_fd, PPPIOCSNPMODE, &np))
			log_ppp_error("ppp: failed to set NP (IPv4) mode: %s\n", strerror(errno));
	}

	if (ppp->ses.ipv6) {
		np.protocol = PPP_IPV6;
		np.mode = NPMODE_PASS;

		if (ioctl(ppp->unit_fd, PPPIOCSNPMODE, &np))
			log_ppp_error("ppp: failed to set NP (IPv6) mode: %s\n", strerror(errno));
	}

	ppp->ses.ctrl->started(ppp);

	triton_event_fire(EV_SES_STARTED, ppp);
}

void __export ppp_ifdown(struct ppp_t *ppp)
{
	struct ifreq ifr;
	struct sockaddr_in addr;
	struct in6_ifreq ifr6;
	struct ipv6db_addr_t *a;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ppp->ifname);
	ioctl(sock_fd, SIOCSIFFLAGS, &ifr);

	if (ppp->ses.ipv4) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		memcpy(&ifr.ifr_addr,&addr,sizeof(addr));
		ioctl(sock_fd, SIOCSIFADDR, &ifr);
	}

	if (ppp->ses.ipv6) {
		memset(&ifr6, 0, sizeof(ifr6));
		ifr6.ifr6_addr.s6_addr32[0] = htons(0xfe80);
		*(uint64_t *)(ifr6.ifr6_addr.s6_addr + 8) = ppp->ses.ipv6->intf_id;
		ifr6.ifr6_prefixlen = 64;
		ifr6.ifr6_ifindex = ppp->ifindex;

		ioctl(sock6_fd, SIOCDIFADDR, &ifr6);

		list_for_each_entry(a, &ppp->ses.ipv6->addr_list, entry) {
			if (a->prefix_len == 128)
				continue;

			build_addr(a, ppp->ses.ipv6->intf_id, &ifr6.ifr6_addr);
			ifr6.ifr6_prefixlen = a->prefix_len;

			ioctl(sock6_fd, SIOCDIFADDR, &ifr6);
		}
	}
}

