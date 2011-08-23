#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "log.h"
#include "ppp.h"
#include "events.h"

#include "memdebug.h"

static int conf_init_ra = 3;
static int conf_init_ra_interval = 1;
static int conf_ra_interval = 60;

struct ipv6_nd_handler_t
{
	struct ppp_t *ppp;
	struct ppp_pd_t pd;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timer;
	int ra_sent;
};

static void *pd_key;

#define BUF_SIZE 1024

static void ipv6_nd_send_ra(struct ipv6_nd_handler_t *h)
{
	void *buf = _malloc(BUF_SIZE);
	struct nd_router_advert *adv = buf;
	struct nd_opt_prefix_info *pinfo;
	//struct nd_opt_route_info *rinfo;
	//struct nd_opt_rdnss_info_local *rdnssinfo;
	//struct nd_opt_mtu *mtu;
	struct sockaddr_in6 addr;

	memset(adv, 0, sizeof(*adv));
	adv->nd_ra_type = ND_ROUTER_ADVERT;
	adv->nd_ra_curhoplimit = 64;
	adv->nd_ra_router_lifetime = htons(1);
	//adv->nd_ra_reachable = 0;
	//adv->nd_ra_retransmit = 0;
	
	pinfo = (struct nd_opt_prefix_info *)(adv + 1);
	memset(pinfo, 0, sizeof(*pinfo));
	pinfo->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
	pinfo->nd_opt_pi_len = 4;
	pinfo->nd_opt_pi_prefix_len = h->ppp->ipv6_prefix_len;
	pinfo->nd_opt_pi_flags_reserved = ND_OPT_PI_FLAG_ONLINK | ND_OPT_PI_FLAG_AUTO;
	pinfo->nd_opt_pi_valid_time = 0xffffffff;
	pinfo->nd_opt_pi_preferred_time = 0xffffffff;
	memcpy(&pinfo->nd_opt_pi_prefix, &h->ppp->ipv6_addr, 8);

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr.s6_addr32[0] = htonl(0xff020000);
	addr.sin6_addr.s6_addr32[3] = htonl(0x1);
	addr.sin6_scope_id = h->ppp->ifindex; 

	sendto(h->hnd.fd, buf, (void *)(pinfo + 1) - buf, 0, (struct sockaddr *)&addr, sizeof(addr));

	_free(buf);
}

static void send_ra_timer(struct triton_timer_t *t)
{
	struct ipv6_nd_handler_t *h = container_of(t, typeof(*h), timer);

	if (h->ra_sent++ == conf_init_ra) {
		h->timer.period = conf_ra_interval * 1000;
		triton_timer_mod(t, 0);
	}

	ipv6_nd_send_ra(h);
}

static int ipv6_nd_read(struct triton_md_handler_t *_h)
{
	struct ipv6_nd_handler_t *h = container_of(_h, typeof(*h), hnd);
	struct msghdr mhdr;
	int chdr_len;
	struct iovec iov;
	struct cmsghdr *chdr, *cmsg;
	struct in6_pktinfo *pkt_info;
	struct icmp6_hdr *icmph;
	void *buf;
	int n;

	chdr_len = CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int));
	chdr = _malloc(chdr_len);
	buf = _malloc(BUF_SIZE);

	iov.iov_len = BUF_SIZE;
	iov.iov_base = buf;

	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = chdr;
	mhdr.msg_controllen = chdr_len;

	while (1) {
		n = recvmsg(h->hnd.fd, &mhdr, 0);
		if (n == -1) {
			if (errno == EAGAIN)
				break;
			log_ppp_error("ipv6_nd: recvmsg: %s\n", strerror(errno));
			continue;
		}

		pkt_info = NULL;
		for (cmsg = CMSG_FIRSTHDR(&mhdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&mhdr, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IPV6 &&
				  cmsg->cmsg_type == IPV6_PKTINFO) {
				if (cmsg->cmsg_len != CMSG_LEN(sizeof(*pkt_info)))
					log_ppp_warn("ipv6_nd: received invalid IPV6_PKTINFO\n");
				else
					pkt_info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
				break;
			}
		}

		if (!pkt_info) {
			log_ppp_warn("ipv6_nd: no IPV6_PKTINFO\n");
			continue;
		}

		if (n < sizeof(*icmph)) {
			log_ppp_warn("ipv6_nd: received short icmp packet (%i)\n", n);
			continue;
		}

		icmph = buf;

		if (icmph->icmp6_type != ND_ROUTER_SOLICIT) {
			log_ppp_warn("ipv6_nd: received unexcpected icmp packet (%i)\n", icmph->icmp6_type);
			continue;
		}

		/*if (!IN6_IS_ADDR_LINKLOCAL(&pkt_info->ipi6_addr)) {
			log_ppp_warn("ipv6_nd: received icmp packet from non link-local address\n");
			continue;
		}*/

		/*if (*(uint64_t *)(pkt_info->ipi6_addr.s6_addr + 8) != *(uint64_t *)(h->ppp->ipv6_addr.s6_addr + 8)) {
			log_ppp_warn("ipv6_nd: received icmp packet from unknown address\n");
			continue;
		}*/

		ipv6_nd_send_ra(h);
	}

	_free(chdr);
	_free(buf);

	return 0;
}

int ppp_ipv6_nd_start(struct ppp_t *ppp, uint64_t intf_id)
{
	int sock;
	struct icmp6_filter filter;
	struct sockaddr_in6 addr;
	struct ipv6_mreq mreq;
	int val;
	struct ipv6_nd_handler_t *h;

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	
	if (sock < 0) {
		log_ppp_error("socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6): %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr.s6_addr32[0] = htons(0xfe80);
	*(uint64_t *)(addr.sin6_addr.s6_addr + 8) = intf_id;
	addr.sin6_scope_id = ppp->ifindex;

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		log_ppp_error("ipv6_nd: bind: %s %i\n", strerror(errno), errno);
		goto out_err;
	}

	val = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_PKTINFO): %s\n", strerror(errno));
		goto out_err;
	}

	val = 2;
	if (setsockopt(sock, IPPROTO_RAW, IPV6_CHECKSUM, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_CHECKSUM): %s\n", strerror(errno));
		goto out_err;
	}

	val = 255;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_UNICAST_HOPS): %s\n", strerror(errno));
		goto out_err;
	}
	
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_MULTICAST_HOPS): %s\n", strerror(errno));
		goto out_err;
	}

	/*val = 1;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &val, sizeof(val))) {
		log_ppp_error("ipv6_nd: setsockopt(IPV6_HOPLIMIT): %s\n", strerror(errno));
		goto out_err;
	}*/

	ICMP6_FILTER_SETBLOCKALL(&filter);
	ICMP6_FILTER_SETPASS(ND_ROUTER_SOLICIT, &filter);

	if (setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter))) {
		log_ppp_error("ipv6_nd: setsockopt(ICMP6_FILTER): %s\n", strerror(errno));
		goto out_err;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.ipv6mr_interface = ppp->ifindex;
	mreq.ipv6mr_multiaddr.s6_addr32[0] = htonl(0xff020000);
	mreq.ipv6mr_multiaddr.s6_addr32[3] = htonl(0x2);

	if (setsockopt(sock, SOL_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		log_ppp_error("ipv6_nd: failed to join ipv6 allrouters\n");
		goto out_err;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);

	h = _malloc(sizeof(*h));
	memset(h, 0, sizeof(*h));
	h->ppp = ppp;
	h->pd.key = &pd_key;
	h->hnd.fd = sock;
	h->hnd.read = ipv6_nd_read;
	h->timer.expire = send_ra_timer;
	h->timer.period = conf_init_ra_interval * 1000;
	list_add_tail(&h->pd.entry, &ppp->pd_list);

	triton_md_register_handler(ppp->ctrl->ctx, &h->hnd);
	triton_md_enable_handler(&h->hnd, MD_MODE_READ);

	return 0;

out_err:
	close(sock);
	return -1;
}

static struct ipv6_nd_handler_t *find_pd(struct ppp_t *ppp)
{
	struct ppp_pd_t *pd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &pd_key)
			return container_of(pd, typeof(struct ipv6_nd_handler_t), pd);
	}

	return NULL;
}

static void ev_ppp_started(struct ppp_t *ppp)
{
	struct ipv6_nd_handler_t *h = find_pd(ppp);

	if (!h)
		return;
	
	triton_timer_add(ppp->ctrl->ctx, &h->timer, 0);
}

static void ev_ppp_finishing(struct ppp_t *ppp)
{
	struct ipv6_nd_handler_t *h = find_pd(ppp);

	if (!h)
		return;
	
	triton_timer_del(&h->timer);
	triton_md_unregister_handler(&h->hnd);
	close(h->hnd.fd);

	list_del(&h->pd.entry);
	
	_free(h);
}

static void init(void)
{
	triton_event_register_handler(EV_PPP_STARTED, (triton_event_func)ev_ppp_started);
	triton_event_register_handler(EV_PPP_FINISHING, (triton_event_func)ev_ppp_finishing);
}

DEFINE_INIT(0, init);
