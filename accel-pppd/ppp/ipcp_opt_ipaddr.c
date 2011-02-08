#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "ppp.h"
#include "ppp_ipcp.h"
#include "log.h"
#include "ipdb.h"
#include "iprange.h"
#include "events.h"

#include "memdebug.h"

static int conf_check_exists;

static struct ipcp_option_t *ipaddr_init(struct ppp_ipcp_t *ipcp);
static void ipaddr_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt);
static int ipaddr_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int ipaddr_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static int ipaddr_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
//static int ipaddr_recv_conf_ack(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr);
static void ipaddr_print(void (*print)(const char *fmt,...),struct ipcp_option_t*, uint8_t *ptr);

struct ipaddr_option_t
{
	struct ipcp_option_t opt;
	struct ipv4db_item_t *ip;
	int started:1;
};

static struct ipcp_option_handler_t ipaddr_opt_hnd=
{
	.init=ipaddr_init,
	.send_conf_req=ipaddr_send_conf_req,
	.send_conf_nak=ipaddr_send_conf_nak,
	.recv_conf_req=ipaddr_recv_conf_req,
	.free=ipaddr_free,
	.print=ipaddr_print,
};

static struct ipcp_option_t *ipaddr_init(struct ppp_ipcp_t *ipcp)
{
	struct ipaddr_option_t *ipaddr_opt=_malloc(sizeof(*ipaddr_opt));
	memset(ipaddr_opt,0,sizeof(*ipaddr_opt));
	ipaddr_opt->opt.id=CI_ADDR;
	ipaddr_opt->opt.len=6;

	return &ipaddr_opt->opt;
}

static void ipaddr_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);

	if (ipaddr_opt->ip)
		ipdb_put_ipv4(ipcp->ppp, ipaddr_opt->ip);

	_free(ipaddr_opt);
}

static int check_exists(struct ppp_t *self_ppp, in_addr_t addr)
{
	struct ppp_t *ppp;
	int r = 0;

	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		if (!ppp->terminating && ppp->peer_ipaddr == addr && ppp != self_ppp) {
			log_ppp_warn("ppp:ipcp: requested IP already assigned to %s\n", ppp->ifname);
			r = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&ppp_lock);

	return r;
}

static int ipaddr_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;
	
	if (!ipaddr_opt->ip) {
		ipaddr_opt->ip = ipdb_get_ipv4(ipcp->ppp);
		if (!ipaddr_opt->ip) {
			log_ppp_warn("ppp:ipcp: no free IP address\n");
			return -1;
		}
	}
	
	if (iprange_tunnel_check(ipaddr_opt->ip->peer_addr)) {
		log_ppp_warn("ppp:ipcp: to avoid kernel soft lockup requested IP cannot be assigned (%i.%i.%i.%i)\n",
			ipaddr_opt->ip->peer_addr&0xff, 
			(ipaddr_opt->ip->peer_addr >> 8)&0xff, 
			(ipaddr_opt->ip->peer_addr >> 16)&0xff, 
			(ipaddr_opt->ip->peer_addr >> 24)&0xff);
		return -1;
	}
	
	if (conf_check_exists && check_exists(ipcp->ppp, ipaddr_opt->ip->peer_addr))
		return -1;
	
	opt32->hdr.id=CI_ADDR;
	opt32->hdr.len=6;
	opt32->val=ipaddr_opt->ip->addr;
	return 6;
}

static int ipaddr_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;
	opt32->hdr.id=CI_ADDR;
	opt32->hdr.len=6;
	opt32->val=ipaddr_opt->ip->peer_addr;
	return 6;
}

static int ipaddr_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt,typeof(*ipaddr_opt), opt);
	struct ipcp_opt32_t *opt32 = (struct ipcp_opt32_t*)ptr;
	struct ifreq ifr;
	struct sockaddr_in addr;
	struct npioctl np;

	if (opt32->hdr.len != 6)
		return IPCP_OPT_REJ;

	if (ipaddr_opt->ip->peer_addr == opt32->val)
		goto ack;
		
	/*if (!ipaddr_opt->peer_addr) {
		ipaddr_opt->peer_addr = opt32->val;
		goto ack;
	}*/
	
	return IPCP_OPT_NAK;

ack:
	if (ipaddr_opt->started)
		return IPCP_OPT_ACK;
	
	ipaddr_opt->started = 1;

	ipcp->ppp->ipaddr = ipaddr_opt->ip->addr;
	ipcp->ppp->peer_ipaddr = ipaddr_opt->ip->peer_addr;

	triton_event_fire(EV_PPP_ACCT_START, ipcp->ppp);
	if (ipcp->ppp->stop_time)
		return IPCP_OPT_ACK;

	triton_event_fire(EV_PPP_PRE_UP, ipcp->ppp);
	if (ipcp->ppp->stop_time)
		return IPCP_OPT_ACK;

	memset(&ifr, 0, sizeof(ifr));
	memset(&addr, 0, sizeof(addr));

	strcpy(ifr.ifr_name, ipcp->ppp->ifname);

	addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ipaddr_opt->ip->addr;
	memcpy(&ifr.ifr_addr,&addr,sizeof(addr));

	if (ioctl(sock_fd, SIOCSIFADDR, &ifr))
		log_ppp_error("ipcp: failed to set PA address: %s\n", strerror(errno));
	
  addr.sin_addr.s_addr = ipaddr_opt->ip->peer_addr;
	memcpy(&ifr.ifr_dstaddr,&addr,sizeof(addr));
	
	if (ioctl(sock_fd, SIOCSIFDSTADDR, &ifr))
		log_ppp_error("ipcp: failed to set remote PA address: %s\n", strerror(errno));

	if (ioctl(sock_fd, SIOCGIFFLAGS, &ifr))
		log_ppp_error("ipcp: failed to get interface flags: %s\n", strerror(errno));

	ifr.ifr_flags |= IFF_UP | IFF_POINTOPOINT;

	if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr))
		log_ppp_error("ipcp: failed to set interface flags: %s\n", strerror(errno));

	np.protocol = PPP_IP;
	np.mode = NPMODE_PASS;

	if (ioctl(ipcp->ppp->unit_fd, PPPIOCSNPMODE, &np))
		log_ppp_error("ipcp: failed to set NP mode: %s\n", strerror(errno));

	return IPCP_OPT_ACK;
}

static void ipaddr_print(void (*print)(const char *fmt,...),struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;
	struct in_addr in = { .s_addr = 0, };

	if (ptr)
		in.s_addr = opt32->val;
	else if (ipaddr_opt->ip)
		in.s_addr = ipaddr_opt->ip->addr;
	
	print("<addr %s>",inet_ntoa(in));
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("ppp", "check-ip");
	if (opt && atoi(opt) > 0)
		conf_check_exists = 1;
}

static void __init ipaddr_opt_init()
{
	ipcp_option_register(&ipaddr_opt_hnd);
	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

