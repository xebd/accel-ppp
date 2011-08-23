#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "linux_ppp.h"

#include "log.h"
#include "events.h"
#include "ppp.h"
#include "ppp_ipv6cp.h"
#include "ipdb.h"

#include "memdebug.h"

#define INTF_ID_FIXED  0
#define INTF_ID_RANDOM 1

static int conf_check_exists;
static int conf_intf_id = INTF_ID_FIXED;
static uint64_t conf_intf_id_val = 1;

// from /usr/include/linux/ipv6.h
struct in6_ifreq {
        struct in6_addr ifr6_addr;
        __u32           ifr6_prefixlen;
        int             ifr6_ifindex; 
};

static int urandom_fd;
static int sock6_fd;

static struct ipv6cp_option_t *ipaddr_init(struct ppp_ipv6cp_t *ipv6cp);
static void ipaddr_free(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt);
static int ipaddr_send_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
static int ipaddr_send_conf_nak(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
static int ipaddr_recv_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
//static int ipaddr_recv_conf_ack(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr);
static void ipaddr_print(void (*print)(const char *fmt,...),struct ipv6cp_option_t*, uint8_t *ptr);

struct ipaddr_option_t
{
	struct ipv6cp_option_t opt;
	uint64_t intf_id;
	struct ipv6db_item_t *ip;
	int started:1;
};

static struct ipv6cp_option_handler_t ipaddr_opt_hnd =
{
	.init          = ipaddr_init,
	.send_conf_req = ipaddr_send_conf_req,
	.send_conf_nak = ipaddr_send_conf_nak,
	.recv_conf_req = ipaddr_recv_conf_req,
	.free          = ipaddr_free,
	.print         = ipaddr_print,
};

static struct ipv6cp_option_t *ipaddr_init(struct ppp_ipv6cp_t *ipv6cp)
{
	struct ipaddr_option_t *ipaddr_opt = _malloc(sizeof(*ipaddr_opt));

	memset(ipaddr_opt, 0, sizeof(*ipaddr_opt));

	ipaddr_opt->opt.id = CI_INTFID;
	ipaddr_opt->opt.len = 10;

	switch (conf_intf_id) {
		case INTF_ID_FIXED:
			ipaddr_opt->intf_id = conf_intf_id_val;
			break;
		case INTF_ID_RANDOM:
			read(urandom_fd, &ipaddr_opt->intf_id, 8);
			break;
	}
	
	return &ipaddr_opt->opt;
}

static void ipaddr_free(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);

	_free(ipaddr_opt);
}

static int check_exists(struct ppp_t *self_ppp, struct in6_addr *addr)
{
	struct ppp_t *ppp;
	int r = 0;

	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		if (ppp->terminating)
			continue;
		if (ppp == self_ppp)
			continue;

		if (addr->s6_addr32[0] == ppp->ipv6_addr.s6_addr32[0] &&
			  addr->s6_addr32[1] == ppp->ipv6_addr.s6_addr32[1]) {
			log_ppp_warn("ppp:ipv6cp: requested IP already assigned to %s\n", ppp->ifname);
			r = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&ppp_lock);

	return r;
}

static int ipaddr_send_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t *)ptr;
	
	if (!ipaddr_opt->ip) {
		ipaddr_opt->ip = ipdb_get_ipv6(ipv6cp->ppp);
		if (!ipaddr_opt->ip) {
			log_ppp_warn("ppp:ipv6cp: no free IP address\n");
			return -1;
		}
	}
	
	if (conf_check_exists && check_exists(ipv6cp->ppp, &ipaddr_opt->ip->addr))
		return -1;
	
	ipv6cp->ppp->ipv6_addr = ipaddr_opt->ip->addr;
	ipv6cp->ppp->ipv6_prefix_len = ipaddr_opt->ip->prefix_len;
	
	opt64->hdr.id = CI_INTFID;
	opt64->hdr.len = 10;
	opt64->val = ipaddr_opt->intf_id;
	return 10;
}

static int ipaddr_send_conf_nak(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t *)ptr;
	opt64->hdr.id = CI_INTFID;
	opt64->hdr.len = 10;
	opt64->val = *(uint64_t *)(&ipaddr_opt->ip->addr.s6_addr32[2]);
	return 10;
}

static int ipaddr_recv_conf_req(struct ppp_ipv6cp_t *ipv6cp, struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t* )ptr;
	struct in6_ifreq ifr6;

	if (opt64->hdr.len != 10)
		return IPV6CP_OPT_REJ;

	if (*(uint64_t *)(&ipaddr_opt->ip->addr.s6_addr32[2]) == opt64->val)
		goto ack;
		
	return IPV6CP_OPT_NAK;

ack:
	if (ipaddr_opt->started)
		return IPV6CP_OPT_ACK;
	
	ipaddr_opt->started = 1;

	//ipv6cp->ppp->ipaddr = ipaddr_opt->ip->addr;
	//ipv6cp->ppp->peer_ipaddr = ipaddr_opt->ip->peer_addr;

	//triton_event_fire(EV_PPP_ACCT_START, ipv6cp->ppp);
	//if (ipv6cp->ppp->stop_time)
	//	return IPV6CP_OPT_ACK;

	//triton_event_fire(EV_PPP_PRE_UP, ipv6cp->ppp);
	//if (ipv6cp->ppp->stop_time)
	//	return IPV6CP_OPT_ACK;

	memset(&ifr6, 0, sizeof(ifr6));
	ifr6.ifr6_addr.s6_addr32[0] = htons(0xfe80);
	*(uint64_t *)(ifr6.ifr6_addr.s6_addr + 8) = ipaddr_opt->intf_id;
	ifr6.ifr6_prefixlen = 64;
	ifr6.ifr6_ifindex = ipv6cp->ppp->ifindex;

	if (ioctl(sock6_fd, SIOCSIFADDR, &ifr6)) {
		log_ppp_error("ppp:ipv6cp: ioctl(SIOCSIFADDR): %s\n", strerror(errno));
		return IPV6CP_OPT_REJ;
	}

	memcpy(ifr6.ifr6_addr.s6_addr, ipaddr_opt->ip->addr.s6_addr, 8);

	if (ioctl(sock6_fd, SIOCSIFADDR, &ifr6)) {
		log_ppp_error("ppp:ipv6cp: ioctl(SIOCSIFADDR): %s\n", strerror(errno));
		return IPV6CP_OPT_REJ;
	}

	if (ppp_ipv6_nd_start(ipv6cp->ppp, ipaddr_opt->intf_id))
		return IPV6CP_OPT_REJ;

	return IPV6CP_OPT_ACK;
}

static void ipaddr_print(void (*print)(const char *fmt,...), struct ipv6cp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt = container_of(opt, typeof(*ipaddr_opt), opt);
	struct ipv6cp_opt64_t *opt64 = (struct ipv6cp_opt64_t *)ptr;
	struct in6_addr a;

	if (ptr)
		*(uint64_t *)(a.s6_addr + 8) = opt64->val;
	else
		*(uint64_t *)(a.s6_addr + 8) = ipaddr_opt->intf_id;
	
	print("<addr %x:%x:%x:%x>", ntohs(a.s6_addr16[4]), ntohs(a.s6_addr16[5]), ntohs(a.s6_addr16[6]), ntohs(a.s6_addr16[7]));
}

static uint64_t parse_intfid(const char *opt)
{
	union {
		uint64_t u64;
		uint16_t u16[4];
	} u;

	int n[4];
	int i;

	if (sscanf(opt, "%x:%x:%x:%x", &n[0], &n[1], &n[2], &n[3]) != 4)
		goto err;
	
	for (i = 0; i < 4; i++) {
		if (n[i] < 0 || n[i] > 0xffff)
			goto err;
		u.u16[i] = htons(n[i]);
	}

	return u.u64;

err:
	log_error("ppp:ipv6cp: failed to parse ipv6-intf-id\n");
	conf_intf_id = INTF_ID_RANDOM;
	return 0;
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("ppp", "check-ip");
	if (opt && atoi(opt) > 0)
		conf_check_exists = 1;
	
	opt = conf_get_opt("ppp", "ipv6-intf-id");
	if (opt) {
		if (!strcmp(opt, "random"))
			conf_intf_id = INTF_ID_RANDOM;
		else {
			conf_intf_id = INTF_ID_FIXED;
			conf_intf_id_val = parse_intfid(opt);
		}
	}
}

static void init()
{
	sock6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!sock6_fd) {
		log_warn("ppp:ipv6cp: kernel doesn't support ipv6\n");
		return;
	}

	urandom_fd = open("/dev/urandom", O_RDONLY);

	ipv6cp_option_register(&ipaddr_opt_hnd);
	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(5, init);

