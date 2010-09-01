#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_ipcp.h"
#include "log.h"
#include "ipdb.h"

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
	in_addr_t addr;
	in_addr_t peer_addr;
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
	struct ipaddr_option_t *ipaddr_opt=malloc(sizeof(*ipaddr_opt));
	memset(ipaddr_opt,0,sizeof(*ipaddr_opt));
	ipdb_get(&ipaddr_opt->addr,&ipaddr_opt->peer_addr);
	ipaddr_opt->opt.id=CI_ADDR;
	ipaddr_opt->opt.len=6;

	return &ipaddr_opt->opt;
}

static void ipaddr_free(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);

	free(ipaddr_opt);
}

static int ipaddr_send_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;
	opt32->hdr.id=CI_ADDR;
	opt32->hdr.len=6;
	opt32->val=ipaddr_opt->addr;
	return 6;
}

static int ipaddr_send_conf_nak(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;
	opt32->hdr.id=CI_ADDR;
	opt32->hdr.len=6;
	opt32->val=ipaddr_opt->peer_addr;
	return 6;
}

static int ipaddr_recv_conf_req(struct ppp_ipcp_t *ipcp, struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;

	if (ipaddr_opt->peer_addr==opt32->val)
		return IPCP_OPT_ACK;
		
	if (!ipaddr_opt->peer_addr)
	{
		ipaddr_opt->peer_addr=opt32->val;
		return IPCP_OPT_ACK;
	}
	
	return IPCP_OPT_NAK;
}

static void ipaddr_print(void (*print)(const char *fmt,...),struct ipcp_option_t *opt, uint8_t *ptr)
{
	struct ipaddr_option_t *ipaddr_opt=container_of(opt,typeof(*ipaddr_opt),opt);
	struct ipcp_opt32_t *opt32=(struct ipcp_opt32_t*)ptr;
	struct in_addr in;

	if (ptr) in.s_addr=opt32->val;
	else in.s_addr=ipaddr_opt->addr;
	
	print("<addr %s>",inet_ntoa(in));
}

static void __init ipaddr_opt_init()
{
	ipcp_option_register(&ipaddr_opt_hnd);
}

