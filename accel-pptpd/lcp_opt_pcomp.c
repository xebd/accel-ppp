#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"

static struct lcp_option_t *pcomp_init(struct ppp_lcp_t *lcp);
static void pcomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int pcomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int pcomp_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int pcomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void pcomp_print(void (*print)(const char *fmt,...),struct lcp_option_t*, uint8_t *ptr);

struct pcomp_option_t
{
	struct lcp_option_t opt;
	int pcomp; // 0 - disabled, 1 - enabled, 2 - allow,disabled, 3 - allow,enabled
};

static struct lcp_option_handler_t pcomp_opt_hnd=
{
	.init=pcomp_init,
	.send_conf_req=pcomp_send_conf_req,
	.send_conf_nak=pcomp_send_conf_nak,
	.recv_conf_req=pcomp_recv_conf_req,
	.free=pcomp_free,
	.print=pcomp_print,
};

static struct lcp_option_t *pcomp_init(struct ppp_lcp_t *lcp)
{
	struct pcomp_option_t *pcomp_opt=malloc(sizeof(*pcomp_opt));
	memset(pcomp_opt,0,sizeof(*pcomp_opt));
	pcomp_opt->pcomp=2;
	pcomp_opt->opt.id=CI_PCOMP;
	pcomp_opt->opt.len=2;

	return &pcomp_opt->opt;
}

static void pcomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct pcomp_option_t *pcomp_opt=container_of(opt,typeof(*pcomp_opt),opt);

	free(pcomp_opt);
}

static int pcomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt=container_of(opt,typeof(*pcomp_opt),opt);
	struct lcp_opt_hdr_t *opt0=(struct lcp_opt_hdr_t*)ptr;
	if (pcomp_opt->pcomp==1 || pcomp_opt->pcomp==3)
	{
		opt0->id=CI_PCOMP;
		opt0->len=2;
		return 2;
	}
	return 0;
}

static int pcomp_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt=container_of(opt,typeof(*pcomp_opt),opt);
	struct lcp_opt_hdr_t *opt0=(struct lcp_opt_hdr_t*)ptr;
	opt0->id=CI_PCOMP;
	opt0->len=2;
	return 2;
}

static int pcomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct pcomp_option_t *pcomp_opt=container_of(opt,typeof(*pcomp_opt),opt);

	if (pcomp_opt->pcomp>0)
	{
		pcomp_opt->pcomp=1;
		return LCP_OPT_ACK;
	}else return LCP_OPT_NAK;
}

static void pcomp_print(void (*print)(const char *fmt,...),struct lcp_option_t *opt, uint8_t *ptr)
{
	print("<pcomp>");
}

static void __init pcomp_opt_init()
{
	lcp_option_register(&pcomp_opt_hnd);
}

