#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"

#include "memdebug.h"

static struct lcp_option_t *accomp_init(struct ppp_lcp_t *lcp);
static void accomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int accomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int accomp_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int accomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void accomp_print(void (*print)(const char *fmt,...),struct lcp_option_t*, uint8_t *ptr);

struct accomp_option_t
{
	struct lcp_option_t opt;
	int accomp; // 0 - disabled, 1 - enabled, 2 - allow,disabled, 3 - allow,enabled
};

static struct lcp_option_handler_t accomp_opt_hnd=
{
	.init=accomp_init,
	.send_conf_req=accomp_send_conf_req,
	.send_conf_nak=accomp_send_conf_nak,
	.recv_conf_req=accomp_recv_conf_req,
	.free=accomp_free,
	.print=accomp_print,
};

static struct lcp_option_t *accomp_init(struct ppp_lcp_t *lcp)
{
	struct accomp_option_t *accomp_opt=_malloc(sizeof(*accomp_opt));
	memset(accomp_opt,0,sizeof(*accomp_opt));
	accomp_opt->accomp=0;
	accomp_opt->opt.id=CI_ACCOMP;
	accomp_opt->opt.len=2;

	return &accomp_opt->opt;
}

static void accomp_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct accomp_option_t *accomp_opt=container_of(opt,typeof(*accomp_opt),opt);

	_free(accomp_opt);
}

static int accomp_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt=container_of(opt,typeof(*accomp_opt),opt);
	struct lcp_opt_hdr_t *opt0=(struct lcp_opt_hdr_t*)ptr;
	if (accomp_opt->accomp==1 || accomp_opt->accomp==3)
	{
		opt0->id=CI_ACCOMP;
		opt0->len=2;
		return 2;
	}
	return 0;
}

static int accomp_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt=container_of(opt,typeof(*accomp_opt),opt);
	struct lcp_opt_hdr_t *opt0=(struct lcp_opt_hdr_t*)ptr;
	opt0->id=CI_ACCOMP;
	opt0->len=2;
	return 2;
}

static int accomp_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct accomp_option_t *accomp_opt=container_of(opt,typeof(*accomp_opt),opt);

	if (accomp_opt->accomp>0)
	{
		accomp_opt->accomp=1;
		return LCP_OPT_ACK;
	}else return LCP_OPT_REJ;
}

static void accomp_print(void (*print)(const char *fmt,...),struct lcp_option_t *opt, uint8_t *ptr)
{
	print("<accomp>");
}

static void __init accomp_opt_init()
{
	lcp_option_register(&accomp_opt_hnd);
}

