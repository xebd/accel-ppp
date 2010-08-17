#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"

static struct lcp_option_t *magic_init(struct ppp_lcp_t *lcp);
static void magic_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int magic_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int magic_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void magic_print(void (*print)(const char *fmt,...),struct lcp_option_t*, uint8_t *ptr);

struct magic_option_t
{
	struct lcp_option_t opt;
	int magic;
};

static struct lcp_option_handler_t magic_opt_hnd=
{
	.init=magic_init,
	.send_conf_req=magic_send_conf_req,
	.recv_conf_req=magic_recv_conf_req,
	.free=magic_free,
	.print=magic_print,
};

static struct lcp_option_t *magic_init(struct ppp_lcp_t *lcp)
{
	struct magic_option_t *magic_opt=malloc(sizeof(*magic_opt));
	memset(magic_opt,0,sizeof(*magic_opt));
	magic_opt->magic=random();
	magic_opt->opt.id=CI_MAGIC;
	magic_opt->opt.len=6;

	return &magic_opt->opt;
}

static void magic_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct magic_option_t *magic_opt=container_of(opt,typeof(*magic_opt),opt);

	free(magic_opt);
}

static int magic_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt=container_of(opt,typeof(*magic_opt),opt);
	struct lcp_opt32_t *opt32=(struct lcp_opt32_t*)ptr;
	opt32->hdr.id=CI_MAGIC;
	opt32->hdr.len=6;
	opt32->val=htonl(magic_opt->magic);
	return 6;
}

static int magic_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt=container_of(opt,typeof(*magic_opt),opt);
	struct lcp_opt32_t *opt32=(struct lcp_opt32_t*)ptr;

	if (magic_opt->magic==ntohl(opt32->val))
	{
		log_error("loop detected");
		return -1;
	}
	return LCP_OPT_ACK;
}

static void magic_print(void (*print)(const char *fmt,...),struct lcp_option_t *opt, uint8_t *ptr)
{
	struct magic_option_t *magic_opt=container_of(opt,typeof(*magic_opt),opt);

	print("<magic %04x>",magic_opt->magic);
}

static void __init magic_opt_init()
{
	lcp_option_register(&magic_opt_hnd);
}
