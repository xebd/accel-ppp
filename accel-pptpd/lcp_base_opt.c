#include "ppp_lcp.h"

static struct lcp_option_t *mru_init(struct ppp_lcp_t *lcp);
static void mru_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int mru_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);

struct mru_option_t
{
	struct lcp_option_t opt;
	int mru;
	int mtu;
};

static struct lcp_option_handler_t opt_mru=
{
	.id=CI_MRU,
	.init=mru_init,
	.send_conf_req=mru_send_conf_req,
	.send_conf_nak=mru_send_conf_nak,
	.recv_conf_req=mru_recv_conf_req,
	.free=mru_free,
};

static struct lcp_option_t *mru_init(struct ppp_lcp_t *lcp)
{
	struct mru_option_t *mru_opt=malloc(sizeof(*mru_opt));
	memset(mru_opt,0,sizeof(*mru_opt));
	mru_opt->mtu=0;
	mru_opt->mru=1500;
	mru_opt->opt.len=4;

	return &mru_opt->opt;
}

static void mru_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct mru_option_t *mru_opt=container_of(opt,typeof(*mru_opt),opt);

	free(mru_opt);
}

static int mru_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt=container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;
	opt16->hdr.type=CI_MRU;
	opt16->hdr.len=4;
	opt16->val=htons(mru_opt->mru);
	return 4;
}

static int mru_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt=container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;
	opt16->hdr.type=CI_MRU;
	opt16->hdr.len=4;
	opt16->val=htons(mru_opt->mtu);
	return 4;
}

static int mru_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt=container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;

	if (!mru_opt->mtu || mru_opt->mtu==ntohs(opt16->val))
	{
		mru_opt->mtu=ntohs(opt16->val);
		return LCP_OPT_ACK;
	}else return LCP_OPT_NAK;
}

