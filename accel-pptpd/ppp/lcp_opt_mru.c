#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ppp.h>
#include <sys/ioctl.h>

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"

#define MAX_MTU 1436

static struct lcp_option_t *mru_init(struct ppp_lcp_t *lcp);
static void mru_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int mru_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int mru_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void mru_print(void (*print)(const char *fmt,...),struct lcp_option_t*, uint8_t *ptr);

struct mru_option_t
{
	struct lcp_option_t opt;
	int mru;
	int mtu;
};

static struct lcp_option_handler_t mru_opt_hnd=
{
	.init=mru_init,
	.send_conf_req=mru_send_conf_req,
	.send_conf_nak=mru_send_conf_nak,
	.recv_conf_req=mru_recv_conf_req,
	.recv_conf_ack=mru_recv_conf_ack,
	.free=mru_free,
	.print=mru_print,
};

static struct lcp_option_t *mru_init(struct ppp_lcp_t *lcp)
{
	struct mru_option_t *mru_opt=malloc(sizeof(*mru_opt));
	memset(mru_opt,0,sizeof(*mru_opt));
	mru_opt->mtu=0;
	mru_opt->mru=MAX_MTU;
	mru_opt->opt.id=CI_MRU;
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
	opt16->hdr.id=CI_MRU;
	opt16->hdr.len=4;
	opt16->val=htons(mru_opt->mru);
	return 4;
}

static int mru_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt=container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;
	opt16->hdr.id=CI_MRU;
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

static int mru_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt,typeof(*mru_opt), opt);
	struct ifreq ifr = {
		.ifr_mtu = mru_opt->mtu,
	};

	sprintf(ifr.ifr_name,"ppp%i",lcp->ppp->unit_idx);

	if (ioctl(lcp->ppp->unit_fd, PPPIOCSMRU, &mru_opt->mru))
		log_error("\nlcp:mru: failed to set MRU: %s\n", strerror(errno));

	if (ioctl(sock_fd, SIOCSIFMTU, &ifr))
		log_error("\nlcp:mru: failed to set MTU: %s\n", strerror(errno));
	
	return 0;
}

static void mru_print(void (*print)(const char *fmt,...),struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt=container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;

	if (ptr) print("<mru %i>",ntohs(opt16->val));
	else print("<mru %i>",mru_opt->mru);
}

static void __init mru_opt_init()
{
	lcp_option_register(&mru_opt_hnd);
}

