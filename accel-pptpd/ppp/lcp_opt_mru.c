#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ppp.h>
#include <sys/ioctl.h>

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"

#include "memdebug.h"

static int conf_mtu;
static int conf_min_mtu = 100;

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
	struct mru_option_t *mru_opt=_malloc(sizeof(*mru_opt));
	memset(mru_opt, 0, sizeof(*mru_opt));
	mru_opt->mtu = 0;
	mru_opt->mru = (conf_mtu && conf_mtu <= lcp->ppp->ctrl->max_mtu) ? conf_mtu : lcp->ppp->ctrl->max_mtu;
	mru_opt->opt.id = CI_MRU;
	mru_opt->opt.len = 4;

	return &mru_opt->opt;
}

static void mru_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);

	_free(mru_opt);
}

static int mru_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;
	opt16->hdr.id = CI_MRU;
	opt16->hdr.len = 4;
	opt16->val = htons(mru_opt->mru);
	return 4;
}

static int mru_send_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;
	opt16->hdr.id = CI_MRU;
	opt16->hdr.len = 4;
	opt16->val = htons(mru_opt->mtu ? mru_opt->mtu : lcp->ppp->ctrl->max_mtu);
	return 4;
}

static int mru_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt,typeof(*mru_opt),opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;

	if (!ptr)
		return LCP_OPT_NAK;

	if (ntohs(opt16->val) < conf_min_mtu || ntohs(opt16->val) > lcp->ppp->ctrl->max_mtu)
		return LCP_OPT_NAK;

	mru_opt->mtu = ntohs(opt16->val);
	return LCP_OPT_ACK;
}

static int mru_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt,typeof(*mru_opt), opt);
	struct ifreq ifr = {
		.ifr_mtu = mru_opt->mtu,
	};

	strcpy(ifr.ifr_name, lcp->ppp->ifname);

	if (ioctl(lcp->ppp->unit_fd, PPPIOCSMRU, &mru_opt->mru))
		log_ppp_error("lcp:mru: failed to set MRU: %s\n", strerror(errno));

	if (ioctl(sock_fd, SIOCSIFMTU, &ifr))
		log_ppp_error("lcp:mru: failed to set MTU: %s\n", strerror(errno));
	
	return 0;
}

static void mru_print(void (*print)(const char *fmt,...), struct lcp_option_t *opt, uint8_t *ptr)
{
	struct mru_option_t *mru_opt = container_of(opt, typeof(*mru_opt), opt);
	struct lcp_opt16_t *opt16 = (struct lcp_opt16_t*)ptr;

	if (ptr)
		print("<mru %i>",ntohs(opt16->val));
	else
		print("<mru %i>",mru_opt->mru);
}

static void __init mru_opt_init()
{
	char *opt;

	opt = conf_get_opt("ppp", "mtu");
	if (opt && atoi(opt) > 0)
		conf_mtu = atoi(opt);

	opt = conf_get_opt("ppp", "min-mtu");
	if (opt && atoi(opt) > 0)
		conf_min_mtu = atoi(opt);

	lcp_option_register(&mru_opt_hnd);
}

