#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "ppp.h"
#include "ppp_lcp.h"
#include "log.h"

#include "ppp_auth.h"


static LIST_HEAD(auth_handlers);
static int extra_opt_len=0;

static struct lcp_option_t *auth_init(struct ppp_lcp_t *lcp);
static void auth_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt);
static int auth_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static int auth_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr);
static void auth_print(void (*print)(const char *fmt,...),struct lcp_option_t*, uint8_t *ptr);

struct auth_option_t
{
	struct lcp_option_t opt;
	struct list_head auth_list;
	struct auth_data_t *auth;
	struct auth_data_t *peer_auth;
};

static struct lcp_option_handler_t auth_opt_hnd=
{
	.init=auth_init,
	.send_conf_req=auth_send_conf_req,
	.send_conf_nak=auth_send_conf_req,
	.recv_conf_req=auth_recv_conf_req,
	.recv_conf_nak=auth_recv_conf_nak,
	.recv_conf_rej=auth_recv_conf_rej,
	.recv_conf_ack=auth_recv_conf_ack,
	.free=auth_free,
	.print=auth_print,
};

static struct lcp_option_t *auth_init(struct ppp_lcp_t *lcp)
{
	struct ppp_auth_handler_t *h;
	struct auth_data_t *d;
	struct auth_option_t *auth_opt=malloc(sizeof(*auth_opt));
	memset(auth_opt,0,sizeof(*auth_opt));
	auth_opt->opt.id=CI_AUTH;
	auth_opt->opt.len=4+extra_opt_len;

	INIT_LIST_HEAD(&auth_opt->auth_list);

	list_for_each_entry(h,&auth_handlers,entry)
	{
		d=h->init(lcp->ppp);
		d->h=h;
		list_add_tail(&d->entry,&auth_opt->auth_list);
	}

	return &auth_opt->opt;
}

static void auth_free(struct ppp_lcp_t *lcp, struct lcp_option_t *opt)
{
	struct auth_option_t *auth_opt=container_of(opt,typeof(*auth_opt),opt);
	struct auth_data_t *d;

	while(!list_empty(&auth_opt->auth_list))
	{
		d=list_entry(auth_opt->auth_list.next,typeof(*d),entry);
		list_del(&d->entry);
		d->h->free(lcp->ppp,d);
	}

	free(auth_opt);
}

static int auth_send_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt=container_of(opt,typeof(*auth_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;
	struct auth_data_t *d;
	int n;

	if (list_empty(&auth_opt->auth_list)) return 0;

	if (!auth_opt->auth)
	{
		d=list_entry(auth_opt->auth_list.next,typeof(*d),entry);
		auth_opt->auth=d;
	}

	opt16->hdr.id=CI_AUTH;
	opt16->val=htons(auth_opt->auth->proto);
	n=auth_opt->auth->h->send_conf_req(lcp->ppp,auth_opt->auth,(uint8_t*)(opt16+1));
	opt16->hdr.len=4+n;

	return 4+n;
}

static int auth_recv_conf_req(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt=container_of(opt,typeof(*auth_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;
	struct auth_data_t *d;

	if (list_empty(&auth_opt->auth_list))
		return LCP_OPT_REJ;

	list_for_each_entry(d,&auth_opt->auth_list,entry)
	{
		if (d->proto==ntohs(opt16->val))
		{
			if (d->h->recv_conf_req(lcp->ppp,d,(uint8_t*)(opt16+1)))
				break;
			auth_opt->peer_auth=d;
			return LCP_OPT_ACK;
		}
	}
		
	list_for_each_entry(d,&auth_opt->auth_list,entry)
	{
		if (d->state!=LCP_OPT_NAK)
		{
			auth_opt->peer_auth=d;
			return LCP_OPT_NAK;
		}
	}

	log_msg("cann't negotiate authentication type\n");
	return LCP_OPT_FAIL;
}

static int auth_recv_conf_ack(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt=container_of(opt,typeof(*auth_opt),opt);

	auth_opt->peer_auth=NULL;

	return 0;
}

static int auth_recv_conf_nak(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt=container_of(opt,typeof(*auth_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;
	struct auth_data_t *d;

	list_for_each_entry(d,&auth_opt->auth_list,entry)
	{
		if (d->proto==ntohs(opt16->val))
		{
			d->state=LCP_OPT_NAK;
			if (d->h->recv_conf_req(lcp->ppp,d,(uint8_t*)(opt16+1)))
				break;
			auth_opt->auth=d;
			return 0;
		}
	}
	
	list_for_each_entry(d,&auth_opt->auth_list,entry)
	{
		if (d->state!=LCP_OPT_NAK)
			return 0;
	}

	log_msg("cann't negotiate authentication type\n");
	return -1;
}

static int auth_recv_conf_rej(struct ppp_lcp_t *lcp, struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt=container_of(opt,typeof(*auth_opt),opt);

	if (list_empty(&auth_opt->auth_list))
		return 0;

	log_msg("cann't negotiate authentication type\n");
	return -1;
}

static void auth_print(void (*print)(const char *fmt,...),struct lcp_option_t *opt, uint8_t *ptr)
{
	struct auth_option_t *auth_opt=container_of(opt,typeof(*auth_opt),opt);
	struct lcp_opt16_t *opt16=(struct lcp_opt16_t*)ptr;
	struct auth_data_t *d;

	if (ptr)
	{
		list_for_each_entry(d,&auth_opt->auth_list,entry)
		{
			if (d->proto==ntohs(opt16->val))
				goto print_d;
		}

		print("<auth %02x>",ntohs(opt16->val));
		return;
	}
	else if (auth_opt->auth) d=auth_opt->auth;
	else return;

print_d:
	print("<auth %s>",d->h->name);
}

int ppp_auth_register_handler(struct ppp_auth_handler_t *h)
{
	list_add_tail(&h->entry,&auth_handlers);
	return 0;
}

static void __init auth_opt_init()
{
	lcp_option_register(&auth_opt_hnd);
}








int auth_start(struct ppp_t *ppp)
{
	struct lcp_option_t *opt;
	struct auth_option_t *auth_opt;

	list_for_each_entry(opt,&ppp->lcp->options,entry)
	{
		if (opt->id==CI_AUTH)
		{
			auth_opt=container_of(opt,typeof(*auth_opt),opt);
			if (auth_opt->auth)
			{
				auth_opt->auth->h->start(ppp,auth_opt->auth);
				return 1;
			}
			break;
		}
	}

	return 0;
}

void auth_finish(struct ppp_t *ppp)
{
	struct lcp_option_t *opt;
	struct auth_option_t *auth_opt;

	list_for_each_entry(opt,&ppp->lcp->options,entry)
	{
		if (opt->id==CI_AUTH)
		{
			auth_opt=container_of(opt,typeof(*auth_opt),opt);
			if (auth_opt->auth)
				auth_opt->auth->h->finish(ppp,auth_opt->auth);
			break;
		}
	}
}

void auth_successed(struct ppp_t *ppp)
{
	ppp_layer_started(ppp);
}

void auth_failed(struct ppp_t *ppp)
{
	ppp_terminate(ppp);
}

