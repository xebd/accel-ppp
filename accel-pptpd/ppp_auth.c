#include "triton/triton.h"

#include "ppp.h"
#include "ppp_lcp.h"
#include "ppp_fsm.h"
#include "ppp_auth.h"

static LIST_HEAD(drv_list);

int auth_register(struct auth_driver_t *new)
{
	struct auth_driver_t *drv;

	list_for_each_entry(drv,&drv_list,entry)
	{
		if (drv->type==new->type)
			return -1;
	}
	list_add_tail(&new->entry,&drv_list);
	return 0;
}

int auth_get_conf_req(struct ppp_layer_t *l, struct lcp_opt32_t *opt)
{
	int i,n;
	struct auth_driver_t *drv;

	for(i=0; i<AUTH_MAX; i++)
	{
		if (l->auth[i] && l->options.lcp.neg_auth[i]>0)
			goto cont;
	}
	for(i=0; i<AUTH_MAX; i++)
	{
		if (l->auth[i] && l->options.lcp.neg_auth[i]==0)
			goto cont;
	}
	return -1;

cont:
	list_for_each_entry(drv,&drv_list,entry)
	{
		if (drv->type==l->auth[i])
			break;
	}
	n=drv->get_conf_req(drv,l,opt);
	opt->val=l->auth[i];
	opt->hdr.len=6+n;
	return 0;
}
int auth_recv_conf_req(struct ppp_layer_t *l, struct lcp_opt_hdr_t *hdr)
{
	struct lcp_opt32_t *opt=(struct lcp_opt32_t*)hdr;
	struct auth_driver_t *drv;
	int i;

	for(i=0; i<AUTH_MAX; i++)
	{
		if (l->auth[i]==opt->val)
		{
			list_for_each_entry(drv,&drv_list,entry)
			{
				if (drv->type==l->auth[i])
				{
					if (drv->recv_conf_req(drv,l,opt))
						return -1;
					l->options.lcp.neg_auth[i]=1;
					return 0;
				}
			}
			return -1;
		}
	}
	return -1;
}
int auth_recv_conf_rej(struct ppp_layer_t *l, struct lcp_opt_hdr_t *hdr)
{
	struct lcp_opt32_t *opt=(struct lcp_opt32_t*)hdr;
	int i;

	for(i=0; i<AUTH_MAX; i++)
	{
		if (l->auth[i]==opt->val)
		{
			l->options.lcp.neg_auth[i]=-1;
			break;
		}
	}
	for(i=0; i<3; i++)
	{
		if (l->auth[i] && l->options.lcp.neg_auth[i]!=-1)
			return 0;
	}
	return -1;
}
int auth_recv_conf_nak(struct ppp_layer_t *l, struct lcp_opt_hdr_t *hdr)
{
	struct lcp_opt32_t *opt=(struct lcp_opt32_t*)hdr;
	int i;

	for(i=0; i<AUTH_MAX; i++)
	{
		if (l->auth[i]==opt->val)
		{
			l->options.lcp.neg_auth[i]=2;
			return 0;
		}
	}
	return -1;
}

