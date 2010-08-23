#include <stdlib.h>
#include <string.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <arpa/inet.h>

#include "triton/triton.h"

#include "log.h"

#include "ppp.h"
#include "ppp_ccp.h"

struct recv_opt_t
{
	struct list_head entry;
	struct ccp_opt_hdr_t *hdr;
	int len;
	int state;
	struct ccp_option_t *lopt;
};

static LIST_HEAD(option_handlers);

static void ccp_layer_up(struct ppp_fsm_t*);
static void ccp_layer_down(struct ppp_fsm_t*);
static void send_conf_req(struct ppp_fsm_t*);
static void send_conf_ack(struct ppp_fsm_t*);
static void send_conf_nak(struct ppp_fsm_t*);
static void send_conf_rej(struct ppp_fsm_t*);
static void ccp_recv(struct ppp_handler_t*);

static void ccp_options_init(struct ppp_ccp_t *ccp)
{
	struct ccp_option_t *lopt;
	struct ccp_option_handler_t *h;

	INIT_LIST_HEAD(&ccp->options);

	list_for_each_entry(h,&option_handlers,entry)
	{
		lopt=h->init(ccp);
		if (lopt)
		{
			lopt->h=h;
			list_add_tail(&lopt->entry,&ccp->options);
			ccp->conf_req_len+=lopt->len;
		}
	}
}

static void ccp_options_free(struct ppp_ccp_t *ccp)
{
	struct ccp_option_t *lopt;

	while(!list_empty(&ccp->options))
	{
		lopt=list_entry(ccp->options.next,typeof(*lopt),entry);
		list_del(&lopt->entry);
		lopt->h->free(ccp,lopt);
	}
}

static struct ppp_layer_data_t *ccp_layer_init(struct ppp_t *ppp)
{
	struct ppp_ccp_t *ccp=malloc(sizeof(*ccp));
	memset(ccp,0,sizeof(*ccp));
	
	log_debug("ccp_layer_init\n");

	ccp->ppp=ppp;
	ccp->fsm.ppp=ppp;
	
	ccp->hnd.proto=PPP_CCP;
	ccp->hnd.recv=ccp_recv;
	
	ppp_register_unit_handler(ppp,&ccp->hnd);
	
	ppp_fsm_init(&ccp->fsm);

	ccp->fsm.layer_up=ccp_layer_up;
	ccp->fsm.layer_finished=ccp_layer_down;
	ccp->fsm.send_conf_req=send_conf_req;
	ccp->fsm.send_conf_ack=send_conf_ack;
	ccp->fsm.send_conf_nak=send_conf_nak;
	ccp->fsm.send_conf_rej=send_conf_rej;

	INIT_LIST_HEAD(&ccp->ropt_list);

	return &ccp->ld;
}

void ccp_layer_start(struct ppp_layer_data_t *ld)
{
	struct ppp_ccp_t *ccp=container_of(ld,typeof(*ccp),ld);
	
	log_debug("ccp_layer_start\n");

	ccp_options_init(ccp);
	ppp_fsm_lower_up(&ccp->fsm);
	ppp_fsm_open(&ccp->fsm);
}

void ccp_layer_finish(struct ppp_layer_data_t *ld)
{
	struct ppp_ccp_t *ccp=container_of(ld,typeof(*ccp),ld);
	
	log_debug("ccp_layer_finish\n");

	ppp_fsm_lower_down(&ccp->fsm);
	
	ppp_unregister_handler(ccp->ppp,&ccp->hnd);
	ccp_options_free(ccp);

	ppp_layer_finished(ccp->ppp,ld);
}

void ccp_layer_free(struct ppp_layer_data_t *ld)
{
	struct ppp_ccp_t *ccp=container_of(ld,typeof(*ccp),ld);
	
	log_debug("ccp_layer_free\n");
		
	free(ccp);
}

static void ccp_layer_up(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp=container_of(fsm,typeof(*ccp),fsm);
	log_debug("ccp_layer_started\n");
	ppp_layer_started(ccp->ppp,&ccp->ld);
}

static void ccp_layer_down(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp=container_of(fsm,typeof(*ccp),fsm);
	log_debug("ccp_layer_finished\n");
	ppp_layer_finished(ccp->ppp,&ccp->ld);
}

static void print_ropt(struct recv_opt_t *ropt)
{
	int i;
	uint8_t *ptr=(uint8_t*)ropt->hdr;

	log_debug(" <");
	for(i=0; i<ropt->len; i++)
	{
		log_debug(" %x",ptr[i]);
	}
	log_debug(" >");
}

static void send_conf_req(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp=container_of(fsm,typeof(*ccp),fsm);
	uint8_t *buf=malloc(ccp->conf_req_len), *ptr=buf;
	struct ccp_hdr_t *ccp_hdr=(struct ccp_hdr_t*)ptr;
	struct ccp_option_t *lopt;
	int n;

	log_debug("send [CCP ConfReq");
	ccp_hdr->proto=htons(PPP_CCP);
	ccp_hdr->code=CONFREQ;
	ccp_hdr->id=++ccp->fsm.id;
	ccp_hdr->len=0;
	log_debug(" id=%x",ccp_hdr->id);
	
	ptr+=sizeof(*ccp_hdr);

	list_for_each_entry(lopt,&ccp->options,entry)
	{
		n=lopt->h->send_conf_req(ccp,lopt,ptr);
		if (n)
		{
			log_debug(" ");
			lopt->h->print(log_debug,lopt,NULL);
			ptr+=n;
		}
	}
	
	log_debug("]\n");

	ccp_hdr->len=htons((ptr-buf)-2);
	ppp_unit_send(ccp->ppp,ccp_hdr,ptr-buf);
}

static void send_conf_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp=container_of(fsm,typeof(*ccp),fsm);
	struct ccp_hdr_t *hdr=(struct ccp_hdr_t*)ccp->ppp->unit_buf;

	hdr->code=CONFACK;
	log_debug("send [CCP ConfAck id=%x ]\n",ccp->fsm.recv_id);

	ppp_unit_send(ccp->ppp,hdr,ntohs(hdr->len)+2);
}

static void send_conf_nak(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp=container_of(fsm,typeof(*ccp),fsm);
	uint8_t *buf=malloc(ccp->conf_req_len), *ptr=buf;
	struct ccp_hdr_t *ccp_hdr=(struct ccp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	log_debug("send [CCP ConfNak id=%x",ccp->fsm.recv_id);

	ccp_hdr->proto=htons(PPP_CCP);
	ccp_hdr->code=CONFNAK;
	ccp_hdr->id=ccp->fsm.recv_id;
	ccp_hdr->len=0;
	
	ptr+=sizeof(*ccp_hdr);

	list_for_each_entry(ropt,&ccp->ropt_list,entry)
	{
		if (ropt->state==CCP_OPT_NAK)
		{
			log_debug(" ");
			ropt->lopt->h->print(log_debug,ropt->lopt,NULL);
			ptr+=ropt->lopt->h->send_conf_nak(ccp,ropt->lopt,ptr);
		}
	}
	
	log_debug("]\n");

	ccp_hdr->len=htons((ptr-buf)-2);
	ppp_unit_send(ccp->ppp,ccp_hdr,ptr-buf);
}

static void send_conf_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_ccp_t *ccp=container_of(fsm,typeof(*ccp),fsm);
	uint8_t *buf=malloc(ccp->ropt_len), *ptr=buf;
	struct ccp_hdr_t *ccp_hdr=(struct ccp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	log_debug("send [CCP ConfRej id=%x ",ccp->fsm.recv_id);

	ccp_hdr->proto=htons(PPP_CCP);
	ccp_hdr->code=CONFREJ;
	ccp_hdr->id=ccp->fsm.recv_id;
	ccp_hdr->len=0;

	ptr+=sizeof(*ccp_hdr);

	list_for_each_entry(ropt,&ccp->ropt_list,entry)
	{
		if (ropt->state==CCP_OPT_REJ)
		{
			log_debug(" ");
			if (ropt->lopt)	ropt->lopt->h->print(log_debug,ropt->lopt,(uint8_t*)ropt->hdr);
			else print_ropt(ropt);
			memcpy(ptr,ropt->hdr,ropt->len);
			ptr+=ropt->len;
		}
	}

	log_debug("]\n");

	ccp_hdr->len=htons((ptr-buf)-2);
	ppp_unit_send(ccp->ppp,ccp_hdr,ptr-buf);
}

static int ccp_recv_conf_req(struct ppp_ccp_t *ccp,uint8_t *data,int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct recv_opt_t *ropt;
	struct ccp_option_t *lopt;
	int r,ret=1,ack=0;

	ccp->ropt_len=size;

	while(size>0)
	{
		hdr=(struct ccp_opt_hdr_t *)data;

		ropt=malloc(sizeof(*ropt));
		memset(ropt,0,sizeof(*ropt));
		if (hdr->len>size) ropt->len=size;
		else ropt->len=hdr->len;
		ropt->hdr=hdr;
		ropt->state=CCP_OPT_NONE;
		list_add_tail(&ropt->entry,&ccp->ropt_list);

		data+=ropt->len;
		size-=ropt->len;
	}
	
	list_for_each_entry(lopt,&ccp->options,entry)
		lopt->state=CCP_OPT_NONE;

	log_debug("recv [CCP ConfReq id=%x",ccp->fsm.recv_id);
	list_for_each_entry(ropt,&ccp->ropt_list,entry)
	{
		list_for_each_entry(lopt,&ccp->options,entry)
		{
			if (lopt->id==ropt->hdr->id)
			{
				log_debug(" ");
				lopt->h->print(log_debug,lopt,(uint8_t*)ropt->hdr);
				r=lopt->h->recv_conf_req(ccp,lopt,(uint8_t*)ropt->hdr);
				if (ack)
				{
					lopt->state=CCP_OPT_REJ;
					ropt->state=CCP_OPT_REJ;
				}else
				{
					lopt->state=r;
					ropt->state=r;
				}
				ropt->lopt=lopt;
				if (r<ret) ret=r;
				break;
			}
		}
		if (ropt->state==CCP_OPT_ACK || ropt->state==CCP_OPT_NAK)
			ack=1;
		else if (!ropt->lopt)
		{
			log_debug(" ");
			print_ropt(ropt);
			ropt->state=CCP_OPT_REJ;
			ret=CCP_OPT_REJ;
		}
	}
	log_debug("]\n");

	/*list_for_each_entry(lopt,&ccp->options,entry)
	{
		if (lopt->state==CCP_OPT_NONE)
		{
			r=lopt->h->recv_conf_req(ccp,lopt,NULL);
			lopt->state=r;
			if (r<ret) ret=r;
		}
	}*/

	return ret;
}

static void ccp_free_conf_req(struct ppp_ccp_t *ccp)
{
	struct recv_opt_t *ropt;

	while(!list_empty(&ccp->ropt_list))
	{
		ropt=list_entry(ccp->ropt_list.next,typeof(*ropt),entry);
		list_del(&ropt->entry);
		free(ropt);
	}
}

static int ccp_recv_conf_rej(struct ppp_ccp_t *ccp,uint8_t *data,int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct ccp_option_t *lopt;
	int res=0;

	log_debug("recv [CCP ConfRej id=%x",ccp->fsm.recv_id);

	if (ccp->fsm.recv_id!=ccp->fsm.id)
	{
		log_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct ccp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&ccp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				if (!lopt->h->recv_conf_rej)
					res=-1;
				else if (lopt->h->recv_conf_rej(ccp,lopt,data))
					res=-1;
				break;
			}
		}

		data+=hdr->len;
		size-=hdr->len;
	}
	log_debug("]\n");
	return res;
}

static int ccp_recv_conf_nak(struct ppp_ccp_t *ccp,uint8_t *data,int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct ccp_option_t *lopt;
	int res=0;

	log_debug("recv [CCP ConfNak id=%x",ccp->fsm.recv_id);

	if (ccp->fsm.recv_id!=ccp->fsm.id)
	{
		log_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct ccp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&ccp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				log_debug(" ");
				lopt->h->print(log_debug,lopt,data);
				if (lopt->h->recv_conf_nak(ccp,lopt,data))
					res=-1;
				break;
			}
		}

		data+=hdr->len;
		size-=hdr->len;
	}
	log_debug("]\n");
	return res;
}

static int ccp_recv_conf_ack(struct ppp_ccp_t *ccp,uint8_t *data,int size)
{
	struct ccp_opt_hdr_t *hdr;
	struct ccp_option_t *lopt;
	int res=0;

	log_debug("recv [CCP ConfAck id=%x",ccp->fsm.recv_id);

	if (ccp->fsm.recv_id!=ccp->fsm.id)
	{
		log_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct ccp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&ccp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				log_debug(" ");
				lopt->h->print(log_debug,lopt,data);
				if (lopt->h->recv_conf_ack)
					lopt->h->recv_conf_ack(ccp,lopt,data);
				break;
			}
		}

		data+=hdr->len;
		size-=hdr->len;
	}
	log_debug("]\n");
	return res;
}

static void ccp_recv(struct ppp_handler_t*h)
{
	struct ccp_hdr_t *hdr;
	struct ppp_ccp_t *ccp=container_of(h,typeof(*ccp),hnd);
	int r;
	char *term_msg;
	
	if (ccp->ppp->unit_buf_size<PPP_HEADERLEN+2)
	{
		log_warn("CCP: short packet received\n");
		return;
	}

	hdr=(struct ccp_hdr_t *)ccp->ppp->unit_buf;
	if (ntohs(hdr->len)<PPP_HEADERLEN)
	{
		log_warn("CCP: short packet received\n");
		return;
	}

	ccp->fsm.recv_id=hdr->id;
	switch(hdr->code)
	{
		case CONFREQ:
			r=ccp_recv_conf_req(ccp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			switch(r)
			{
				case CCP_OPT_ACK:
					ppp_fsm_recv_conf_req_ack(&ccp->fsm);
					break;
				case CCP_OPT_NAK:
					ppp_fsm_recv_conf_req_nak(&ccp->fsm);
					break;
				case CCP_OPT_REJ:
					ppp_fsm_recv_conf_req_rej(&ccp->fsm);
					break;
			}
			ccp_free_conf_req(ccp);
			if (r==CCP_OPT_FAIL)
				ppp_terminate(ccp->ppp);
			break;
		case CONFACK:
			ccp_recv_conf_ack(ccp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_ack(&ccp->fsm);
			break;
		case CONFNAK:
			ccp_recv_conf_nak(ccp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_rej(&ccp->fsm);
			break;
		case CONFREJ:
			if (ccp_recv_conf_rej(ccp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN))
				ppp_terminate(ccp->ppp);
			else
				ppp_fsm_recv_conf_rej(&ccp->fsm);
			break;
		case TERMREQ:
			term_msg=strndup((uint8_t*)(hdr+1),ntohs(hdr->len));
			log_debug("recv [CCP TermReq id=%x \"%s\"]\n",hdr->id,term_msg);
			free(term_msg);
			ppp_fsm_recv_term_req(&ccp->fsm);
			ppp_terminate(ccp->ppp);
			break;
		case TERMACK:
			term_msg=strndup((uint8_t*)(hdr+1),ntohs(hdr->len));
			log_debug("recv [CCP TermAck id=%x \"%s\"]\n",hdr->id,term_msg);
			free(term_msg);
			ppp_fsm_recv_term_ack(&ccp->fsm);
			break;
		case CODEREJ:
			log_debug("recv [CCP CodeRej id=%x]\n",hdr->id);
			ppp_fsm_recv_code_rej_bad(&ccp->fsm);
			break;
		default:
			ppp_fsm_recv_unk(&ccp->fsm);
			break;
	}
}

int ccp_option_register(struct ccp_option_handler_t *h)
{
	/*struct ccp_option_drv_t *p;

	list_for_each_entry(p,option_drv_list,entry)
		if (p->id==h->id) 
			return -1;*/
	
	list_add_tail(&h->entry,&option_handlers);

	return 0;
}

static struct ppp_layer_t ccp_layer=
{
	.init=ccp_layer_init,
	.start=ccp_layer_start,
	.finish=ccp_layer_finish,
	.free=ccp_layer_free,
};

static void __init ccp_init(void)
{
	ppp_register_layer("ccp",&ccp_layer);
}
