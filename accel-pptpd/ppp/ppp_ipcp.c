#include <stdlib.h>
#include <string.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <arpa/inet.h>

#include "triton.h"

#include "log.h"

#include "ppp.h"
#include "ppp_ipcp.h"

struct recv_opt_t
{
	struct list_head entry;
	struct ipcp_opt_hdr_t *hdr;
	int len;
	int state;
	struct ipcp_option_t *lopt;
};

static LIST_HEAD(option_handlers);

static void ipcp_layer_up(struct ppp_fsm_t*);
static void ipcp_layer_down(struct ppp_fsm_t*);
static int send_conf_req(struct ppp_fsm_t*);
static void send_conf_ack(struct ppp_fsm_t*);
static void send_conf_nak(struct ppp_fsm_t*);
static void send_conf_rej(struct ppp_fsm_t*);
static void ipcp_recv(struct ppp_handler_t*);

static void ipcp_options_init(struct ppp_ipcp_t *ipcp)
{
	struct ipcp_option_t *lopt;
	struct ipcp_option_handler_t *h;

	list_for_each_entry(h,&option_handlers,entry)
	{
		lopt=h->init(ipcp);
		if (lopt)
		{
			lopt->h=h;
			list_add_tail(&lopt->entry,&ipcp->options);
			ipcp->conf_req_len+=lopt->len;
		}
	}
}

static void ipcp_options_free(struct ppp_ipcp_t *ipcp)
{
	struct ipcp_option_t *lopt;

	while(!list_empty(&ipcp->options))
	{
		lopt=list_entry(ipcp->options.next,typeof(*lopt),entry);
		list_del(&lopt->entry);
		lopt->h->free(ipcp,lopt);
	}
}

static struct ppp_layer_data_t *ipcp_layer_init(struct ppp_t *ppp)
{
	struct ppp_ipcp_t *ipcp=malloc(sizeof(*ipcp));
	memset(ipcp,0,sizeof(*ipcp));
	
	log_ppp_debug("ipcp_layer_init\n");

	ipcp->ppp=ppp;
	ipcp->fsm.ppp=ppp;
	
	ipcp->hnd.proto=PPP_IPCP;
	ipcp->hnd.recv=ipcp_recv;
	
	ppp_register_unit_handler(ppp,&ipcp->hnd);
	
	ppp_fsm_init(&ipcp->fsm);

	ipcp->fsm.layer_up=ipcp_layer_up;
	ipcp->fsm.layer_finished=ipcp_layer_down;
	ipcp->fsm.send_conf_req=send_conf_req;
	ipcp->fsm.send_conf_ack=send_conf_ack;
	ipcp->fsm.send_conf_nak=send_conf_nak;
	ipcp->fsm.send_conf_rej=send_conf_rej;

	INIT_LIST_HEAD(&ipcp->options);
	INIT_LIST_HEAD(&ipcp->ropt_list);

	return &ipcp->ld;
}

int ipcp_layer_start(struct ppp_layer_data_t *ld)
{
	struct ppp_ipcp_t *ipcp=container_of(ld,typeof(*ipcp),ld);
	
	log_ppp_debug("ipcp_layer_start\n");

	ipcp_options_init(ipcp);
	ppp_fsm_lower_up(&ipcp->fsm);
	if (ppp_fsm_open(&ipcp->fsm))
		return -1;
	
	return 0;
}

void ipcp_layer_finish(struct ppp_layer_data_t *ld)
{
	struct ppp_ipcp_t *ipcp=container_of(ld,typeof(*ipcp),ld);
	
	log_ppp_debug("ipcp_layer_finish\n");

	ipcp->fsm.fsm_state = FSM_Closed;
	ppp_layer_finished(ipcp->ppp,&ipcp->ld);
}

void ipcp_layer_free(struct ppp_layer_data_t *ld)
{
	struct ppp_ipcp_t *ipcp=container_of(ld,typeof(*ipcp),ld);
	
	log_ppp_debug("ipcp_layer_free\n");
		
	ppp_unregister_handler(ipcp->ppp,&ipcp->hnd);
	ipcp_options_free(ipcp);
	ppp_fsm_free(&ipcp->fsm);

	free(ipcp);
}

static void ipcp_layer_up(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp=container_of(fsm,typeof(*ipcp),fsm);
	log_ppp_debug("ipcp_layer_started\n");
	ppp_layer_started(ipcp->ppp,&ipcp->ld);
}

static void ipcp_layer_down(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp=container_of(fsm,typeof(*ipcp),fsm);
	log_ppp_debug("ipcp_layer_finished\n");
	ppp_layer_finished(ipcp->ppp,&ipcp->ld);
}

static void print_ropt(struct recv_opt_t *ropt)
{
	int i;
	uint8_t *ptr=(uint8_t*)ropt->hdr;

	log_ppp_debug(" <");
	for(i=0; i<ropt->len; i++)
	{
		log_ppp_debug(" %x",ptr[i]);
	}
	log_ppp_debug(" >");
}

static int send_conf_req(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp=container_of(fsm,typeof(*ipcp),fsm);
	uint8_t *buf=malloc(ipcp->conf_req_len), *ptr=buf;
	struct ipcp_hdr_t *ipcp_hdr=(struct ipcp_hdr_t*)ptr;
	struct ipcp_option_t *lopt;
	int n;

	ipcp_hdr->proto=htons(PPP_IPCP);
	ipcp_hdr->code=CONFREQ;
	ipcp_hdr->id=++ipcp->fsm.id;
	ipcp_hdr->len=0;
	
	ptr+=sizeof(*ipcp_hdr);

	list_for_each_entry(lopt,&ipcp->options,entry)
	{
		n = lopt->h->send_conf_req(ipcp, lopt, ptr);
		if (n < 0)
			return -1;
		if (n) {
			ptr+=n;
			lopt->print = 1;
		} else
			lopt->print = 0;
	}

	if (conf_ppp_verbose) {
		log_ppp_debug("send [IPCP ConfReq id=%x", ipcp_hdr->id);
		list_for_each_entry(lopt,&ipcp->options,entry){
			if (lopt->print) {
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,NULL);
			}
		}
		log_ppp_debug("]\n");
	}

	ipcp_hdr->len=htons((ptr-buf)-2);
	ppp_unit_send(ipcp->ppp,ipcp_hdr,ptr-buf);

	return 0;
}

static void send_conf_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp=container_of(fsm,typeof(*ipcp),fsm);
	struct ipcp_hdr_t *hdr=(struct ipcp_hdr_t*)ipcp->ppp->unit_buf;

	hdr->code=CONFACK;
	log_ppp_debug("send [IPCP ConfAck id=%x ]\n",ipcp->fsm.recv_id);

	ppp_unit_send(ipcp->ppp,hdr,ntohs(hdr->len)+2);
}

static void send_conf_nak(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp=container_of(fsm,typeof(*ipcp),fsm);
	uint8_t *buf=malloc(ipcp->conf_req_len), *ptr=buf;
	struct ipcp_hdr_t *ipcp_hdr=(struct ipcp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	log_ppp_debug("send [IPCP ConfNak id=%x",ipcp->fsm.recv_id);

	ipcp_hdr->proto=htons(PPP_IPCP);
	ipcp_hdr->code=CONFNAK;
	ipcp_hdr->id=ipcp->fsm.recv_id;
	ipcp_hdr->len=0;
	
	ptr+=sizeof(*ipcp_hdr);

	list_for_each_entry(ropt,&ipcp->ropt_list,entry)
	{
		if (ropt->state==IPCP_OPT_NAK)
		{
			log_ppp_debug(" ");
			ropt->lopt->h->print(log_ppp_debug,ropt->lopt,NULL);
			ptr+=ropt->lopt->h->send_conf_nak(ipcp,ropt->lopt,ptr);
		}
	}
	
	log_ppp_debug("]\n");

	ipcp_hdr->len=htons((ptr-buf)-2);
	ppp_unit_send(ipcp->ppp,ipcp_hdr,ptr-buf);
}

static void send_conf_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_ipcp_t *ipcp=container_of(fsm,typeof(*ipcp),fsm);
	uint8_t *buf=malloc(ipcp->ropt_len), *ptr=buf;
	struct ipcp_hdr_t *ipcp_hdr=(struct ipcp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	log_ppp_debug("send [IPCP ConfRej id=%x ",ipcp->fsm.recv_id);

	ipcp_hdr->proto=htons(PPP_IPCP);
	ipcp_hdr->code=CONFREJ;
	ipcp_hdr->id=ipcp->fsm.recv_id;
	ipcp_hdr->len=0;

	ptr+=sizeof(*ipcp_hdr);

	list_for_each_entry(ropt,&ipcp->ropt_list,entry)
	{
		if (ropt->state==IPCP_OPT_REJ)
		{
			log_ppp_debug(" ");
			if (ropt->lopt)	ropt->lopt->h->print(log_ppp_debug,ropt->lopt,(uint8_t*)ropt->hdr);
			else print_ropt(ropt);
			memcpy(ptr,ropt->hdr,ropt->len);
			ptr+=ropt->len;
		}
	}

	log_ppp_debug("]\n");

	ipcp_hdr->len=htons((ptr-buf)-2);
	ppp_unit_send(ipcp->ppp,ipcp_hdr,ptr-buf);
}

static int ipcp_recv_conf_req(struct ppp_ipcp_t *ipcp,uint8_t *data,int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct recv_opt_t *ropt;
	struct ipcp_option_t *lopt;
	int r,ret=1;

	ipcp->ropt_len=size;

	while(size>0)
	{
		hdr=(struct ipcp_opt_hdr_t *)data;

		ropt=malloc(sizeof(*ropt));
		memset(ropt,0,sizeof(*ropt));
		if (hdr->len>size) ropt->len=size;
		else ropt->len=hdr->len;
		ropt->hdr=hdr;
		ropt->state=IPCP_OPT_NONE;
		list_add_tail(&ropt->entry,&ipcp->ropt_list);

		data+=ropt->len;
		size-=ropt->len;
	}
	
	list_for_each_entry(lopt,&ipcp->options,entry)
		lopt->state=IPCP_OPT_NONE;

	log_ppp_debug("recv [IPCP ConfReq id=%x",ipcp->fsm.recv_id);
	list_for_each_entry(ropt,&ipcp->ropt_list,entry)
	{
		list_for_each_entry(lopt,&ipcp->options,entry)
		{
			if (lopt->id==ropt->hdr->id)
			{
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,(uint8_t*)ropt->hdr);
				r=lopt->h->recv_conf_req(ipcp,lopt,(uint8_t*)ropt->hdr);
				lopt->state=r;
				ropt->state=r;
				ropt->lopt=lopt;
				if (r<ret) ret=r;
				break;
			}	
		}
		if (!ropt->lopt)
		{
			log_ppp_debug(" ");
			print_ropt(ropt);
			ropt->state=IPCP_OPT_REJ;
			ret=IPCP_OPT_REJ;
		}
	}
	log_ppp_debug("]\n");

	/*list_for_each_entry(lopt,&ipcp->options,entry)
	{
		if (lopt->state==IPCP_OPT_NONE)
		{
			r=lopt->h->recv_conf_req(ipcp,lopt,NULL);
			lopt->state=r;
			if (r<ret) ret=r;
		}
	}*/

	return ret;
}

static void ipcp_free_conf_req(struct ppp_ipcp_t *ipcp)
{
	struct recv_opt_t *ropt;

	while(!list_empty(&ipcp->ropt_list))
	{
		ropt=list_entry(ipcp->ropt_list.next,typeof(*ropt),entry);
		list_del(&ropt->entry);
		free(ropt);
	}
}

static int ipcp_recv_conf_rej(struct ppp_ipcp_t *ipcp,uint8_t *data,int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct ipcp_option_t *lopt;
	int res=0;

	log_ppp_debug("recv [IPCP ConfRej id=%x",ipcp->fsm.recv_id);

	if (ipcp->fsm.recv_id!=ipcp->fsm.id)
	{
		log_ppp_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct ipcp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&ipcp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				if (!lopt->h->recv_conf_rej)
					res=-1;
				else if (lopt->h->recv_conf_rej(ipcp,lopt,data))
					res=-1;
				break;
			}
		}

		data+=hdr->len;
		size-=hdr->len;
	}
	log_ppp_debug("]\n");
	return res;
}

static int ipcp_recv_conf_nak(struct ppp_ipcp_t *ipcp,uint8_t *data,int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct ipcp_option_t *lopt;
	int res=0;

	log_ppp_debug("recv [IPCP ConfNak id=%x",ipcp->fsm.recv_id);

	if (ipcp->fsm.recv_id!=ipcp->fsm.id)
	{
		log_ppp_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct ipcp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&ipcp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,data);
				if (lopt->h->recv_conf_nak(ipcp,lopt,data))
					res=-1;
				break;
			}
		}

		data+=hdr->len;
		size-=hdr->len;
	}
	log_ppp_debug("]\n");
	return res;
}

static int ipcp_recv_conf_ack(struct ppp_ipcp_t *ipcp,uint8_t *data,int size)
{
	struct ipcp_opt_hdr_t *hdr;
	struct ipcp_option_t *lopt;
	int res=0;

	log_ppp_debug("recv [IPCP ConfAck id=%x",ipcp->fsm.recv_id);

	if (ipcp->fsm.recv_id!=ipcp->fsm.id)
	{
		log_ppp_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct ipcp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&ipcp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,data);
				if (!lopt->h->recv_conf_ack)
					break;
				if (lopt->h->recv_conf_ack(ipcp,lopt,data))
					res=-1;
				break;
			}
		}

		data+=hdr->len;
		size-=hdr->len;
	}
	log_ppp_debug("]\n");
	return res;
}

static void ipcp_recv(struct ppp_handler_t*h)
{
	struct ipcp_hdr_t *hdr;
	struct ppp_ipcp_t *ipcp=container_of(h,typeof(*ipcp),hnd);
	int r;
	char *term_msg;

	if (ipcp->fsm.fsm_state==FSM_Initial || ipcp->fsm.fsm_state==FSM_Closed)
	{
		log_ppp_warn("IPCP: discaring packet\n");
		return;
	}

	if (ipcp->ppp->unit_buf_size<PPP_HEADERLEN+2)
	{
		log_ppp_warn("IPCP: short packet received\n");
		return;
	}

	hdr=(struct ipcp_hdr_t *)ipcp->ppp->unit_buf;
	if (ntohs(hdr->len)<PPP_HEADERLEN)
	{
		log_ppp_warn("IPCP: short packet received\n");
		return;
	}

	ipcp->fsm.recv_id=hdr->id;
	switch(hdr->code)
	{
		case CONFREQ:
			r=ipcp_recv_conf_req(ipcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			switch(r)
			{
				case IPCP_OPT_ACK:
					ppp_fsm_recv_conf_req_ack(&ipcp->fsm);
					break;
				case IPCP_OPT_NAK:
					ppp_fsm_recv_conf_req_nak(&ipcp->fsm);
					break;
				case IPCP_OPT_REJ:
					ppp_fsm_recv_conf_req_rej(&ipcp->fsm);
					break;
			}
			ipcp_free_conf_req(ipcp);
			if (r==IPCP_OPT_FAIL)
				ppp_terminate(ipcp->ppp, 0);
			break;
		case CONFACK:
			if (ipcp_recv_conf_ack(ipcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN))
				ppp_terminate(ipcp->ppp, 0);
			else
				ppp_fsm_recv_conf_ack(&ipcp->fsm);
			break;
		case CONFNAK:
			ipcp_recv_conf_nak(ipcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_rej(&ipcp->fsm);
			break;
		case CONFREJ:
			if (ipcp_recv_conf_rej(ipcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN))
				ppp_terminate(ipcp->ppp, 0);
			else
				ppp_fsm_recv_conf_rej(&ipcp->fsm);
			break;
		case TERMREQ:
			term_msg=strndup((char*)(hdr+1),ntohs(hdr->len));
			log_ppp_debug("recv [IPCP TermReq id=%x \"%s\"]\n",hdr->id,term_msg);
			free(term_msg);
			ppp_fsm_recv_term_req(&ipcp->fsm);
			ppp_terminate(ipcp->ppp, 0);
			break;
		case TERMACK:
			term_msg=strndup((char*)(hdr+1),ntohs(hdr->len));
			log_ppp_debug("recv [IPCP TermAck id=%x \"%s\"]\n",hdr->id,term_msg);
			free(term_msg);
			ppp_fsm_recv_term_ack(&ipcp->fsm);
			break;
		case CODEREJ:
			log_ppp_debug("recv [IPCP CodeRej id=%x]\n",hdr->id);
			ppp_fsm_recv_code_rej_bad(&ipcp->fsm);
			break;
		default:
			ppp_fsm_recv_unk(&ipcp->fsm);
			break;
	}
}

int ipcp_option_register(struct ipcp_option_handler_t *h)
{
	/*struct ipcp_option_drv_t *p;

	list_for_each_entry(p,option_drv_list,entry)
		if (p->id==h->id) 
			return -1;*/
	
	list_add_tail(&h->entry,&option_handlers);

	return 0;
}

static struct ppp_layer_t ipcp_layer=
{
	.init=ipcp_layer_init,
	.start=ipcp_layer_start,
	.finish=ipcp_layer_finish,
	.free=ipcp_layer_free,
};

static void __init ipcp_init(void)
{
	ppp_register_layer("ipcp",&ipcp_layer);
}
