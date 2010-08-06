#include <stdlib.h>
#include <string.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <arpa/inet.h>

#include "triton/triton.h"

#include "events.h"
#include "log.h"

#include "ppp.h"
#include "ppp_fsm.h"
#include "ppp_lcp.h"
#include "ppp_auth.h"

char* accomp="allow,disabled";
char* pcomp="allow,disabled";
char* auth="pap,eap,mschap-v2";
char* mppe="allow,disabled";
char* pwdb="radius";

static void send_conf_req(struct ppp_layer_t*);
static void send_conf_ack(struct ppp_layer_t*);
static void send_conf_nak(struct ppp_layer_t*);
static void send_conf_rej(struct ppp_layer_t*);
static void lcp_recv(struct ppp_layer_t*);

struct ppp_layer_t* ppp_lcp_init(struct ppp_t *ppp)
{
	struct ppp_layer_t *layer=malloc(sizeof(*layer));
	memset(layer,0,sizeof(*layer));

	layer->proto=PPP_LCP;
	layer->ppp=ppp;
	ppp_fsm_init(layer);

	layer->recv=lcp_recv;
	layer->send_conf_req=send_conf_req;
	layer->send_conf_ack=send_conf_ack;
	layer->send_conf_nak=send_conf_nak;
	layer->send_conf_rej=send_conf_rej;

	ppp_fsm_init(layer);

	return layer;
}

static void send_conf_req(struct ppp_layer_t*l)
{
	uint8_t buf[128],*ptr=buf;
	struct lcp_opt_hdr_t *opt0;
	struct lcp_opt16_t *opt16;
	struct lcp_opt32_t *opt32;
	struct lcp_hdr_t *lcp_hdr=(struct lcp_hdr_t*)ptr; ptr+=sizeof(*lcp_hdr);

	log_msg("send [LCP ConfReq");
	lcp_hdr->proto=PPP_LCP;
	lcp_hdr->code=CONFREQ;
	lcp_hdr->id=++l->id;
	lcp_hdr->len=0;
	log_msg(" id=%x",lcp_hdr->id);

	//mru
	opt16=(struct lcp_opt16_t*)ptr; ptr+=sizeof(*opt16);
	opt16->hdr.type=CI_MRU;
	opt16->hdr.len=4;
	opt16->val=htons(l->options.lcp.mtu);
	log_msg(" <mru %i>",l->options.lcp.mtu);

	//auth
	opt32=(struct lcp_opt32_t*)ptr;;
	if (auth_get_conf_req(l,opt32))
		ptr+=opt32->hdr.len;
	
	//magic
	opt32=(struct lcp_opt32_t*)ptr; ptr+=sizeof(*opt32);
	opt32->hdr.type=CI_MAGIC;
	opt32->hdr.len=6;
	opt32->val=htonl(l->options.lcp.magic);
	log_msg(" <magic %x>",l->options.lcp.magic);


	//pcomp
	if (l->options.lcp.pcomp==1 || (l->options.lcp.pcomp==3 && l->options.lcp.neg_pcomp!=-1))
	{
		opt0=(struct lcp_opt_hdr_t*)ptr; ptr+=sizeof(*opt0);
		opt0->type=CI_PCOMP;
		opt0->len=2;
		log_msg(" <pcomp>");
	}

	//acccomp
	if (l->options.lcp.accomp==1 || (l->options.lcp.accomp==3 && l->options.lcp.neg_accomp!=-1))
	{
		opt0=(struct lcp_opt_hdr_t*)ptr; ptr+=sizeof(*opt0);
		opt0->type=CI_ACCOMP;
		opt0->len=2;
		log_msg(" <accomp>");
	}
	log_msg("]\n");

	lcp_hdr->len=ptr-buf;
	ppp_send(l->ppp,lcp_hdr,lcp_hdr->len+2);
}
static void send_conf_ack(struct ppp_layer_t*l)
{
	struct lcp_hdr_t *hdr=(struct lcp_hdr_t*)l->ppp->in_buf;

	hdr->code=CONFACK;
	log_msg("send [LCP ConfAck id=%x\n",l->recv_id);

	ppp_send(l->ppp,hdr,hdr->len+2);
}
static void send_conf_nak(struct ppp_layer_t*l)
{
}
static void send_conf_rej(struct ppp_layer_t*l)
{
	struct lcp_hdr_t *hdr=(struct lcp_hdr_t*)l->ppp->in_buf;

	hdr->code=CONFREJ;
	log_msg("send [LCP ConfRej id=%x\n",l->recv_id);

	ppp_send(l->ppp,hdr,hdr->len+2);
}

static int lcp_recv_conf_req(struct ppp_layer_t*l,uint8_t *data,int size)
{
	struct lcp_opt_hdr_t *opt;
	struct lcp_opt16_t *opt16;
	int res=0;

	log_debug("recv [LCP ConfReq id=%x",l->recv_id);

	while(size)
	{
		opt=(struct lcp_opt_hdr_t *)data;
		switch(opt->type)
		{
			case CI_MRU:
				opt16=(struct lcp_opt16_t*)data;
				l->options.lcp.neg_mru=ntohs(opt16->val);
				log_debug(" <mru %i>",l->options.lcp.neg_mru);
				break;
			case CI_ASYNCMAP:
				log_debug(" <asyncmap ...>");
				break;
			case CI_AUTHTYPE:
				if (auth_recv_conf_req(l,opt))
					res=-1;
				break;
			case CI_MAGIC:
				if (*(uint32_t*)data==l->options.lcp.magic)
				{
					log_error("loop detected\n");
					res=-1;
				}
				break;
			case CI_PCOMP:
				log_debug(" <pcomp>");
				if (l->options.lcp.pcomp>=1) l->options.lcp.neg_pcomp=1;
				else {
					l->options.lcp.neg_pcomp=-2;
					res=-1;
				}
				break;
			case CI_ACCOMP:
				log_debug(" <accomp>");
				if (l->options.lcp.accomp>=1) l->options.lcp.neg_accomp=1;
				else {
					l->options.lcp.neg_accomp=-2;
					res=-1;
				}
				break;
		}
		data+=opt->len;
		size-=opt->len;
	}
	log_debug("\n");
	return res;
}

static int lcp_recv_conf_rej(struct ppp_layer_t*l,uint8_t *data,int size)
{
	struct lcp_opt_hdr_t *opt;
	struct lcp_opt16_t *opt16;
	int res=0;

	log_debug("recv [LCP ConfRej id=%x",l->recv_id);

	if (l->recv_id!=l->id)
	{
		log_debug(": id mismatch\n");
		return 0;
	}

	while(size)
	{
		opt=(struct lcp_opt_hdr_t *)data;
		switch(opt->type)
		{
			case CI_MRU:
				opt16=(struct lcp_opt16_t*)data;
				log_debug(" <mru %i>",l->options.lcp.neg_mru);
				break;
			case CI_ASYNCMAP:
				log_debug(" <asyncmap ...>");
				break;
			case CI_AUTHTYPE:
				if (auth_recv_conf_rej(l,opt))
					res=-1;
				break;
			case CI_MAGIC:
				if (*(uint32_t*)data==l->options.lcp.magic)
				{
					log_error("loop detected\n");
					res=-1;
				}
				break;
			case CI_PCOMP:
				log_debug(" <pcomp>");
				if (l->options.lcp.pcomp>=1) l->options.lcp.neg_pcomp=-1;
				else {
					l->options.lcp.neg_pcomp=-2;
					res=-1;
				}
				break;
			case CI_ACCOMP:
				log_debug(" <accomp>");
				if (l->options.lcp.accomp>=1) l->options.lcp.neg_accomp=-1;
				else {
					l->options.lcp.neg_accomp=-2;
					res=-1;
				}
				break;
		}
		data+=opt->len;
		size-=opt->len;
	}
	log_debug("\n");
	return res;
}
static int lcp_recv_conf_nak(struct ppp_layer_t*l,uint8_t *data,int size)
{
	struct lcp_opt_hdr_t *opt;
	struct lcp_opt16_t *opt16;
	int res=0;

	log_debug("recv [LCP ConfNak id=%x",l->recv_id);

	if (l->recv_id!=l->id)
	{
		log_debug(": id mismatch\n");
		return 0;
	}

	while(size)
	{
		opt=(struct lcp_opt_hdr_t *)data;
		switch(opt->type)
		{
			case CI_MRU:
				opt16=(struct lcp_opt16_t*)data;
				log_debug(" <mru %i>",l->options.lcp.neg_mru);
				break;
			case CI_ASYNCMAP:
				log_debug(" <asyncmap ...>");
				break;
			case CI_AUTHTYPE:
				if (auth_recv_conf_nak(l,opt))
					res=-1;
				break;
			case CI_MAGIC:
				if (*(uint32_t*)data==l->options.lcp.magic)
				{
					log_error("loop detected\n");
					res=-1;
				}
				break;
			case CI_PCOMP:
				log_debug(" <pcomp>");
				if (l->options.lcp.pcomp>=1) l->options.lcp.neg_pcomp=-1;
				else {
					l->options.lcp.neg_pcomp=-2;
					res=-1;
				}
				break;
			case CI_ACCOMP:
				log_debug(" <accomp>");
				if (l->options.lcp.accomp>=1) l->options.lcp.neg_accomp=-1;
				else {
					l->options.lcp.neg_accomp=-2;
					res=-1;
				}
				break;
		}
		data+=opt->len;
		size-=opt->len;
	}
	log_debug("\n");
	return res;
}
static void lcp_recv_echo_repl(struct ppp_layer_t*l,uint8_t *data,int size)
{

}

void send_echo_reply(struct ppp_layer_t *layer)
{
	struct lcp_echo_reply_t
	{
		struct lcp_hdr_t hdr;
		struct lcp_opt32_t magic;
	} __attribute__((packed)) msg = 
	{
		.hdr.proto=PPP_LCP,
		.hdr.code=ECHOREP,
		.hdr.id=layer->recv_id,
		.hdr.len=8,
		.magic.val=layer->options.lcp.magic,
	};

	ppp_send(layer->ppp,&msg,msg.hdr.len+2);
}

static void lcp_recv(struct ppp_layer_t*l)
{
	struct lcp_hdr_t *hdr;
	
	if (l->ppp->in_buf_size<PPP_HEADERLEN+2)
	{
		log_warn("LCP: short packet received\n");
		return;
	}

	hdr=(struct lcp_hdr_t *)l->ppp->in_buf;
	if (ntohs(hdr->len)<PPP_HEADERLEN)
	{
		log_warn("LCP: short packet received\n");
		return;
	}

	l->recv_id=hdr->id;
	switch(hdr->code)
	{
		case CONFREQ:
			if (lcp_recv_conf_req(l,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN))
				ppp_fsm_recv_conf_req_bad(l);
			else
				ppp_fsm_recv_conf_req_good(l);
			break;
		case CONFACK:
			//lcp_recv_conf_ack(l,hdr+1,ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_ack(l);
			break;
		case CONFNAK:
			lcp_recv_conf_nak(l,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_rej(l);
			break;
		case CONFREJ:
			lcp_recv_conf_rej(l,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_rej(l);
			break;
		case TERMREQ:
			ppp_fsm_recv_term_req(l);
			break;
		case TERMACK:
			ppp_fsm_recv_term_ack(l);
			break;
		case CODEREJ:
			ppp_fsm_recv_code_rej_bad(l);
			break;
		case ECHOREQ:
			send_echo_reply(l);
			break;
		case ECHOREP:
			lcp_recv_echo_repl(l,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			break;
		default:
			ppp_fsm_recv_unk(l);
			break;
	}
}

