#include <stdlib.h>
#include <string.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <arpa/inet.h>

#include "triton.h"

#include "log.h"

#include "ppp.h"
#include "ppp_lcp.h"

#include "memdebug.h"

struct recv_opt_t
{
	struct list_head entry;
	struct lcp_opt_hdr_t *hdr;
	int len;
	int state;
	struct lcp_option_t *lopt;
};

static int conf_echo_interval = 0;
static int conf_echo_failure = 3;

static LIST_HEAD(option_handlers);
static struct ppp_layer_t lcp_layer;

static void lcp_layer_up(struct ppp_fsm_t*);
static void lcp_layer_down(struct ppp_fsm_t*);
static void lcp_layer_finished(struct ppp_fsm_t*);
static int send_conf_req(struct ppp_fsm_t*);
static void send_conf_ack(struct ppp_fsm_t*);
static void send_conf_nak(struct ppp_fsm_t*);
static void send_conf_rej(struct ppp_fsm_t*);
static void send_code_rej(struct ppp_fsm_t*);
static void start_echo(struct ppp_lcp_t *lcp);
static void stop_echo(struct ppp_lcp_t *lcp);
static void send_term_req(struct ppp_fsm_t *fsm);
static void send_term_ack(struct ppp_fsm_t *fsm);
static void lcp_recv(struct ppp_handler_t*);

static void lcp_options_init(struct ppp_lcp_t *lcp)
{
	struct lcp_option_t *lopt;
	struct lcp_option_handler_t *h;

	INIT_LIST_HEAD(&lcp->options);

	lcp->conf_req_len = sizeof(struct lcp_hdr_t);

	list_for_each_entry(h,&option_handlers,entry)
	{
		lopt=h->init(lcp);
		if (lopt)
		{
			lopt->h=h;
			list_add_tail(&lopt->entry,&lcp->options);
			lcp->conf_req_len+=lopt->len;
		}
	}
}

static void lcp_options_free(struct ppp_lcp_t *lcp)
{
	struct lcp_option_t *lopt;

	while(!list_empty(&lcp->options))
	{
		lopt=list_entry(lcp->options.next,typeof(*lopt),entry);
		list_del(&lopt->entry);
		lopt->h->free(lcp,lopt);
	}
}

static struct ppp_layer_data_t *lcp_layer_init(struct ppp_t *ppp)
{
	struct ppp_lcp_t *lcp=_malloc(sizeof(*lcp));
	memset(lcp,0,sizeof(*lcp));
	
	log_ppp_debug("lcp_layer_init\n");

	lcp->ppp=ppp;
	lcp->fsm.ppp=ppp;
	
	lcp->hnd.proto=PPP_LCP;
	lcp->hnd.recv=lcp_recv;
	
	ppp_register_chan_handler(ppp,&lcp->hnd);

	lcp->fsm.proto = PPP_LCP;
	ppp_fsm_init(&lcp->fsm);

	lcp->fsm.layer_up=lcp_layer_up;
	lcp->fsm.layer_down=lcp_layer_down;
	lcp->fsm.layer_finished=lcp_layer_finished;
	lcp->fsm.send_conf_req=send_conf_req;
	lcp->fsm.send_conf_ack=send_conf_ack;
	lcp->fsm.send_conf_nak=send_conf_nak;
	lcp->fsm.send_conf_rej=send_conf_rej;
	lcp->fsm.send_code_rej=send_code_rej;
	lcp->fsm.send_term_req=send_term_req;
	lcp->fsm.send_term_ack=send_term_ack;

	INIT_LIST_HEAD(&lcp->ropt_list);

	return &lcp->ld;
}

int lcp_layer_start(struct ppp_layer_data_t *ld)
{
	struct ppp_lcp_t *lcp=container_of(ld,typeof(*lcp),ld);
	
	log_ppp_debug("lcp_layer_start\n");

	lcp_options_init(lcp);
	ppp_fsm_lower_up(&lcp->fsm);
	if (ppp_fsm_open(&lcp->fsm))
		return -1;
	
	return 0;
}

void lcp_layer_finish(struct ppp_layer_data_t *ld)
{
	struct ppp_lcp_t *lcp=container_of(ld,typeof(*lcp),ld);
	
	log_ppp_debug("lcp_layer_finish\n");

	stop_echo(lcp);

	ppp_fsm_close(&lcp->fsm);
}

void lcp_layer_free(struct ppp_layer_data_t *ld)
{
	struct ppp_lcp_t *lcp=container_of(ld,typeof(*lcp),ld);
	
	log_ppp_debug("lcp_layer_free\n");

	stop_echo(lcp);
	ppp_unregister_handler(lcp->ppp,&lcp->hnd);
	lcp_options_free(lcp);
	ppp_fsm_free(&lcp->fsm);
	
	_free(lcp);
}

static void lcp_layer_up(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	log_ppp_debug("lcp_layer_started\n");
	ppp_layer_started(lcp->ppp,&lcp->ld);

	start_echo(lcp);
}

static void lcp_layer_down(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	//ppp_fsm_close(&lcp->fsm);
	stop_echo(lcp);
	//ppp_layer_finished(lcp->ppp,&lcp->ld);
}

static void lcp_layer_finished(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	log_ppp_debug("lcp_layer_finished\n");
	stop_echo(lcp);
	ppp_layer_finished(lcp->ppp,&lcp->ld);
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
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	uint8_t *buf=_malloc(lcp->conf_req_len), *ptr=buf;
	struct lcp_hdr_t *lcp_hdr=(struct lcp_hdr_t*)ptr;
	struct lcp_option_t *lopt;
	int n;

	lcp_hdr->proto=htons(PPP_LCP);
	lcp_hdr->code=CONFREQ;
	lcp_hdr->id=++lcp->fsm.id;
	lcp_hdr->len=0;
	
	ptr+=sizeof(*lcp_hdr);

	list_for_each_entry(lopt,&lcp->options,entry)
	{
		n=lopt->h->send_conf_req(lcp,lopt,ptr);
		if (n < 0)
			return -1;
		if (n)
		{
			ptr+=n;
			lopt->print = 1;
		} else
			lopt->print = 0;
	}
	
	if (conf_ppp_verbose) {
		log_ppp_debug("send [LCP ConfReq id=%x", lcp_hdr->id);
		list_for_each_entry(lopt,&lcp->options,entry)
		{
			if (lopt->print) {
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,NULL);
			}
		}
		log_ppp_debug("]\n");
	}

	lcp_hdr->len=htons((ptr-buf)-2);
	ppp_chan_send(lcp->ppp,lcp_hdr,ptr-buf);

	_free(buf);

	return 0;
}

static void send_conf_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	struct lcp_hdr_t *hdr=(struct lcp_hdr_t*)lcp->ppp->chan_buf;

	hdr->code=CONFACK;
	log_ppp_debug("send [LCP ConfAck id=%x ]\n",lcp->fsm.recv_id);

	ppp_chan_send(lcp->ppp,hdr,ntohs(hdr->len)+2);
}

static void send_code_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	struct lcp_hdr_t *hdr=(struct lcp_hdr_t*)lcp->ppp->chan_buf;

	hdr->code=CONFACK;
	log_ppp_debug("send [LCP CodeRej %x id=%x ]\n",hdr->code, lcp->fsm.recv_id);

	ppp_chan_send(lcp->ppp,hdr,ntohs(hdr->len)+2);
}

static void send_conf_nak(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	uint8_t *buf=_malloc(lcp->conf_req_len), *ptr=buf;
	struct lcp_hdr_t *lcp_hdr=(struct lcp_hdr_t*)ptr;
	struct lcp_option_t *lopt;

	log_ppp_debug("send [LCP ConfNak id=%x",lcp->fsm.recv_id);

	lcp_hdr->proto=htons(PPP_LCP);
	lcp_hdr->code=CONFNAK;
	lcp_hdr->id=lcp->fsm.recv_id;
	lcp_hdr->len=0;
	
	ptr+=sizeof(*lcp_hdr);

	list_for_each_entry(lopt, &lcp->options, entry) {
		if (lopt->state == LCP_OPT_NAK) {
			log_ppp_debug(" ");
			lopt->h->print(log_ppp_debug,lopt,NULL);
			ptr+=lopt->h->send_conf_nak(lcp,lopt,ptr);
		}
	}
	
	log_ppp_debug("]\n");

	lcp_hdr->len=htons((ptr-buf)-2);
	ppp_chan_send(lcp->ppp,lcp_hdr,ptr-buf);

	_free(buf);
}

static void send_conf_rej(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	uint8_t *buf=_malloc(lcp->ropt_len + sizeof(struct lcp_hdr_t)), *ptr=buf;
	struct lcp_hdr_t *lcp_hdr=(struct lcp_hdr_t*)ptr;
	struct recv_opt_t *ropt;

	log_ppp_debug("send [LCP ConfRej id=%x ",lcp->fsm.recv_id);

	lcp_hdr->proto=htons(PPP_LCP);
	lcp_hdr->code=CONFREJ;
	lcp_hdr->id=lcp->fsm.recv_id;
	lcp_hdr->len=0;

	ptr+=sizeof(*lcp_hdr);

	list_for_each_entry(ropt,&lcp->ropt_list,entry)
	{
		if (ropt->state==LCP_OPT_REJ)
		{
			log_ppp_debug(" ");
			if (ropt->lopt)	ropt->lopt->h->print(log_ppp_debug,ropt->lopt,(uint8_t*)ropt->hdr);
			else print_ropt(ropt);
			memcpy(ptr,ropt->hdr,ropt->len);
			ptr+=ropt->len;
		}
	}

	log_ppp_debug("]\n");

	lcp_hdr->len=htons((ptr-buf)-2);
	ppp_chan_send(lcp->ppp,lcp_hdr,ptr-buf);

	_free(buf);
}

static int lcp_recv_conf_req(struct ppp_lcp_t *lcp,uint8_t *data,int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct recv_opt_t *ropt;
	struct lcp_option_t *lopt;
	int r,ret=1;

	lcp->ropt_len=size;

	while(size>0)
	{
		hdr=(struct lcp_opt_hdr_t *)data;

		ropt=_malloc(sizeof(*ropt));
		memset(ropt, 0, sizeof(*ropt));
		if (hdr->len>size) ropt->len=size;
		else ropt->len=hdr->len;
		ropt->hdr=hdr;
		ropt->state=LCP_OPT_NONE;
		list_add_tail(&ropt->entry,&lcp->ropt_list);

		data+=ropt->len;
		size-=ropt->len;
	}
	
	list_for_each_entry(lopt,&lcp->options,entry)
		lopt->state=LCP_OPT_NONE;

	log_ppp_debug("recv [LCP ConfReq id=%x",lcp->fsm.recv_id);
	list_for_each_entry(ropt,&lcp->ropt_list,entry)
	{
		list_for_each_entry(lopt,&lcp->options,entry)
		{
			if (lopt->id==ropt->hdr->id)
			{
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,(uint8_t*)ropt->hdr);
				r=lopt->h->recv_conf_req(lcp,lopt,(uint8_t*)ropt->hdr);
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
			ropt->state=LCP_OPT_REJ;
			ret=LCP_OPT_REJ;
		}
	}
	log_ppp_debug("]\n");

	/*list_for_each_entry(lopt,&lcp->options,entry)
	{
		if (lopt->state==LCP_OPT_NONE)
		{
			r=lopt->h->recv_conf_req(lcp,lopt,NULL);
			lopt->state=r;
			if (r<ret) ret=r;
		}
	}*/

	return ret;
}

static void lcp_free_conf_req(struct ppp_lcp_t *lcp)
{
	struct recv_opt_t *ropt;

	while(!list_empty(&lcp->ropt_list))
	{
		ropt=list_entry(lcp->ropt_list.next,typeof(*ropt),entry);
		list_del(&ropt->entry);
		_free(ropt);
	}
}

static int lcp_recv_conf_rej(struct ppp_lcp_t *lcp,uint8_t *data,int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct lcp_option_t *lopt;
	int res=0;

	log_ppp_debug("recv [LCP ConfRej id=%x",lcp->fsm.recv_id);

	if (lcp->fsm.recv_id!=lcp->fsm.id)
	{
		log_ppp_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct lcp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&lcp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				if (!lopt->h->recv_conf_rej)
					res=-1;
				else if (lopt->h->recv_conf_rej(lcp,lopt,data))
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

static int lcp_recv_conf_nak(struct ppp_lcp_t *lcp,uint8_t *data,int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct lcp_option_t *lopt;
	int res=0;

	log_ppp_debug("recv [LCP ConfNak id=%x",lcp->fsm.recv_id);

	if (lcp->fsm.recv_id!=lcp->fsm.id)
	{
		log_ppp_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct lcp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&lcp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,data);
				if (lopt->h->recv_conf_nak(lcp,lopt,data))
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

static int lcp_recv_conf_ack(struct ppp_lcp_t *lcp,uint8_t *data,int size)
{
	struct lcp_opt_hdr_t *hdr;
	struct lcp_option_t *lopt;
	int res=0;

	log_ppp_debug("recv [LCP ConfAck id=%x",lcp->fsm.recv_id);

	if (lcp->fsm.recv_id!=lcp->fsm.id)
	{
		log_ppp_debug(": id mismatch ]\n");
		return 0;
	}

	while(size>0)
	{
		hdr=(struct lcp_opt_hdr_t *)data;
		
		list_for_each_entry(lopt,&lcp->options,entry)
		{
			if (lopt->id==hdr->id)
			{
				log_ppp_debug(" ");
				lopt->h->print(log_ppp_debug,lopt,data);
				if (!lopt->h->recv_conf_ack)
					break;
				if (lopt->h->recv_conf_ack(lcp,lopt,data))
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

static void lcp_recv_echo_repl(struct ppp_lcp_t *lcp,uint8_t *data,int size)
{
	uint32_t magic = *(uint32_t *)data;

	if (size != 4) {
		log_ppp_error("lcp:echo: magic number size mismatch\n");
		ppp_terminate(lcp->ppp, 0);
	}

	log_ppp_debug("recv [LCP EchoRep id=%x <magic %x>]\n",lcp->fsm.recv_id,magic);

	if (magic == lcp->magic) {
		log_ppp_error("lcp:echo: loop-back detected\n");
		ppp_terminate(lcp->ppp, 0);
	}

	lcp->echo_sent = 0;
}

static void send_echo_reply(struct ppp_lcp_t *lcp)
{
	struct lcp_hdr_t *hdr=(struct lcp_hdr_t*)lcp->ppp->chan_buf;
	uint32_t magic = *(uint32_t *)(hdr+1);

	hdr->code=ECHOREP;
	*(uint32_t *)(hdr+1) = lcp->magic;
	log_ppp_debug("send [LCP EchoRep id=%x <magic %x>]\n", hdr->id, magic);

	ppp_chan_send(lcp->ppp,hdr,ntohs(hdr->len)+2);
}
static void send_echo_request(struct triton_timer_t *t)
{
	struct ppp_lcp_t *lcp = container_of(t, typeof(*lcp), echo_timer);
	struct lcp_echo_req_t
	{
		struct lcp_hdr_t hdr;
		uint32_t magic;
	} __attribute__((packed)) msg = {
		.hdr.proto = htons(PPP_LCP),
		.hdr.code = ECHOREQ,
		.hdr.id = ++lcp->fsm.id,
		.hdr.len = htons(8),
		.magic = lcp->magic,
	};

	if (++lcp->echo_sent > lcp->echo_failure) {
		log_ppp_warn("lcp: no echo reply\n");
		ppp_terminate(lcp->ppp, 0);
	} else {
		log_ppp_debug("send [LCP EchoReq id=%x <magic %x>]\n", msg.hdr.id, msg.magic);
		ppp_chan_send(lcp->ppp,&msg,ntohs(msg.hdr.len)+2);
	}
}

static void start_echo(struct ppp_lcp_t *lcp)
{
	lcp->echo_interval = conf_echo_interval;
	lcp->echo_failure = conf_echo_failure;

	lcp->echo_timer.period = lcp->echo_interval * 1000;
	lcp->echo_timer.expire = send_echo_request;
	if (lcp->echo_timer.period)
		triton_timer_add(lcp->ppp->ctrl->ctx, &lcp->echo_timer, 0);
}
static void stop_echo(struct ppp_lcp_t *lcp)
{
	if (lcp->echo_timer.tpd)
		triton_timer_del(&lcp->echo_timer);
}

static void send_term_req(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	struct lcp_hdr_t hdr = {
		.proto = htons(PPP_LCP),
		.code = TERMREQ,
		.id = ++lcp->fsm.id,
		.len = htons(4),
	};

	log_ppp_debug("send [LCP TermReq id=%i \"\"]\n",hdr.id);

	ppp_chan_send(lcp->ppp, &hdr, 6);
}

static void send_term_ack(struct ppp_fsm_t *fsm)
{
	struct ppp_lcp_t *lcp=container_of(fsm,typeof(*lcp),fsm);
	struct lcp_hdr_t hdr = {
		.proto = htons(PPP_LCP),
		.code = TERMACK,
		.id = lcp->fsm.recv_id,
		.len = htons(4),
	};

	log_ppp_debug("send [LCP TermAck id=%i \"\"]\n", hdr.id);
	
	ppp_chan_send(lcp->ppp, &hdr, 6);
}

void lcp_send_proto_rej(struct ppp_t *ppp, uint16_t proto)
{
	struct ppp_lcp_t *lcp = container_of(ppp_find_layer_data(ppp, &lcp_layer), typeof(*lcp), ld);
	struct rej_msg_t
	{
		struct lcp_hdr_t hdr;
		uint16_t proto;
	} __attribute__((packed)) msg = {
		.hdr.proto = htons(PPP_LCP),
		.hdr.code = PROTOREJ,
		.hdr.id = ++lcp->fsm.id,
		.hdr.len = htons(6),
		.proto = proto,
	};

	log_ppp_debug("send [LCP ProtoRej id=%i <%x>]\n", msg.hdr.id, proto);

	ppp_chan_send(lcp->ppp, &msg, sizeof(msg));
}

static void lcp_recv(struct ppp_handler_t*h)
{
	struct lcp_hdr_t *hdr;
	struct ppp_lcp_t *lcp=container_of(h,typeof(*lcp),hnd);
	int r;
	char *term_msg;
	
	if (lcp->ppp->chan_buf_size<PPP_HEADERLEN+2)
	{
		log_ppp_warn("LCP: short packet received\n");
		return;
	}

	hdr=(struct lcp_hdr_t *)lcp->ppp->chan_buf;
	if (ntohs(hdr->len)<PPP_HEADERLEN)
	{
		log_ppp_warn("LCP: short packet received\n");
		return;
	}

	lcp->fsm.recv_id=hdr->id;
	switch(hdr->code)
	{
		case CONFREQ:
			r=lcp_recv_conf_req(lcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			switch(r)
			{
				case LCP_OPT_ACK:
					ppp_fsm_recv_conf_req_ack(&lcp->fsm);
					break;
				case LCP_OPT_NAK:
					ppp_fsm_recv_conf_req_nak(&lcp->fsm);
					break;
				case LCP_OPT_REJ:
					ppp_fsm_recv_conf_req_rej(&lcp->fsm);
					break;
			}
			lcp_free_conf_req(lcp);
			if (r==LCP_OPT_FAIL)
				ppp_terminate(lcp->ppp, 0);
			break;
		case CONFACK:
			if (lcp_recv_conf_ack(lcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN))
				ppp_terminate(lcp->ppp, 0);
			else
				if (lcp->fsm.recv_id!=lcp->fsm.id)
					break;
				ppp_fsm_recv_conf_ack(&lcp->fsm);
			break;
		case CONFNAK:
			lcp_recv_conf_nak(lcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			if (lcp->fsm.recv_id!=lcp->fsm.id)
				break;
			ppp_fsm_recv_conf_rej(&lcp->fsm);
			break;
		case CONFREJ:
			if (lcp_recv_conf_rej(lcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN))
				ppp_terminate(lcp->ppp, 0);
			else
				if (lcp->fsm.recv_id!=lcp->fsm.id)
					break;
				ppp_fsm_recv_conf_rej(&lcp->fsm);
			break;
		case TERMREQ:
			term_msg=_strndup((char*)(hdr+1),ntohs(hdr->len)-4);
			log_ppp_debug("recv [LCP TermReq id=%x \"%s\"]\n",hdr->id,term_msg);
			_free(term_msg);
			ppp_fsm_recv_term_req(&lcp->fsm);
			ppp_terminate(lcp->ppp, 0);
			break;
		case TERMACK:
			term_msg=_strndup((char*)(hdr+1),ntohs(hdr->len)-4);
			log_ppp_debug("recv [LCP TermAck id=%x \"%s\"]\n",hdr->id,term_msg);
			_free(term_msg);
			ppp_fsm_recv_term_ack(&lcp->fsm);
			break;
		case CODEREJ:
			log_ppp_debug("recv [LCP CodeRej id=%x]\n",hdr->id);
			ppp_fsm_recv_code_rej_bad(&lcp->fsm);
			break;
		case ECHOREQ:
			log_ppp_debug("recv [LCP EchoReq id=%x <magic %x>]\n",hdr->id, *(uint32_t*)(hdr + 1));
			send_echo_reply(lcp);
			break;
		case ECHOREP:
			lcp_recv_echo_repl(lcp,(uint8_t*)(hdr+1),ntohs(hdr->len)-PPP_HDRLEN);
			break;
		case PROTOREJ:
			log_ppp_debug("recv [LCP ProtoRej id=%x <%x>]\n",hdr->code, hdr->id, *(uint16_t*)(hdr + 1));
			break;
		case IDENT:
			term_msg = _strndup((char*)(hdr + 1) + 4, ntohs(hdr->len) - 4 - 4);
			log_ppp_debug("recv [LCP Ident id=%x <%s>]\n", hdr->id, term_msg);
			_free(term_msg);
			break;
		default:
			log_ppp_debug("recv [LCP Unknown %x]\n",hdr->code);
			ppp_fsm_recv_unk(&lcp->fsm);
			break;
	}
}

int lcp_option_register(struct lcp_option_handler_t *h)
{
	/*struct lcp_option_drv_t *p;

	list_for_each_entry(p,option_drv_list,entry)
		if (p->id==h->id) 
			return -1;*/
	
	list_add_tail(&h->entry,&option_handlers);

	return 0;
}

static struct ppp_layer_t lcp_layer=
{
	.init=lcp_layer_init,
	.start=lcp_layer_start,
	.finish=lcp_layer_finish,
	.free=lcp_layer_free,
};

static void __init lcp_init(void)
{
	char *opt;

	ppp_register_layer("lcp",&lcp_layer);

	opt = conf_get_opt("lcp", "echo-interval");
	if (opt && atoi(opt) > 0)
		conf_echo_interval = atoi(opt);

	opt = conf_get_opt("lcp", "echo-failure");
	if (opt && atoi(opt) > 0)
		conf_echo_failure = atoi(opt);

}
