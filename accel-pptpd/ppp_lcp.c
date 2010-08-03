#include <stdlib.h>
#include <string.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>
#include <arpa/inet.h>

#include "triton/triton.h"

#include "ppp.h"
#include "ppp_fsm.h"
#include "events.h"
#include "log.h"

char* accomp="allow,disabled";
char* pcomp="allow,disabled";
char* auth="pap,mschap-v2";
char* mppe="allow,disabled";
char* pwdb="radius";

/*
 * Options.
 */
#define CI_VENDOR	0	/* Vendor Specific */
#define CI_MRU		1	/* Maximum Receive Unit */
#define CI_ASYNCMAP	2	/* Async Control Character Map */
#define CI_AUTHTYPE	3	/* Authentication Type */
#define CI_QUALITY	4	/* Quality Protocol */
#define CI_MAGICNUMBER	5	/* Magic Number */
#define CI_PCOMPRESSION	7	/* Protocol Field Compression */
#define CI_ACCOMPRESSION 8	/* Address/Control Field Compression */
#define CI_FCSALTERN	9	/* FCS-Alternatives */
#define CI_SDP		10	/* Self-Describing-Pad */
#define CI_NUMBERED	11	/* Numbered-Mode */
#define CI_CALLBACK	13	/* callback */
#define CI_MRRU		17	/* max reconstructed receive unit; multilink */
#define CI_SSNHF	18	/* short sequence numbers for multilink */
#define CI_EPDISC	19	/* endpoint discriminator */
#define CI_MPPLUS	22	/* Multi-Link-Plus-Procedure */
#define CI_LDISC	23	/* Link-Discriminator */
#define CI_LCPAUTH	24	/* LCP Authentication */
#define CI_COBS		25	/* Consistent Overhead Byte Stuffing */
#define CI_PREFELIS	26	/* Prefix Elision */
#define CI_MPHDRFMT	27	/* MP Header Format */
#define CI_I18N		28	/* Internationalization */
#define CI_SDL		29	/* Simple Data Link */

/*static void layer_up(struct ppp_layer_t*);
static void layer_down(struct ppp_layer_t*);
static void layer_started(struct ppp_layer_t*);
static void layer_finished(struct ppp_layer_t*);*/
static void send_conf_req(struct ppp_layer_t*);
static void send_conf_ack(struct ppp_layer_t*);
static void send_conf_nak(struct ppp_layer_t*);
static void send_conf_rej(struct ppp_layer_t*);
static void lcp_recv(struct ppp_layer_t*`);

struct ppp_layer_t* ppp_lcp_init(struct ppp_t *ppp)
{
	struct ppp_layer_t *layer=malloc(sizeof(*layer));
	memset(layer,0,sizeof(*layer));

	layer->proto=PPP_PROTO_LCP;
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

/*void ev_ppp_packet(int proto,struct ppp_t *ppp)
{
	struct ppp_hdr_t *hdr;

	if (proto!=PPP_LCP) return;
	if (ppp->in_buf_size-2<PPP_HEADERLEN)
	{
		log_debug("LCP: short packet received\n");
		return;
	}

	hdr=(struct ppp_hdr_t *)(ppp->in_buf+2);
	if (hdr->len<PPP_HEADERLEN)
	{
		log_debug("LCP: short packet received\n");
		return;
	}

	//ppp_fsm_recv();
}*/

/*static void layer_up(struct ppp_layer_t*)
{
}
static void layer_down(struct ppp_layer_t*)
{
}
static void layer_started(struct ppp_layer_t*)
{
}
static void layer_finished(struct ppp_layer_t*)
{
}*/
static void send_conf_req(struct ppp_layer_t*l)
{
}
static void send_conf_ack(struct ppp_layer_t*l)
{
}
static void send_conf_nak(struct ppp_layer_t*l)
{
}
static void send_conf_rej(struct ppp_layer_t*l)
{
}

static int lcp_recv_conf_req(struct ppp_layer_t*l,u_int8_t *data,int size)
{
	struct ppp_opt_t *opt;
	while(size)
	{
		opt=(struct ppp_opt_t *)data;
		switch(opt->type)
		{
			case CI_MRU:
				l->options.lcp.mru=*(u_int16_t*)data;
				break;
			case CI_ASYNCMAP:
				break;
			case CI_AUTHTYPE:
				if (l->ppp->log) log_msg("<auth ");
				switch(*(u_int16_t*)data)
				{
					case PPP_PAP:
						if (l->ppp->log) log_msg("pap");
						break;
					case PPP_EAP:
						if (l->ppp->log) log_msg("eap");
						break;
					case PPP_CHAP:
						if (l->ppp->log) log_msg("chap");
						break;
						/*switch(data[4])
						{
							case 
						}*/
					default:
						if (l->ppp->log) log_msg("unknown");
						return -1;
				}
				if (l->ppp->log) log_msg(" auth>");
			case CI_MAGICNUMBER:
				if (*(u_int32_t*)data==l->magic_num)
				{
					log_error("loop detected\n");
					return -1;
				}
				break;
			case CI_PCOMPRESSION:
			case CI_ACCOMPRESSION:
		}
	}
	return 0;
}

static void lcp_recv(struct ppp_layer_t*l)
{
	struct ppp_hdr_t *hdr;
	
	if (l->ppp->in_buf_size-2<PPP_HEADERLEN)
	{
		log_debug("LCP: short packet received\n");
		return;
	}

	hdr=(struct ppp_hdr_t *)(l->ppp->in_buf+2);
	if (hdr->len<PPP_HEADERLEN)
	{
		log_debug("LCP: short packet received\n");
		return;
	}

	l->recv_id=hdr->id;
	switch(hdr->code)
	{
		case CONFREQ:
			if (lcp_recv_conf_req(l,hdr->data,ntohs(hdr->len)-PPP_HDRLEN))
				ppp_fsm_recv_conf_req_bad(l);
			else
				ppp_fsm_recv_conf_req_good(l);
			break;
		case CONFACK:
			lcp_recv_conf_ack(l,hdr->data,ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_ack(l);
			break;
		case CONFNAK:
			lcp_recv_conf_nak(l,hdr->data,ntohs(hdr->len)-PPP_HDRLEN);
			ppp_fsm_recv_conf_nak(l);
			break;
		case CONFREJ:
			lcp_recv_conf_rej(l,hdr->data,ntohs(hdr->len)-PPP_HDRLEN);
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
			ppp_fsm_recv_echo_req(l);
			break;
		case ECHOREP:
			lcp_recv_echo_rep(l);
			break;
		default:
			ppp_fsm_recv_unk(l);
			break;
	}
}
