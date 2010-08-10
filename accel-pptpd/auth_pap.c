#include "log.h"
#include "ppp_auth.h"

static int lcp_get_conf_req(struct auth_driver_t*, struct ppp_layer_t*, struct lcp_opt32_t*);
static int lcp_recv_conf_req(struct auth_driver_t*, struct ppp_layer_t*, struct lcp_opt32_t*);
static int lcp_conf_established(struct auth_driver_t*, struct ppp_layer_t*);
static void pap_recv(struct ppp_handler_t*h);

struct pap_proto_t
{
	struct ppp_handler_t h;
	struct ppp_t *ppp;
	struct ppp_layer_t *lcp;
};

struct pap_hdr_t
{
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

static struct auth_driver_t pap=
{
	.type=PPP_PAP,
	.get_conf_req=lcp_get_conf_req,
	.recv_conf_req=lcp_recv_conf_req,
	.established=lcp_established,
};


int plugin_init(void)
{
	if (auth_register(&pap))
	{
		log_error("pap: failed to register driver\n");
		return -1;
	}

	return 0;
}

static int lcp_established(struct auth_driver_t*d, struct ppp_layer_t*lcp)
{
	struct pap_proto_t *p=malloc(sizeof(*l));

	memset(&p,0,sizeof(*l));
	p->h.proto=PPP_PAP;
	p->h.recv=pap_recv;
	p->ppp=lcp->ppp;
	p->lcp=lcp;

	ppp_register_handler(p->ppp,p->h);
}

static int lcp_get_conf_req(struct auth_driver_t*, struct ppp_layer_t*, struct lcp_opt32_t*)
{
}

static int lcp_recv_conf_req(struct auth_driver_t*, struct ppp_layer_t*, struct lcp_opt32_t*)
{
}

static void pap_send_nack(struct pap_proto_t *p,struct pap_hdr_t *hdr)
{

}

static int pap_recv_req(struct pap_proto_t *p,struct pap_hdr_t *hdr)
{
	int ret;
	char *peer_id;
	char *passwd;
	int peer_id_len;
	int passwd_len;
	uint8_t *ptr=(uint8_t*)(hdr+1);
	
	peer_id_len=*(uint8_t*)ptr; ptr++;
	if (peer_id_len>htons(hdr->len)-sizeof(*hdr)-1)
	{
		log_warn("PAP: short packet received\n");
		return -1;
	}
	peer_id=ptr; ptr+=peer_id_len;

	passwd_len=*(uint8_t*)ptr; ptr++;
	if (passwd_len>htons(hdr->len)-sizeof(*hdr)-2-peer_id_len)
	{
		log_warn("PAP: short packet received\n");
		return -1;
	}

	peer_id=stdndup(peer_id,peer_id_len);
	passwd=stdndup(ptr,passwd_len);

	if (pwdb_check(peer_id,passwd))
	{
		log_warn("PAP: authentication error\n");
		pap_send_nack(p,hdr);
		ret=-1;
	}else ret=0;

	free(peer_id);
	free(passwd);

	pap_send_ack(p,hdr);
	return 0;
}

static void pap_recv(struct ppp_handler_t*h)
{
	struct pap_proto_t *p=container_of(h,typeof(*p),h);
	struct pap_hdr_t *hdr;

	if (p->ppp->in_buf_size<sizeof(*hdr)+2 || htons(hdr->len)<sizeof(*hdr) || htons(hdr->len)<p->ppp->in_buf_size-2)
	{
		log_warn("PAP: short packet received\n");
		return;
	}

	hdr=(struct pap_hdr_t *)p->ppp->in_buf;
	if (ntohs(hdr->len)<sizeof(*hdr) ||)
	{
		log_warn("PAP: short packet received\n");
		return;
	}

	if (hdr->code==PAP_REQ) pap_recv_req(p,hdr);
	else
	{
		log_warn("PAP: unknown code received %x\n",hdr->code);
	}
}

