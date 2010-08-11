#include "log.h"
#include "ppp.h"
#include "ppp_auth.h"

#define MSG_FAILED "Authentication failed"
#define MSG_SUCCESSED "Authentication successed"

#define HDR_LEN (sizeof(struct pap_hdr_t)-2)

static int lcp_get_conf_req(struct auth_driver_t*, struct ppp_t*, struct lcp_opt32_t*);
static int lcp_recv_conf_req(struct auth_driver_t*, struct ppp_t*, struct lcp_opt32_t*);
static int begin(struct auth_driver_t*, struct ppp_t*);
static int terminate(struct auth_driver_t*, struct ppp_t*);
static void pap_recv(struct ppp_handler_t*h);

struct pap_proto_t
{
	struct ppp_handler_t h;
	struct ppp_t *ppp;
};

struct pap_hdr_t
{
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

struct pap_ack_t
{
	struct pap_hdr_t hdr;
	uint8_t msg_len;
	char msg[0];
} __attribute__((packed));

static struct auth_driver_t pap=
{
	.type=PPP_PAP,
	.get_conf_req=lcp_get_conf_req,
	.recv_conf_req=lcp_recv_conf_req,
	.start=pap_start,
	.finish=pap_finish,
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

static int pap_start(struct auth_driver_t *d, struct ppp_t *ppp)
{
	struct pap_proto_t *p=malloc(sizeof(*p));

	memset(&p,0,sizeof(*p));
	p->h.proto=PPP_PAP;
	p->h.recv=pap_recv;
	p->ppp=ppp;
	ppp->auth_pd=p;

	ppp_register_handler(p->ppp,p->h);

	return 0;
}
static int pap_finish(struct auth_driver_t *d, struct ppp_t *ppp)
{
	struct pap_proto_t *p=(struct pap_proto_t*)ppp->auth_pd;

	ppp_unregister_handler(p->ppp,p->h);

	free(p);

	return 0;
}

static int lcp_get_conf_req(struct auth_driver_t *d, struct ppp_t *ppp, struct lcp_opt32_t *opt)
{
	return 0;
}

static int lcp_recv_conf_req(struct auth_driver_t *d, struct ppp_t *ppp, struct lcp_opt32_t *opt)
{
	return 0;
}

static void pap_send_ack(struct pap_proto_t *p, int id)
{
	uint8_t buf[128];
	struct pap_ack_t *msg=(struct pap_ack_t*)buf;
	msg->hdr.proto=PPP_PAP;
	msg->hdr.code=PAP_ACK;
	msg->hdr.id=id;
	msg->hdr.len=HDR_LEN+1+sizeof(MSG_SUCCESSED);
	msg->len=sizeof(MSG_SUCCESSED);
	memcpy(msg->msg,MSG_SUCCESSED,sizeof(MSG_SUCCESSED));
	
	ppp_send(p->ppp,msg,msg->hdr.len+2);
}

static void pap_send_nack(struct pap_proto_t *p,int id)
{
	uint8_t buf[128];
	struct pap_ack_t *msg=(struct pap_ack_t*)buf;
	msg->hdr.proto=PPP_PAP;
	msg->hdr.code=PAP_NACK;
	msg->hdr.id=id;
	msg->hdr.len=HDR_LEN+1+sizeof(MSG_FAILED);
	msg->len=sizeof(MSG_FAILED);
	memcpy(msg->msg,MSG_FAILED,sizeof(MSG_FAILED));
	
	ppp_send(p->ppp,msg,msg->hdr.len+2);
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
		pap_send_nack(p,hdr->id);
		auth_failed(p->ppp);
		ret=-1;
	}else
	{
		pap_send_ack(p,hdr->id);
		auth_successed(p->ppp);
		ret=0;
	}

	free(peer_id);
	free(passwd);

	return ret;
}

static void pap_recv(struct ppp_handler_t *h)
{
	struct pap_proto_t *p=container_of(h,typeof(*p),h);
	struct pap_hdr_t *hdr=(struct pap_hdr_t *)p->ppp->in_buf;

	if (p->ppp->in_buf_size<sizeof(*hdr) || htons(hdr->len)<HDR_LEN || htons(hdr->len)<p->ppp->in_buf_size-2)
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

