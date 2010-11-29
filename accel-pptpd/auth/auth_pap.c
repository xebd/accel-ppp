#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "log.h"
#include "ppp.h"
#include "ppp_auth.h"
#include "ppp_lcp.h"
#include "pwdb.h"

#include "memdebug.h"

#define MSG_FAILED "Authentication failed"
#define MSG_SUCCESSED "Authentication successed"

#define HDR_LEN (sizeof(struct pap_hdr_t)-2)

#define PAP_REQ 1
#define PAP_ACK 2
#define PAP_NAK 3

static int conf_timeout = 5;
static int conf_any_login = 0;

static struct auth_data_t* auth_data_init(struct ppp_t *ppp);
static void auth_data_free(struct ppp_t*, struct auth_data_t*);
static int lcp_send_conf_req(struct ppp_t*, struct auth_data_t*, uint8_t*);
static int lcp_recv_conf_req(struct ppp_t*, struct auth_data_t*, uint8_t*);
static int pap_start(struct ppp_t*, struct auth_data_t*);
static int pap_finish(struct ppp_t*, struct auth_data_t*);
static void pap_recv(struct ppp_handler_t*h);
static void pap_timeout(struct triton_timer_t *t);

struct pap_auth_data_t
{
	struct auth_data_t auth;
	struct ppp_handler_t h;
	struct ppp_t *ppp;
	int started:1;
	struct triton_timer_t timeout;
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

static struct ppp_auth_handler_t pap=
{
	.name          = "PAP",
	.init          = auth_data_init,
	.free          = auth_data_free,
	.send_conf_req = lcp_send_conf_req,
	.recv_conf_req = lcp_recv_conf_req,
	.start         = pap_start,
	.finish        = pap_finish,
};

static struct auth_data_t* auth_data_init(struct ppp_t *ppp)
{
	struct pap_auth_data_t *d = _malloc(sizeof(*d));

	memset(d, 0, sizeof(*d));
	d->auth.proto = PPP_PAP;
	d->ppp = ppp;

	return &d->auth;
}

static void auth_data_free(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct pap_auth_data_t *d = container_of(auth, typeof(*d), auth);

	_free(d);
}

static int pap_start(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct pap_auth_data_t *d = container_of(auth, typeof(*d), auth);

	d->h.proto = PPP_PAP;
	d->h.recv = pap_recv;
	d->timeout.expire = pap_timeout;
	d->timeout.period = conf_timeout * 1000;

	triton_timer_add(ppp->ctrl->ctx, &d->timeout, 0);

	ppp_register_chan_handler(ppp, &d->h);

	return 0;
}
static int pap_finish(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct pap_auth_data_t *d = container_of(auth, typeof(*d), auth);
	
	if (d->timeout.tpd)
		triton_timer_del(&d->timeout);

	ppp_unregister_handler(ppp, &d->h);

	return 0;
}

static void pap_timeout(struct triton_timer_t *t)
{
	struct pap_auth_data_t *d = container_of(t, typeof(*d), timeout);

	if (conf_ppp_verbose)
		log_ppp_warn("pap: timeout\n");

	ppp_auth_failed(d->ppp, NULL);
}

static int lcp_send_conf_req(struct ppp_t *ppp, struct auth_data_t *d, uint8_t *ptr)
{
	return 0;
}

static int lcp_recv_conf_req(struct ppp_t *ppp, struct auth_data_t *d, uint8_t *ptr)
{
	return LCP_OPT_ACK;
}

static void pap_send_ack(struct pap_auth_data_t *p, int id)
{
	uint8_t buf[128];
	struct pap_ack_t *msg = (struct pap_ack_t*)buf;
	msg->hdr.proto = htons(PPP_PAP);
	msg->hdr.code = PAP_ACK;
	msg->hdr.id = id;
	msg->hdr.len = htons(HDR_LEN + 1 + sizeof(MSG_SUCCESSED) - 1);
	msg->msg_len = sizeof(MSG_SUCCESSED) - 1;
	memcpy(msg->msg, MSG_SUCCESSED, sizeof(MSG_SUCCESSED));
	
	if (conf_ppp_verbose)
		log_ppp_info2("send [PAP AuthAck id=%x \"%s\"]\n", id, MSG_SUCCESSED);
	
	ppp_chan_send(p->ppp, msg, ntohs(msg->hdr.len) + 2);
}

static void pap_send_nak(struct pap_auth_data_t *p, int id)
{
	uint8_t buf[128];
	struct pap_ack_t *msg = (struct pap_ack_t*)buf;
	msg->hdr.proto = htons(PPP_PAP);
	msg->hdr.code = PAP_NAK;
	msg->hdr.id = id;
	msg->hdr.len = htons(HDR_LEN + 1 + sizeof(MSG_FAILED) - 1);
	msg->msg_len = sizeof(MSG_FAILED) - 1;
	memcpy(msg->msg, MSG_FAILED, sizeof(MSG_FAILED));
	
	if (conf_ppp_verbose)
		log_ppp_info2("send [PAP AuthNak id=%x \"%s\"]\n", id, MSG_FAILED);
	
	ppp_chan_send(p->ppp, msg, ntohs(msg->hdr.len) + 2);
}

static int pap_recv_req(struct pap_auth_data_t *p, struct pap_hdr_t *hdr)
{
	int ret, r;
	char *peer_id;
	char *passwd;
	char *passwd2;
	int peer_id_len;
	int passwd_len;
	uint8_t *ptr = (uint8_t*)(hdr + 1);

	if (p->timeout.tpd)
		triton_timer_del(&p->timeout);

	if (conf_ppp_verbose)
		log_ppp_info2("recv [PAP AuthReq id=%x]\n", hdr->id);

	peer_id_len = *(uint8_t*)ptr; ptr++;
	if (peer_id_len > ntohs(hdr->len) - sizeof(*hdr) + 2 - 1) {
		log_ppp_warn("PAP: short packet received\n");
		return -1;
	}
	peer_id = (char*)ptr; ptr += peer_id_len;

	passwd_len = *(uint8_t*)ptr; ptr++;
	if (passwd_len > ntohs(hdr->len) - sizeof(*hdr ) + 2 - 2 - peer_id_len) {
		log_ppp_warn("PAP: short packet received\n");
		return -1;
	}

	peer_id = _strndup((const char*)peer_id, peer_id_len);
	
	if (conf_any_login) {
		pap_send_ack(p, hdr->id);
		p->started = 1;
		ppp_auth_successed(p->ppp, peer_id);
		return 0;
	}

	passwd = _strndup((const char*)ptr, passwd_len);

	r = pwdb_check(p->ppp, peer_id, PPP_PAP, passwd);
	if (r == PWDB_NO_IMPL) {
		passwd2 = pwdb_get_passwd(p->ppp, peer_id);
		if (!passwd2 || strcmp(passwd2, passwd))
			r = PWDB_DENIED;
		else
			r = PWDB_SUCCESS;
		_free(passwd2);
	}
	if (r == PWDB_DENIED) {
		if (conf_ppp_verbose)
			log_ppp_warn("PAP: authentication error\n");
		pap_send_nak(p, hdr->id);
		if (p->started)
			ppp_terminate(p->ppp, TERM_AUTH_ERROR, 0);
		else
			ppp_auth_failed(p->ppp, peer_id);
		ret=-1;
		_free(peer_id);
	} else {
		pap_send_ack(p, hdr->id);
		if (!p->started) {
			p->started = 1;
			ppp_auth_successed(p->ppp, peer_id);
		}
		ret = 0;
	}

	_free(passwd);

	return ret;
}

static void pap_recv(struct ppp_handler_t *h)
{
	struct pap_auth_data_t *d = container_of(h, typeof(*d), h);
	struct pap_hdr_t *hdr = (struct pap_hdr_t *)d->ppp->chan_buf;

	if (d->ppp->chan_buf_size < sizeof(*hdr) || ntohs(hdr->len) < HDR_LEN || ntohs(hdr->len) < d->ppp->chan_buf_size - 2)	{
		log_ppp_warn("PAP: short packet received\n");
		return;
	}

	if (hdr->code == PAP_REQ)
		pap_recv_req(d, hdr);
	else {
		log_ppp_warn("PAP: unknown code received %x\n",hdr->code);
	}
}

static void __init auth_pap_init()
{
	char *opt;

	opt = conf_get_opt("auth", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("auth", "any-login");
	if (opt && atoi(opt) > 0)
		conf_any_login = 1;

	ppp_auth_register_handler(&pap);
}

