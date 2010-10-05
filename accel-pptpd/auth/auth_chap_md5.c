#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>

#include <openssl/md5.h>

#include "log.h"
#include "ppp.h"
#include "ppp_auth.h"
#include "ppp_lcp.h"
#include "pwdb.h"

#include "memdebug.h"

#define CHAP_CHALLENGE 1
#define CHAP_RESPONSE  2
#define CHAP_SUCCESS   3
#define CHAP_FAILURE   4

#define CHAP_MD5 5

#define VALUE_SIZE 16

#define MSG_FAILURE   "Authentication failed"
#define MSG_SUCCESS   "Authentication successed"

#define HDR_LEN (sizeof(struct chap_hdr_t)-2)

static int conf_timeout = 5;
static int conf_interval = 0;
static int conf_max_failure = 3;

static int urandom_fd;

struct chap_hdr_t
{
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));

struct chap_challenge_t
{
	struct chap_hdr_t hdr;
	uint8_t val_size;
	uint8_t val[VALUE_SIZE];
	char name[0];
} __attribute__((packed));

struct chap_failure_t
{
	struct chap_hdr_t hdr;
	char message[sizeof(MSG_FAILURE)];
} __attribute__((packed));

struct chap_success_t
{
	struct chap_hdr_t hdr;
	char message[sizeof(MSG_SUCCESS)];
} __attribute__((packed));


struct chap_auth_data_t
{
	struct auth_data_t auth;
	struct ppp_handler_t h;
	struct ppp_t *ppp;
	int id;
	uint8_t val[VALUE_SIZE];
	struct triton_timer_t timeout;
	struct triton_timer_t interval;
	int failure;
	int started:1;
};

static void chap_send_challenge(struct chap_auth_data_t *ad);
static void chap_recv(struct ppp_handler_t *h);
static void chap_timeout(struct triton_timer_t *t);
static void chap_restart(struct triton_timer_t *t);

static void print_buf(const uint8_t *buf, int size)
{
	int i;
	for (i=0; i < size; i++)
		log_ppp_info("%x", buf[i]);
}
static void print_str(const char *buf, int size)
{
	int i;
	for (i = 0; i < size; i++)
		log_ppp_info("%c", buf[i]);
}

static struct auth_data_t* auth_data_init(struct ppp_t *ppp)
{
	struct chap_auth_data_t *d = _malloc(sizeof(*d));

	memset(d, 0, sizeof(*d));
	d->auth.proto = PPP_CHAP;
	d->ppp = ppp;

	return &d->auth;
}

static void auth_data_free(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data_t *d = container_of(auth, typeof(*d), auth);

	_free(d);
}

static int chap_start(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data_t *d = container_of(auth, typeof(*d), auth);

	d->h.proto = PPP_CHAP;
	d->h.recv = chap_recv;
	d->timeout.expire = chap_timeout;
	d->timeout.period = conf_timeout * 1000;
	d->interval.expire = chap_restart;
	d->interval.period = conf_interval * 1000;

	ppp_register_chan_handler(ppp, &d->h);

	chap_send_challenge(d);

	return 0;
}

static int chap_finish(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data_t *d = container_of(auth, typeof(*d), auth);

	if (d->timeout.tpd)
		triton_timer_del(&d->timeout);

	if (d->interval.tpd)
		triton_timer_del(&d->interval);

	ppp_unregister_handler(ppp, &d->h);

	return 0;
}

static void chap_timeout(struct triton_timer_t *t)
{
	struct chap_auth_data_t *d = container_of(t, typeof(*d), timeout);

	if (conf_ppp_verbose)
		log_ppp_warn("chap-md5: timeout\n");

	if (++d->failure == conf_max_failure) {
		if (d->started)
			ppp_terminate(d->ppp, 0);
		else
			auth_failed(d->ppp);
	} else {
		--d->id;
		chap_send_challenge(d);
	}
}

static void chap_restart(struct triton_timer_t *t)
{
	struct chap_auth_data_t *d = container_of(t, typeof(*d), interval);
	
	chap_send_challenge(d);
}

static int lcp_send_conf_req(struct ppp_t *ppp, struct auth_data_t *d, uint8_t *ptr)
{
	*ptr = CHAP_MD5;
	return 1;
}

static int lcp_recv_conf_req(struct ppp_t *ppp, struct auth_data_t *d, uint8_t *ptr)
{
	if (*ptr == CHAP_MD5)
		return LCP_OPT_ACK;
	return LCP_OPT_NAK;
}

static void chap_send_failure(struct chap_auth_data_t *ad)
{
	struct chap_failure_t msg = {
		.hdr.proto = htons(PPP_CHAP),
		.hdr.code = CHAP_FAILURE,
		.hdr.id = ad->id,
		.hdr.len = htons(sizeof(msg) - 1 - 2),
		.message = MSG_FAILURE,
	};
	
	if (conf_ppp_verbose)
		log_ppp_info("send [CHAP Failure id=%x \"%s\"]\n", msg.hdr.id, MSG_FAILURE);

	ppp_chan_send(ad->ppp, &msg, ntohs(msg.hdr.len) + 2);
}

static void chap_send_success(struct chap_auth_data_t *ad)
{
	struct chap_success_t msg =	{
		.hdr.proto = htons(PPP_CHAP),
		.hdr.code = CHAP_SUCCESS,
		.hdr.id = ad->id,
		.hdr.len = htons(sizeof(msg)-1-2),
		.message = MSG_SUCCESS,
	};
	
	if (conf_ppp_verbose)
		log_ppp_info("send [CHAP Success id=%x \"%s\"]\n", msg.hdr.id, MSG_SUCCESS);

	ppp_chan_send(ad->ppp, &msg, ntohs(msg.hdr.len) + 2);
}

static void chap_send_challenge(struct chap_auth_data_t *ad)
{
	struct chap_challenge_t msg =	{
		.hdr.proto = htons(PPP_CHAP),
		.hdr.code = CHAP_CHALLENGE,
		.hdr.id = ++ad->id,
		.hdr.len = htons(sizeof(msg) - 2),
		.val_size = VALUE_SIZE,
	};

	read(urandom_fd, ad->val, VALUE_SIZE);
	memcpy(msg.val, ad->val, VALUE_SIZE);

	if (conf_ppp_verbose) {
		log_ppp_info("send [CHAP Challenge id=%x <", msg.hdr.id);
		print_buf(msg.val, VALUE_SIZE);
		log_ppp_info(">]\n");
	}

	ppp_chan_send(ad->ppp, &msg, ntohs(msg.hdr.len) + 2);

	if (conf_timeout && !ad->timeout.tpd)
		triton_timer_add(ad->ppp->ctrl->ctx, &ad->timeout, 0);
}

static void chap_recv_response(struct chap_auth_data_t *ad, struct chap_hdr_t *hdr)
{
	MD5_CTX md5_ctx;
	uint8_t md5[MD5_DIGEST_LENGTH];
	char *passwd;
	char *name;
	int r;
	struct chap_challenge_t *msg = (struct chap_challenge_t*)hdr;

	if (ad->timeout.tpd)
		triton_timer_del(&ad->timeout);

	if (conf_ppp_verbose) {
		log_ppp_info("recv [CHAP Response id=%x <", msg->hdr.id);
		print_buf(msg->val, msg->val_size);
		log_ppp_info(">, name=\"");
		print_str(msg->name, ntohs(msg->hdr.len) - sizeof(*msg) + 2);
		log_ppp_info("\"]\n");
	}

	if (msg->hdr.id != ad->id) {
		if (conf_ppp_verbose)
			log_ppp_error("chap-md5: id mismatch\n");
		chap_send_failure(ad);
		ppp_terminate(ad->ppp, 0);
	}

	if (msg->val_size != VALUE_SIZE) {
		log_ppp_error("chap-md5: incorrect value-size (%i)\n", msg->val_size);
		chap_send_failure(ad);
		ppp_terminate(ad->ppp, 0);
	}

	name = _strndup(msg->name,ntohs(msg->hdr.len) - sizeof(*msg) + 2);

	r = pwdb_check(ad->ppp, name, PPP_CHAP, CHAP_MD5, ad->id, ad->val, VALUE_SIZE, msg->val);

	if (r == PWDB_NO_IMPL) {
		passwd = pwdb_get_passwd(ad->ppp,name);
		if (!passwd)
		{
			_free(name);
			if (conf_ppp_verbose)
				log_ppp_warn("chap-md5: user not found\n");
			chap_send_failure(ad);
			return;
		}

		MD5_Init(&md5_ctx);
		MD5_Update(&md5_ctx,&msg->hdr.id,1);
		MD5_Update(&md5_ctx,passwd,strlen(passwd));
		MD5_Update(&md5_ctx,ad->val,VALUE_SIZE);
		MD5_Final(md5,&md5_ctx);
		
		if (memcmp(md5,msg->val,sizeof(md5)))
		{
			if (conf_ppp_verbose)
				log_ppp_warn("chap-md5: challenge response mismatch\n");
			chap_send_failure(ad);
			if (ad->started)
				ppp_terminate(ad->ppp, 0);
			else
				auth_failed(ad->ppp);
		}else
		{
			chap_send_success(ad);
			if (!ad->started) {
				ad->started = 1;
				if (conf_interval)
					triton_timer_add(ad->ppp->ctrl->ctx, &ad->interval, 0);
				auth_successed(ad->ppp, name);
			}
		}
		_free(name);
		_free(passwd);
	} else if (r == PWDB_DENIED) {
		chap_send_failure(ad);
		_free(name);
		if (ad->started)
			ppp_terminate(ad->ppp, 0);
		else
			auth_failed(ad->ppp);
	} else {
		chap_send_success(ad);
		if (!ad->started) {
			ad->started = 1;
			if (conf_interval)
				triton_timer_add(ad->ppp->ctrl->ctx, &ad->interval, 0);
			auth_successed(ad->ppp, name);
		}
	}
}

static int chap_check(uint8_t *ptr)
{
	return *ptr == CHAP_MD5;
}

static struct ppp_auth_handler_t chap=
{
	.name          = "CHAP-md5",
	.init          = auth_data_init,
	.free          = auth_data_free,
	.send_conf_req = lcp_send_conf_req,
	.recv_conf_req = lcp_recv_conf_req,
	.start         = chap_start,
	.finish        = chap_finish,
	.check         = chap_check,
};

static void chap_recv(struct ppp_handler_t *h)
{
	struct chap_auth_data_t *d = container_of(h, typeof(*d), h);
	struct chap_hdr_t *hdr = (struct chap_hdr_t *)d->ppp->chan_buf;

	if (d->ppp->chan_buf_size < sizeof(*hdr) || ntohs(hdr->len) < HDR_LEN || ntohs(hdr->len) < d->ppp->chan_buf_size - 2)	{
		log_ppp_warn("chap-md5: short packet received\n");
		return;
	}

	if (hdr->code == CHAP_RESPONSE)
		chap_recv_response(d, hdr);
	else
		log_ppp_warn("chap-md5: unknown code received %x\n", hdr->code);
}

static void __init auth_chap_md5_init()
{
	char *opt;

	opt = conf_get_opt("auth", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("auth", "interval");
	if (opt && atoi(opt) > 0)
		conf_interval = atoi(opt);

	opt = conf_get_opt("auth", "max-failure");
	if (opt && atoi(opt) > 0)
		conf_max_failure = atoi(opt);

	urandom_fd=open("/dev/urandom", O_RDONLY);

	if (urandom_fd < 0) {
		log_emerg("chap-md5: failed to open /dev/urandom: %s\n", strerror(errno));
		return;
	}

	if (ppp_auth_register_handler(&chap))
		log_emerg("chap-md5: failed to register handler\n");
}

