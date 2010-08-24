#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <byteswap.h>
#include <arpa/inet.h>

#include <openssl/md4.h>
#include <openssl/des.h>

#include "log.h"
#include "ppp.h"
#include "ppp_auth.h"
#include "ppp_lcp.h"
#include "pwdb.h"

#define CHAP_CHALLENGE 1
#define CHAP_RESPONSE  2
#define CHAP_SUCCESS   3
#define CHAP_FAILURE   4

#define VALUE_SIZE 8
#define RESPONSE_VALUE_SIZE (24+24+1)

#define MSG_FAILURE   "E=691 R=0"
#define MSG_SUCCESS   "Authentication successed"

#define HDR_LEN (sizeof(struct chap_hdr_t)-2)

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

struct chap_response_t
{
	struct chap_hdr_t hdr;
	uint8_t val_size;
	uint8_t lm_hash[24];
	uint8_t nt_hash[24];
	uint8_t use_nt_hash;
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
};

static void chap_send_challenge(struct chap_auth_data_t *ad);
static void chap_recv(struct ppp_handler_t *h);
static int chap_check_response(struct chap_auth_data_t *ad, struct chap_response_t *res);

static void print_buf(const uint8_t *buf,int size)
{
	int i;
	for(i=0;i<size;i++)
		log_debug("%x",buf[i]);
}
static void print_str(const char *buf,int size)
{
	int i;
	for(i=0;i<size;i++)
		log_debug("%c",buf[i]);
}



static struct auth_data_t* auth_data_init(struct ppp_t *ppp)
{
	struct chap_auth_data_t *d=malloc(sizeof(*d));

	memset(d,0,sizeof(*d));
	d->auth.proto=PPP_CHAP;
	d->ppp=ppp;

	return &d->auth;
}

static void auth_data_free(struct ppp_t *ppp,struct auth_data_t *auth)
{
	struct chap_auth_data_t *d=container_of(auth,typeof(*d),auth);

	free(d);
}

static int chap_start(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data_t *d=container_of(auth,typeof(*d),auth);

	d->h.proto=PPP_CHAP;
	d->h.recv=chap_recv;

	ppp_register_chan_handler(ppp,&d->h);

	chap_send_challenge(d);

	return 0;
}

static int chap_finish(struct ppp_t *ppp, struct auth_data_t *auth)
{
	struct chap_auth_data_t *d=container_of(auth,typeof(*d),auth);

	ppp_unregister_handler(ppp,&d->h);

	return 0;
}

static int lcp_send_conf_req(struct ppp_t *ppp, struct auth_data_t *d, uint8_t *ptr)
{
	*ptr=0x80;
	return 1;
}

static int lcp_recv_conf_req(struct ppp_t *ppp, struct auth_data_t *d, uint8_t *ptr)
{
	if (*ptr==0x80)
		return LCP_OPT_ACK;
	return LCP_OPT_NAK;
}

static void chap_send_failure(struct chap_auth_data_t *ad)
{
	struct chap_failure_t msg=
	{
		.hdr.proto=htons(PPP_CHAP),
		.hdr.code=CHAP_FAILURE,
		.hdr.id=ad->id,
		.hdr.len=htons(sizeof(msg)-1-2),
		.message=MSG_FAILURE,
	};
	
	log_debug("send [MSCHAP-v1 Failure id=%x \"%s\"]\n",msg.hdr.id,MSG_FAILURE);

	ppp_chan_send(ad->ppp,&msg,ntohs(msg.hdr.len)+2);
}

static void chap_send_success(struct chap_auth_data_t *ad)
{
	struct chap_success_t msg=
	{
		.hdr.proto=htons(PPP_CHAP),
		.hdr.code=CHAP_SUCCESS,
		.hdr.id=ad->id,
		.hdr.len=htons(sizeof(msg)-1-2),
		.message=MSG_SUCCESS,
	};
	
	log_debug("send [MSCHAP-v1 Success id=%x \"%s\"]\n",msg.hdr.id,MSG_SUCCESS);

	ppp_chan_send(ad->ppp,&msg,ntohs(msg.hdr.len)+2);
}

static void chap_send_challenge(struct chap_auth_data_t *ad)
{
	struct chap_challenge_t msg=
	{
		.hdr.proto=htons(PPP_CHAP),
		.hdr.code=CHAP_CHALLENGE,
		.hdr.id=++ad->id,
		.hdr.len=htons(sizeof(msg)-2),
		.val_size=VALUE_SIZE,
	};

	read(urandom_fd,ad->val,VALUE_SIZE);
	memcpy(msg.val,ad->val,VALUE_SIZE);

	log_debug("send [MSCHAP-v1 Challenge id=%x <",msg.hdr.id);
	print_buf(msg.val,VALUE_SIZE);
	log_debug(">]\n");

	ppp_chan_send(ad->ppp,&msg,ntohs(msg.hdr.len)+2);
}

static void chap_recv_response(struct chap_auth_data_t *ad, struct chap_hdr_t *hdr)
{
	struct chap_response_t *msg=(struct chap_response_t*)hdr;

	log_debug("recv [MSCHAP-v1 Response id=%x <", msg->hdr.id);
	print_buf(msg->lm_hash,24);
	log_debug(">, <");
	print_buf(msg->nt_hash,24);
	log_debug(">, F=%i, name=\"",msg->use_nt_hash);
	print_str(msg->name,ntohs(msg->hdr.len)-sizeof(*msg)+2);
	log_debug("\"]\n");

	if (msg->hdr.id!=ad->id)
	{
		log_error("mschap-v1: id mismatch\n");
		chap_send_failure(ad);
		ppp_terminate(ad->ppp);
	}

	if (msg->val_size!=RESPONSE_VALUE_SIZE)
	{
		log_error("mschap-v1: value-size should be %i, expected %i\n",RESPONSE_VALUE_SIZE,msg->val_size);
		chap_send_failure(ad);
		ppp_terminate(ad->ppp);
	}

	if (chap_check_response(ad,msg))
	{
		chap_send_failure(ad);
		auth_failed(ad->ppp);
	}else
	{
		chap_send_success(ad);
		auth_successed(ad->ppp);
	}
}

static void des_encrypt(const uint8_t *input, const uint8_t *key, uint8_t *output)
{
	int i,j,parity;
	union
	{
		uint64_t u64;
		uint8_t buf[8];
	} p_key;
	DES_cblock cb;
	DES_cblock res;
	DES_key_schedule ks;

	memcpy(p_key.buf,key,7);
	p_key.u64=bswap_64(p_key.u64);

	for(i=0;i<8;i++)
	{
		cb[i]=(((p_key.u64<<(7*i))>>56)&0xfe);
		for(j=0, parity=0; j<7; j++)
			if ((cb[i]>>(j+1))&1) parity++;
		cb[i]|=(~parity)&1;
	}

	DES_set_key_checked(&cb, &ks);
	memcpy(cb,input,8);
	DES_ecb_encrypt(&cb,&res,&ks,DES_ENCRYPT);
	memcpy(output,res,8);	
}

static int chap_check_response(struct chap_auth_data_t *ad, struct chap_response_t *msg)
{
	MD4_CTX md4_ctx;
	uint8_t z_hash[21];
	uint8_t nt_hash[24];
	char *passwd;
	char *u_passwd;
	char *name;
	int i;
	
	name=strndup(msg->name,ntohs(msg->hdr.len)-sizeof(*msg)+2);
	passwd=pwdb_get_passwd(ad->ppp,name);
	if (!passwd)
	{
		free(name);
		log_debug("mschap-v1: user not found\n");
		chap_send_failure(ad);
		return -1;
	}

	u_passwd=malloc(strlen(passwd)*2);
	for(i=0; i<strlen(passwd); i++)
	{
		u_passwd[i*2]=passwd[i];
		u_passwd[i*2+1]=0;
	}

	memset(z_hash,0,sizeof(z_hash));
	MD4_Init(&md4_ctx);
	MD4_Update(&md4_ctx,u_passwd,strlen(passwd)*2);
	MD4_Final(z_hash,&md4_ctx);

	des_encrypt(ad->val,z_hash,nt_hash);
	des_encrypt(ad->val,z_hash+7,nt_hash+8);
	des_encrypt(ad->val,z_hash+14,nt_hash+16);

	free(name);
	free(passwd);
	free(u_passwd);

	return memcmp(nt_hash,msg->nt_hash,24);
}

static struct ppp_auth_handler_t chap=
{
	.name="MSCHAP-v1",
	.init=auth_data_init,
	.free=auth_data_free,
	.send_conf_req=lcp_send_conf_req,
	.recv_conf_req=lcp_recv_conf_req,
	.start=chap_start,
	.finish=chap_finish,
};

static void chap_recv(struct ppp_handler_t *h)
{
	struct chap_auth_data_t *d=container_of(h,typeof(*d),h);
	struct chap_hdr_t *hdr=(struct chap_hdr_t *)d->ppp->chan_buf;

	if (d->ppp->chan_buf_size<sizeof(*hdr) || ntohs(hdr->len)<HDR_LEN || ntohs(hdr->len)<d->ppp->chan_buf_size-2)
	{
		log_warn("mschap-v1: short packet received\n");
		return;
	}

	if (hdr->code==CHAP_RESPONSE) chap_recv_response(d,hdr);
	else
	{
		log_warn("mschap-v1: unknown code received %x\n",hdr->code);
	}
}

static void __init auth_chap_md5_init()
{
	urandom_fd=open("/dev/urandom",O_RDONLY);
	if (urandom_fd<0)
	{
		log_error("mschap-v1: failed to open /dev/urandom: %s\n",strerror(errno));
		return;
	}
	if (ppp_auth_register_handler(&chap))
		log_error("mschap-v1: failed to register handler\n");
}

