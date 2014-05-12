#include <stdlib.h>
#include <string.h>

#include "crypto.h"

#include "triton.h"
#include "events.h"
#include "log.h"
#include "pwdb.h"

#include "radius_p.h"
#include "attr_defs.h"

#include "memdebug.h"

static int decrypt_chap_mppe_keys(struct rad_req_t *req, struct rad_attr_t *attr, const uint8_t *challenge, uint8_t *key)
{
	MD5_CTX md5_ctx;
	SHA_CTX sha1_ctx;
	uint8_t md5[MD5_DIGEST_LENGTH];
	uint8_t sha1[SHA_DIGEST_LENGTH];
	uint8_t plain[32];
	int i;
	
	if (attr->len != 32) {
		log_ppp_warn("radius: %s: incorrect attribute length (%i)\n", attr->attr->name, attr->len);
		return -1;
	}

	memcpy(plain, attr->val.octets, 32);

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, req->pack->buf + 4, 16);
	MD5_Final(md5, &md5_ctx);

	for (i = 0; i < 16; i++)
		plain[i] ^= md5[i];
	
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, attr->val.octets, 16);
	MD5_Final(md5, &md5_ctx);

	for (i = 0; i < 16; i++)
		plain[i + 16] ^= md5[i];
	
	SHA1_Init(&sha1_ctx);
	SHA1_Update(&sha1_ctx, plain + 8, 16);
	SHA1_Update(&sha1_ctx, plain + 8, 16);
	SHA1_Update(&sha1_ctx, challenge, 8);
	SHA1_Final(sha1, &sha1_ctx);

	memcpy(key, sha1, 16);

	return 0;
}

static int decrypt_mppe_key(struct rad_req_t *req, struct rad_attr_t *attr, uint8_t *key)
{
	MD5_CTX md5_ctx;
	uint8_t md5[16];
	uint8_t plain[32];
	int i;
	
	if (attr->len != 34) {
		log_ppp_warn("radius: %s: incorrect attribute length (%i)\n", attr->attr->name, attr->len);
		return -1;
	}

	if ((attr->val.octets[0] & 0x80) == 0) {
		log_ppp_warn("radius: %s: incorrect salt value (%x)\n", attr->attr->name, attr->len);
		return -1;
	}

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, req->pack->buf + 4, 16);
	MD5_Update(&md5_ctx, attr->val.octets, 2);
	MD5_Final(md5, &md5_ctx);

	memcpy(plain, attr->val.octets + 2, 32);

	for (i = 0; i < 16; i++)
		plain[i] ^= md5[i];
	
	if (plain[0] != 16) {
		log_ppp_warn("radius: %s: incorrect key length (%i)\n", attr->attr->name, plain[0]);
		return -1;
	}

	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, req->serv->secret, strlen(req->serv->secret));
	MD5_Update(&md5_ctx, attr->val.octets + 2, 16);
	MD5_Final(md5, &md5_ctx);

	plain[16] ^= md5[0];

	memcpy(key, plain + 1, 16);

	return 0;
}


static uint8_t* encrypt_password(const char *passwd, const char *secret, const uint8_t *RA, int *epasswd_len)
{
	uint8_t *epasswd;
	int i, j, chunk_cnt;
	uint8_t b[16], c[16];
	MD5_CTX ctx;

	if (strlen(passwd))
		chunk_cnt = (strlen(passwd) - 1) / 16 + 1;
	else {
		*epasswd_len = 0;
		return (uint8_t *)1;
	}
	
	epasswd = _malloc(chunk_cnt * 16);
	if (!epasswd) {
		log_emerg("radius: out of memory\n");
		return NULL;
	}

	memset(epasswd, 0, chunk_cnt * 16);
	memcpy(epasswd, passwd, strlen(passwd));
	memcpy(c, RA, 16);

	for (i = 0; i < chunk_cnt; i++) {
		MD5_Init(&ctx);
		MD5_Update(&ctx, secret, strlen(secret));
		MD5_Update(&ctx, c, 16);
		MD5_Final(b, &ctx);
	
		for(j = 0; j < 16; j++)
			epasswd[i * 16 + j] ^= b[j];

		memcpy(c, epasswd + i * 16, 16);
	}

	*epasswd_len = chunk_cnt * 16;
	return epasswd;
}

static int rad_auth_send(struct rad_req_t *req)
{
	int i;
	struct timespec tv, tv2;
	unsigned int dt;
	int timeout;

	while (1) {
		if (rad_server_req_enter(req)) {
			if (rad_server_realloc(req)) {
				log_ppp_warn("radius: no available servers\n");
				break;
			}
			continue;
		}

		for(i = 0; i < conf_max_try; i++) {
			__sync_add_and_fetch(&req->serv->stat_auth_sent, 1);
			clock_gettime(CLOCK_MONOTONIC, &tv);
			if (rad_req_send(req, conf_verbose ? log_ppp_info1 : NULL))
				goto out;

			timeout = conf_timeout;

			while (timeout > 0) {

				rad_req_wait(req, timeout);

				if (req->reply) {
					if (req->reply->id != req->pack->id) {
						rad_packet_free(req->reply);
						req->reply = NULL;
						clock_gettime(CLOCK_MONOTONIC, &tv2);
						timeout = conf_timeout - ((tv2.tv_sec - tv.tv_sec) * 1000 + (tv2.tv_nsec - tv.tv_nsec) / 1000000);
					} else
						break;
				} else
					break;
			}

			if (req->reply) {
				dt = (req->reply->tv.tv_sec - tv.tv_sec) * 1000 + (req->reply->tv.tv_nsec - tv.tv_nsec) / 1000000;
				stat_accm_add(req->serv->stat_auth_query_1m, dt);
				stat_accm_add(req->serv->stat_auth_query_5m, dt);
				break;
			} else {
				__sync_add_and_fetch(&req->serv->stat_auth_lost, 1);
				stat_accm_add(req->serv->stat_auth_lost_1m, 1);
				stat_accm_add(req->serv->stat_auth_lost_5m, 1);
			}
		}
out:
		rad_server_req_exit(req);

		if (!req->reply) {
			rad_server_fail(req->serv);
			if (rad_server_realloc(req)) {
				log_ppp_warn("radius: no available servers\n");
				break;
			}
		} else {
			if (req->reply->code == CODE_ACCESS_ACCEPT) {
				if (rad_proc_attrs(req))
					return PWDB_DENIED;
				return PWDB_SUCCESS;
			} else
				break;
		}
	}

	return PWDB_DENIED;
}

int rad_auth_pap(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req;
	int r = PWDB_DENIED;
	//int id = va_arg(args, int);
	const char *passwd = va_arg(args, const char *);
	uint8_t *epasswd;
	int epasswd_len;

	req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username);
	if (!req)
		return PWDB_DENIED;
	
	epasswd = encrypt_password(passwd, req->serv->secret, req->RA, &epasswd_len);
	if (!epasswd)
		goto out;

	if (rad_packet_add_octets(req->pack, NULL, "User-Password", epasswd, epasswd_len)) {
		if (epasswd_len)
			_free(epasswd);
		goto out;
	}

	if (epasswd_len)
		_free(epasswd);

	if (conf_sid_in_auth)
		if (rad_packet_add_str(req->pack, NULL, "Acct-Session-Id", rpd->ses->sessionid))
			return -1;

	r = rad_auth_send(req);
	if (r == PWDB_SUCCESS) {
		struct ev_radius_t ev = {
			.ses = rpd->ses,
			.request = req->pack,
			.reply = req->reply,
		};
		triton_event_fire(EV_RADIUS_ACCESS_ACCEPT, &ev);
	}

out:
	rad_req_free(req);

	return r;
}

int rad_auth_chap_md5(struct radius_pd_t *rpd, const char *username, va_list args)
{
	int r = PWDB_DENIED;
	uint8_t chap_password[17];
	
	int id = va_arg(args, int);
	uint8_t *challenge = va_arg(args, uint8_t *);
	int challenge_len = va_arg(args, int);
	uint8_t *response = va_arg(args, uint8_t *);

	chap_password[0] = id;
	memcpy(chap_password + 1, response, 16);

	if (!rpd->auth_req) {
		rpd->auth_req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username);
		if (!rpd->auth_req)
			return PWDB_DENIED;
	
		if (challenge_len == 16)
			memcpy(rpd->auth_req->RA, challenge, 16);
		if (rad_packet_add_octets(rpd->auth_req->pack, NULL, "CHAP-Challenge", challenge, challenge_len))
			goto out;

		if (rad_packet_add_octets(rpd->auth_req->pack, NULL, "CHAP-Password", chap_password, 17))
			goto out;
	} else {
		if (challenge_len == 16)
			memcpy(rpd->auth_req->RA, challenge, 16);
		if (rad_packet_change_octets(rpd->auth_req->pack, NULL, "CHAP-Challenge", challenge, challenge_len))
			goto out;

		if (rad_packet_change_octets(rpd->auth_req->pack, NULL, "CHAP-Password", chap_password, 17))
			goto out;
		
		if (rpd->attr_state) {
			if (rad_packet_find_attr(rpd->auth_req->pack, NULL, "State")) {
				if (rad_packet_change_octets(rpd->auth_req->pack, NULL, "State", rpd->attr_state, rpd->attr_state_len))
					goto out;
			} else {
				if (rad_packet_add_octets(rpd->auth_req->pack, NULL, "State", rpd->attr_state, rpd->attr_state_len))
					goto out;
			}
		}
		
		if (rad_packet_build(rpd->auth_req->pack, rpd->auth_req->RA))
			return -1;
	}
	
	if (conf_sid_in_auth)
		if (rad_packet_add_str(rpd->auth_req->pack, NULL, "Acct-Session-Id", rpd->ses->sessionid))
			goto out;

	r = rad_auth_send(rpd->auth_req);
	if (r == PWDB_SUCCESS) {
		struct ev_radius_t ev = {
			.ses = rpd->ses,
			.request = rpd->auth_req->pack,
			.reply = rpd->auth_req->reply,
		};
		triton_event_fire(EV_RADIUS_ACCESS_ACCEPT, &ev);
		rpd->auth_req->pack->id++;
	}

out:
	rad_req_free(rpd->auth_req);
	rpd->auth_req = NULL;

	return r;
}

static void setup_mppe(struct rad_req_t *req, const uint8_t *challenge)
{
	struct rad_attr_t *attr;
	uint8_t mppe_recv_key[16];
	uint8_t mppe_send_key[16];
	struct ev_mppe_keys_t ev_mppe = {
		.ppp = container_of(req->rpd->ses, typeof(struct ppp_t), ses),
	};

	if (!req->rpd->ses->ctrl->ppp)
		return;

	list_for_each_entry(attr, &req->reply->attrs, entry) {
		if (attr->vendor && attr->vendor->id == Vendor_Microsoft) {
			switch (attr->attr->id) {
				case MS_CHAP_MPPE_Keys:
					if (decrypt_chap_mppe_keys(req, attr, challenge, mppe_recv_key))
						continue;
					ev_mppe.recv_key = mppe_recv_key;
					ev_mppe.send_key = mppe_recv_key;
					break;
				case MS_MPPE_Recv_Key:
					if (decrypt_mppe_key(req, attr, mppe_recv_key))
						continue;
					ev_mppe.recv_key = mppe_recv_key;
					break;
				case MS_MPPE_Send_Key:
					if (decrypt_mppe_key(req, attr, mppe_send_key))
						continue;
					ev_mppe.send_key = mppe_send_key;
					break;
				case MS_MPPE_Encryption_Policy:
					ev_mppe.policy = attr->val.integer;
					break;
				case MS_MPPE_Encryption_Type:
					ev_mppe.type = attr->val.integer;
					break;
			}
		}
	}

	if (ev_mppe.recv_key && ev_mppe.send_key)
		triton_event_fire(EV_MPPE_KEYS, &ev_mppe);
}

int rad_auth_mschap_v1(struct radius_pd_t *rpd, const char *username, va_list args)
{
	int r = PWDB_DENIED;
	uint8_t response[50];
	struct rad_attr_t *ra;

	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	int challenge_len = va_arg(args, int);
	const uint8_t *lm_response = va_arg(args, const uint8_t *);
	const uint8_t *nt_response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);
	char  **mschap_error = va_arg(args, char  **);

	response[0] = id;
	response[1] = flags;
	memcpy(response + 2, lm_response, 24);
	memcpy(response + 2 + 24, nt_response, 24);

	if (!rpd->auth_req) {
		rpd->auth_req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username);
		if (!rpd->auth_req)
			return PWDB_DENIED;
		
		if (rad_packet_add_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP-Challenge", challenge, challenge_len))
			goto out;
		
		if (rad_packet_add_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP-Response", response, sizeof(response)))
			goto out;
	} else {
		if (rad_packet_change_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP-Challenge", challenge, challenge_len))
			goto out;
		
		if (rad_packet_change_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP-Response", response, sizeof(response)))
			goto out;

		if (rpd->attr_state) {
			if (rad_packet_find_attr(rpd->auth_req->pack, NULL, "State")) {
				if (rad_packet_change_octets(rpd->auth_req->pack, NULL, "State", rpd->attr_state, rpd->attr_state_len))
					goto out;
			} else {
				if (rad_packet_add_octets(rpd->auth_req->pack, NULL, "State", rpd->attr_state, rpd->attr_state_len))
					goto out;
			}
		}
		
		if (rad_packet_build(rpd->auth_req->pack, rpd->auth_req->RA))
			return -1;
	}

	if (conf_sid_in_auth)
		if (rad_packet_add_str(rpd->auth_req->pack, NULL, "Acct-Session-Id", rpd->ses->sessionid))
			goto out;


	r = rad_auth_send(rpd->auth_req);
	if (r == PWDB_SUCCESS) {
		struct ev_radius_t ev = {
			.ses = rpd->ses,
			.request = rpd->auth_req->pack,
			.reply = rpd->auth_req->reply,
		};
		triton_event_fire(EV_RADIUS_ACCESS_ACCEPT, &ev);
		setup_mppe(rpd->auth_req, challenge);
		rpd->auth_req->pack->id++;
	} else if (rpd->auth_req->reply) {
		ra = rad_packet_find_attr(rpd->auth_req->reply, "Microsoft", "MS-CHAP-Error");
		if (ra)
			*mschap_error = ra->val.string;
	}

out:
	rad_req_free(rpd->auth_req);
	rpd->auth_req = NULL;

	return r;
}

int rad_auth_mschap_v2(struct radius_pd_t *rpd, const char *username, va_list args)
{
	int r = PWDB_DENIED;
	struct rad_attr_t *ra;
	uint8_t mschap_response[50];

	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	const uint8_t *peer_challenge = va_arg(args, const uint8_t *);
	const uint8_t *reserved = va_arg(args, const uint8_t *);
	const uint8_t *response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);
	uint8_t *authenticator = va_arg(args, uint8_t *);
	char **mschap_error = va_arg(args, char **);
	char **reply_msg = va_arg(args, char **);

	mschap_response[0] = id;
	mschap_response[1] = flags;
	memcpy(mschap_response + 2, peer_challenge, 16);
	memcpy(mschap_response + 2 + 16, reserved, 8);
	memcpy(mschap_response + 2 + 16 + 8, response, 24);

	if (!rpd->auth_req) {		
		rpd->auth_req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username);
		if (!rpd->auth_req)
			return PWDB_DENIED;

		if (rad_packet_add_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP-Challenge", challenge, 16))
			goto out;
		
		if (rad_packet_add_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP2-Response", mschap_response, sizeof(mschap_response)))
			goto out;
	} else {
		if (rad_packet_change_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP-Challenge", challenge, 16))
			goto out;
		
		if (rad_packet_change_octets(rpd->auth_req->pack, "Microsoft", "MS-CHAP2-Response", mschap_response, sizeof(mschap_response)))
			goto out;

		if (rpd->attr_state) {
			if (rad_packet_find_attr(rpd->auth_req->pack, NULL, "State")) {
				if (rad_packet_change_octets(rpd->auth_req->pack, NULL, "State", rpd->attr_state, rpd->attr_state_len))
					goto out;
			} else {
				if (rad_packet_add_octets(rpd->auth_req->pack, NULL, "State", rpd->attr_state, rpd->attr_state_len))
					goto out;
			}
		}
		
		if (rad_packet_build(rpd->auth_req->pack, rpd->auth_req->RA))
			return -1;
	}
	
	if (conf_sid_in_auth)
		if (rad_packet_add_str(rpd->auth_req->pack, NULL, "Acct-Session-Id", rpd->ses->sessionid))
			goto out;

	r = rad_auth_send(rpd->auth_req);
	if (r == PWDB_SUCCESS) {
		ra = rad_packet_find_attr(rpd->auth_req->reply, "Microsoft", "MS-CHAP2-Success");
		if (!ra) {
			log_error("radius:auth:mschap-v2: 'MS-CHAP-Success' not found in radius response\n");
			r = PWDB_DENIED;
		} else
			memcpy(authenticator, ra->val.octets + 3, 40);
	}
	if (r == PWDB_SUCCESS) {
		struct ev_radius_t ev = {
			.ses = rpd->ses,
			.request = rpd->auth_req->pack,
			.reply = rpd->auth_req->reply,
		};
		triton_event_fire(EV_RADIUS_ACCESS_ACCEPT, &ev);
		setup_mppe(rpd->auth_req, NULL);
		rpd->auth_req->pack->id++;
	} else if (rpd->auth_req->reply) {
		ra = rad_packet_find_attr(rpd->auth_req->reply, "Microsoft", "MS-CHAP-Error");
		if (ra)
			*mschap_error = ra->val.string;
		ra = rad_packet_find_attr(rpd->auth_req->reply, NULL, "Reply-Message");
		if (ra)
			*reply_msg = ra->val.string;
	}

out:
	rad_req_free(rpd->auth_req);
	rpd->auth_req = NULL;

	return r;
}


int rad_auth_null(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req;
	int r = PWDB_DENIED;

	req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username);
	if (!req)
		return PWDB_DENIED;
	
	if (conf_sid_in_auth)
		if (rad_packet_add_str(req->pack, NULL, "Acct-Session-Id", rpd->ses->sessionid))
			return -1;

	r = rad_auth_send(req);
	if (r == PWDB_SUCCESS) {
		struct ev_radius_t ev = {
			.ses = rpd->ses,
			.request = req->pack,
			.reply = req->reply,
		};
		triton_event_fire(EV_RADIUS_ACCESS_ACCEPT, &ev);
	}

	rad_req_free(req);

	return r;
}

