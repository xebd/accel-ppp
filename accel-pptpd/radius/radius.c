#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/md5.h>

#include "log.h"
#include "ppp.h"
#include "pwdb.h"
#include "ipdb.h"

#include "radius.h"

#define CHAP_MD5 5
#define MSCHAP_V1 0x80
#define MSCHAP_V2 0x81

int conf_max_try = 3;
int conf_timeout = 3;
char *conf_nas_identifier = "accel-pptpd";
char *conf_nas_ip_address;
char *conf_gw_ip_address;
int conf_verbose = 0;

char *conf_auth_server;
int conf_auth_server_port = 1812;
char *conf_auth_server_secret;

char *conf_acct_server;
int conf_acct_server_port = 1813;
char *conf_acct_server_secret;

static struct ppp_notified_t notified;

static struct radius_pd_t *find_pd(struct ppp_t *ppp);

static void proc_attrs(struct rad_req_t *req)
{
	struct rad_req_attr_t *attr;

	list_for_each_entry(attr, &req->reply->attrs, entry) {
		if (!strcmp(attr->attr->name, "Framed-IP-Address")) {
			req->rpd->ipaddr = attr->val.ipaddr;
		}
	}
}

static uint8_t* encrypt_password(const char *passwd, const char *secret, const uint8_t *RA, int *epasswd_len)
{
	uint8_t *epasswd;
	int i, j, chunk_cnt;
	uint8_t b[16], c[16];
	MD5_CTX ctx;
	
	chunk_cnt = (strlen(passwd) - 1) / 16 + 1;
	
	epasswd = malloc(chunk_cnt * 16);
	if (!epasswd) {
		log_error("radius: out of memory\n");
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

static int check_pap(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req;
	int i, r = PWDB_DENIED;
	//int id = va_arg(args, int);
	const char *passwd = va_arg(args, const char *);
	uint8_t *epasswd;
	int epasswd_len;

	req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username);
	if (!req)
		return PWDB_DENIED;
	
	req->server_name = conf_auth_server;
	req->server_port = conf_auth_server_port;

	epasswd = encrypt_password(passwd, conf_auth_server_secret, req->RA, &epasswd_len);
	if (!epasswd)
		goto out;

	if (rad_req_add_str(req, "Password", (char*)epasswd, epasswd_len, 0)) {
		free(epasswd);
		goto out;
	}

	free(epasswd);

	for(i = 0; i < conf_max_try; i++) {
		if (rad_req_send(req))
			goto out;

		rad_req_wait(req, conf_timeout);

		if (req->reply)
			break;
	}

	if (req->reply && req->reply->code == CODE_ACCESS_ACCEPT) {
		proc_attrs(req);
		r = PWDB_SUCCESS;
	}

out:
	rad_req_free(req);

	return r;
}

static int check_chap_md5(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req;
	int i, r = PWDB_DENIED;
	char chap_password[17];
	
	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	int challenge_len = va_arg(args, int);
	const uint8_t *response = va_arg(args, const uint8_t *);

	chap_password[0] = id;
	memcpy(chap_password + 1, response, 16);

	req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST, username);
	if (!req)
		return PWDB_DENIED;
	
	req->server_name = conf_auth_server;
	req->server_port = conf_auth_server_port;

	if (challenge_len == 16)
		memcpy(req->RA, challenge, 16);
	else {
		if (rad_req_add_str(req, "CHAP-Challenge", (char*)challenge, challenge_len, 0))
			goto out;
	}

	if (rad_req_add_str(req, "CHAP-Password", chap_password, 17, 0))
		goto out;

	for(i = 0; i < conf_max_try; i++) {
		if (rad_req_send(req))
			goto out;

		rad_req_wait(req, conf_timeout);

		if (req->reply)
			break;
	}

	if (req->reply && req->reply->code == CODE_ACCESS_ACCEPT) {
		proc_attrs(req);
		r = PWDB_SUCCESS;
	}

out:
	rad_req_free(req);

	return r;
}

static int check_mschap_v1(struct radius_pd_t *rpd, const char *username, va_list args)
{
	/*int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	const uint8_t *lm_response = va_arg(args, const uint8_t *);
	const uint8_t *nt_response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);*/
	return PWDB_DENIED;
}

static int check_mschap_v2(struct radius_pd_t *rpd, const char *username, va_list args)
{
	/*int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	const uint8_t *peer_challenge = va_arg(args, const uint8_t *);
	const uint8_t *response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);
	uint8_t *authenticator = va_arg(args, uint8_t *);*/
	return PWDB_DENIED;
}

static int check(struct pwdb_t *pwdb, struct ppp_t *ppp, const char *username, int type, va_list _args)
{
	int r = PWDB_NO_IMPL;
	va_list args;
	int chap_type;
	struct radius_pd_t *rpd = find_pd(ppp);

	va_copy(args, _args);

	switch(type) {
		case PPP_PAP:
			r = check_pap(rpd, username, args);
			break;
		case PPP_CHAP:
			chap_type = va_arg(args, int);
			switch(chap_type) {
				case CHAP_MD5:
					r = check_chap_md5(rpd, username, args);
					break;
				case MSCHAP_V1:
					r = check_mschap_v1(rpd, username, args);
					break;
				case MSCHAP_V2:
					r = check_mschap_v2(rpd, username, args);
					break;
			}
			break;
	}

	va_end(args);

	return r;
}

static int get_ip(struct ppp_t *ppp, in_addr_t *addr, in_addr_t *peer_addr)
{
	struct radius_pd_t *rpd = find_pd(ppp);
	
	if (rpd->ipaddr) {
		if (!conf_gw_ip_address) {
			log_warn("radius: gw-ip-address not specified, cann't assign IP address...\n");
			return -1;
		}
		*peer_addr = rpd->ipaddr;
		*addr = inet_addr(conf_gw_ip_address);
		return 0;
	}
	return -1;
}

static void ppp_started(struct ppp_notified_t *n, struct ppp_t *ppp)
{
	struct radius_pd_t *pd = malloc(sizeof(*pd));

	memset(pd, 0, sizeof(*pd));
	pd->pd.key = n;
	pd->ppp = ppp;
	list_add_tail(&pd->pd.entry, &ppp->pd_list);
}

static void ppp_finished(struct ppp_notified_t *n, struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);

	list_del(&rpd->pd.entry);
	free(rpd);
}

static struct radius_pd_t *find_pd(struct ppp_t *ppp)
{
	struct ppp_pd_t *pd;
	struct radius_pd_t *rpd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &notified) {
			rpd = container_of(pd, typeof(*rpd), pd);
			return rpd;
		}
	}
	log_error("radius:BUG: rpd not found\n");
	abort();
}


static struct ipdb_t ipdb = {
	.get = get_ip,
};

static struct pwdb_t pwdb = {
	.check = check,
};

static struct ppp_notified_t notified = {
	.started = ppp_started,
	.finished = ppp_finished,
};

static int parse_server(const char *opt, char **name, int *port, char **secret)
{
	char *str = strdup(opt);
	char *p1, *p2;

	p1 = strstr(str, ":");
	p2 = strstr(str, ",");

	if (p1)
		*p1 = 0;
	if (p2)
		*p2 = 0;
	else
		return -1;
	
	*name = str;
	if (p1) {
		*port = atoi(p1 + 1);
		if (*port <=0 )
			return -1;
	}
	*secret = p2 + 1;

	return 0;
}

static void __init radius_init(void)
{
	char *opt;

	opt = conf_get_opt("radius", "max-try");
	if (opt && atoi(opt) > 0)
		conf_max_try = atoi(opt);
	
	opt = conf_get_opt("radius", "timeout");
	if (opt && atoi(opt) > 0)
		conf_timeout = atoi(opt);

	opt = conf_get_opt("radius", "verbose");
	if (opt && atoi(opt) > 0)
		conf_verbose = 1;
	
	opt = conf_get_opt("radius", "nas-ip-address");
	if (opt)
		conf_nas_ip_address = opt;
	
	opt = conf_get_opt("radius", "gw-ip-address");
	if (opt)
		conf_gw_ip_address = opt;

	opt = conf_get_opt("radius", "auth_server");
	if (!opt) {
		log_error("radius: auth_server not specified\n");
		_exit(EXIT_FAILURE);
	} else if (parse_server(opt, &conf_auth_server, &conf_auth_server_port, &conf_auth_server_secret)) {
		log_error("radius: failed to parse auth_server\n");
		_exit(EXIT_FAILURE);
	}

	opt = conf_get_opt("radius", "acct_server");
	if (opt && parse_server(opt, &conf_acct_server, &conf_acct_server_port, &conf_acct_server_secret)) {
		log_error("radius: failed to parse acct_server\n");
		_exit(EXIT_FAILURE);
	}

	opt = conf_get_opt("radius", "dictionary");
	if (!opt) {
		fprintf(stderr, "radius: dictionary not specified\n");
		_exit(EXIT_FAILURE);
	}
	if (rad_dict_load(opt))
		_exit(EXIT_FAILURE);

	pwdb_register(&pwdb);
	ipdb_register(&ipdb);
	ppp_register_notified(&notified);
}

