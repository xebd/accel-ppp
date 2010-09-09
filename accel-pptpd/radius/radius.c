#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

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

void rad_proc_attrs(struct rad_req_t *req)
{
	struct rad_req_attr_t *attr;

	list_for_each_entry(attr, &req->reply->attrs, entry) {
		if (!strcmp(attr->attr->name, "Framed-IP-Address"))
			req->rpd->ipaddr = attr->val.ipaddr;
		else if (!strcmp(attr->attr->name, "Acct-Interim-Interval"))
			req->rpd->acct_interim_interval = attr->val.integer;
	}
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
			r = rad_auth_pap(rpd, username, args);
			break;
		case PPP_CHAP:
			chap_type = va_arg(args, int);
			switch(chap_type) {
				case CHAP_MD5:
					r = rad_auth_chap_md5(rpd, username, args);
					break;
				case MSCHAP_V1:
					r = rad_auth_mschap_v1(rpd, username, args);
					break;
				case MSCHAP_V2:
					r = rad_auth_mschap_v2(rpd, username, args);
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

static void ppp_starting(struct ppp_notified_t *n, struct ppp_t *ppp)
{
	struct radius_pd_t *pd = malloc(sizeof(*pd));

	memset(pd, 0, sizeof(*pd));
	pd->pd.key = n;
	pd->ppp = ppp;
	list_add_tail(&pd->pd.entry, &ppp->pd_list);
}

static void ppp_started(struct ppp_notified_t *n, struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);

	if (rad_acct_start(rpd))
		ppp_terminate(rpd->ppp, 0);
}
static void ppp_finishing(struct ppp_notified_t *n, struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);

	rad_acct_stop(rpd);
}
static void ppp_finished(struct ppp_notified_t *n, struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);

	list_del(&rpd->pd.entry);
	free(rpd);
}

struct radius_pd_t *find_pd(struct ppp_t *ppp)
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
	.starting = ppp_starting,
	.started = ppp_started,
	.finishing = ppp_finishing,
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

