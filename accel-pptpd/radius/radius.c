#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "mempool.h"
#include "events.h"
#include "log.h"
#include "ppp.h"
#include "pwdb.h"
#include "ipdb.h"

#include "radius_p.h"
#include "attr_defs.h"

#include "memdebug.h"

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
char *conf_auth_secret;

char *conf_acct_server;
int conf_acct_server_port = 1813;
char *conf_acct_secret;
char *conf_dm_coa_secret;

static LIST_HEAD(sessions);
static pthread_rwlock_t sessions_lock = PTHREAD_RWLOCK_INITIALIZER;

static void *pd_key;
static struct ipdb_t ipdb;

static mempool_t rpd_pool;

void rad_proc_attrs(struct rad_req_t *req)
{
	struct rad_attr_t *attr;

	list_for_each_entry(attr, &req->reply->attrs, entry) {
		if (attr->vendor)
			continue;
		switch(attr->attr->id) {
			case Framed_IP_Address:
				if (!conf_gw_ip_address)
					log_ppp_warn("radius: gw-ip-address not specified, cann't assign IP address...\n");
				else {
					req->rpd->ipaddr.owner = &ipdb;
					req->rpd->ipaddr.peer_addr = attr->val.ipaddr;
					req->rpd->ipaddr.addr = inet_addr(conf_gw_ip_address);
				}
				break;
			case Acct_Interim_Interval:
				req->rpd->acct_interim_interval = attr->val.integer;
				break;
			case Session_Timeout:
				req->rpd->session_timeout.expire_tv.tv_sec = attr->val.integer;
				break;
		}
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

static struct ipdb_item_t *get_ip(struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);
	
	if (rpd->ipaddr.peer_addr)
		return &rpd->ipaddr;
	return NULL;
}

static void session_timeout(struct triton_timer_t *t)
{
	struct radius_pd_t *rpd = container_of(t, typeof(*rpd), session_timeout);

	log_ppp_msg("radius: session timed out\n");
	ppp_terminate(rpd->ppp, 0);
}

static void ppp_starting(struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = mempool_alloc(rpd_pool);

	memset(rpd, 0, sizeof(*rpd));
	rpd->pd.key = &pd_key;
	rpd->ppp = ppp;
	pthread_mutex_init(&rpd->lock, NULL);
	list_add_tail(&rpd->pd.entry, &ppp->pd_list);

	pthread_rwlock_wrlock(&sessions_lock);
	list_add_tail(&rpd->entry, &sessions);
	pthread_rwlock_unlock(&sessions_lock);
}

static void ppp_started(struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);

	if (rad_acct_start(rpd))
		ppp_terminate(rpd->ppp, 0);
	
	if (rpd->session_timeout.expire_tv.tv_sec) {
		rpd->session_timeout.expire = session_timeout;
		triton_timer_add(ppp->ctrl->ctx, &rpd->session_timeout, 0);
	}
}
static void ppp_finishing(struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);

	rad_acct_stop(rpd);
}
static void ppp_finished(struct ppp_t *ppp)
{
	struct radius_pd_t *rpd = find_pd(ppp);

	pthread_rwlock_wrlock(&sessions_lock);
	pthread_mutex_lock(&rpd->lock);
	list_del(&rpd->entry);
	pthread_mutex_unlock(&rpd->lock);
	pthread_rwlock_unlock(&sessions_lock);

	if (rpd->acct_req)
		rad_req_free(rpd->acct_req);

	if (rpd->dm_coa_req)
		rad_packet_free(rpd->dm_coa_req);

	if (rpd->session_timeout.tpd)
		triton_timer_del(&rpd->session_timeout);

	list_del(&rpd->pd.entry);
	
	mempool_free(rpd);
}

struct radius_pd_t *find_pd(struct ppp_t *ppp)
{
	struct ppp_pd_t *pd;
	struct radius_pd_t *rpd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &pd_key) {
			rpd = container_of(pd, typeof(*rpd), pd);
			return rpd;
		}
	}
	log_emerg("radius:BUG: rpd not found\n");
	abort();
}


struct radius_pd_t *rad_find_session(const char *sessionid, const char *username, int port_id, in_addr_t ipaddr, const char *csid)
{
	struct radius_pd_t *rpd;
	
	pthread_rwlock_rdlock(&sessions_lock);
	list_for_each_entry(rpd, &sessions, entry) {
		if (sessionid && strcmp(sessionid, rpd->ppp->sessionid))
			continue;
		if (username && strcmp(username, rpd->ppp->username))
			continue;
		if (port_id >= 0 && port_id != rpd->ppp->unit_idx)
			continue;
		if (ipaddr && ipaddr != rpd->ipaddr.peer_addr)
			continue;
		if (csid && rpd->ppp->ctrl->calling_station_id && strcmp(csid, rpd->ppp->ctrl->calling_station_id))
			continue;
		pthread_mutex_lock(&rpd->lock);
		pthread_rwlock_unlock(&sessions_lock);
		return rpd;
	}
	pthread_rwlock_unlock(&sessions_lock);
	return NULL;
}

struct radius_pd_t *rad_find_session_pack(struct rad_packet_t *pack)
{
	struct rad_attr_t *attr;
	const char *sessionid = NULL;
	const char *username = NULL;
	const char *csid = NULL;
	int port_id = -1;
	in_addr_t ipaddr = 0;
	
	list_for_each_entry(attr, &pack->attrs, entry) {
		if (!strcmp(attr->attr->name, "Acct-Session-Id"))
			sessionid = attr->val.string;
		else if (!strcmp(attr->attr->name, "User-Name"))
			username = attr->val.string;
		else if (!strcmp(attr->attr->name, "NAS-Port"))
			port_id = attr->val.integer;
		else if (!strcmp(attr->attr->name, "Framed-IP-Address"))
			ipaddr = attr->val.ipaddr;
		else if (!strcmp(attr->attr->name, "Calling-Station-Id"))
			csid = attr->val.string;
	}

	if (!sessionid && !username && port_id == -1 && ipaddr == 0 && !csid)
		return NULL;

	if (username && !sessionid)
		return NULL;
	
	return rad_find_session(sessionid, username, port_id, ipaddr, csid);
}

int rad_check_nas_pack(struct rad_packet_t *pack)
{
	struct rad_attr_t *attr;
	const char *ident = NULL;
	in_addr_t ipaddr = 0;
	
	list_for_each_entry(attr, &pack->attrs, entry) {
		if (!strcmp(attr->attr->name, "NAS-Identifier"))
			ident = attr->val.string;
		else if (!strcmp(attr->attr->name, "NAS-IP-Address"))
			ipaddr = attr->val.ipaddr;
	}

	if (conf_nas_identifier && (!ident || strcmp(conf_nas_identifier, ident)))
		return -1;
	if (conf_nas_ip_address && inet_addr(conf_nas_ip_address) != ipaddr)
		return -1;
	
	return 0;
}

static struct ipdb_t ipdb = {
	.get = get_ip,
};

static struct pwdb_t pwdb = {
	.check = check,
};

static int parse_server(const char *opt, char **name, int *port, char **secret)
{
	char *str = _strdup(opt);
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
	char *dict = DICT_PATH;

	rpd_pool = mempool_create(sizeof(struct radius_pd_t));

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
	
	opt = conf_get_opt("radius", "nas-identifier");
	if (opt)
		conf_nas_identifier = opt;
	
	opt = conf_get_opt("radius", "gw-ip-address");
	if (opt)
		conf_gw_ip_address = opt;

	opt = conf_get_opt("radius", "auth_server");
	if (!opt) {
		log_emerg("radius: auth_server not specified\n");
		_exit(EXIT_FAILURE);
	} else if (parse_server(opt, &conf_auth_server, &conf_auth_server_port, &conf_auth_secret)) {
		log_emerg("radius: failed to parse auth_server\n");
		_exit(EXIT_FAILURE);
	}

	opt = conf_get_opt("radius", "acct_server");
	if (opt && parse_server(opt, &conf_acct_server, &conf_acct_server_port, &conf_acct_secret)) {
		log_emerg("radius: failed to parse acct_server\n");
		_exit(EXIT_FAILURE);
	}

	opt = conf_get_opt("radius", "dm_coa_secret");
	if (opt)
		conf_dm_coa_secret = opt;

	opt = conf_get_opt("radius", "dictionary");
	if (opt)
		dict = opt;

	if (rad_dict_load(dict))
		_exit(EXIT_FAILURE);

	pwdb_register(&pwdb);
	ipdb_register(&ipdb);

	triton_event_register_handler(EV_PPP_STARTING, (triton_event_func)ppp_starting);
	triton_event_register_handler(EV_PPP_STARTED, (triton_event_func)ppp_started);
	triton_event_register_handler(EV_PPP_FINISHING, (triton_event_func)ppp_finishing);
	triton_event_register_handler(EV_PPP_FINISHED, (triton_event_func)ppp_finished);
}
