#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pwdb.h"
#include "ipdb.h"
#include "ppp.h"
#include "events.h"
#include "triton.h"
#include "log.h"

#include "memdebug.h"

static const char *conf_chap_secrets = "/etc/ppp/chap-secrets";
static in_addr_t conf_gw_ip_address = 0;

static void *pd_key;
static struct ipdb_t ipdb;

struct cs_pd_t
{
	struct ppp_pd_t pd;
	struct ipdb_item_t ip;
	char *passwd;
};

static char *skip_word(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr == ' ' || *ptr == '\t' || *ptr == '\n') 
			break;
	return ptr;
}
static char *skip_space(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr != ' ' && *ptr != '\t')
			break;
	return ptr;
}
static int split(char *buf, char **ptr)
{
	int i;

	for (i = 0; i < 3; i++) {
		buf = skip_word(buf);
		if (!*buf)
			return i;
		
		*buf = 0;
		
		buf = skip_space(buf + 1);
		if (!*buf)
			return i;

		ptr[i] = buf;
	}

	buf = skip_word(buf);
	//if (*buf == '\n')
		*buf = 0;
	//else if (*buf)
	//	return -1;

	return i;
}


static struct cs_pd_t *create_pd(struct ppp_t *ppp, const char *username)
{
	FILE *f;
	char *buf;
	char *ptr[4];
	int n;
	struct cs_pd_t *pd;

	if (!conf_chap_secrets)
		return NULL;
	
	f = fopen(conf_chap_secrets, "r");
	if (!f) {
		log_error("chap-secrets: open '%s': %s\n", conf_chap_secrets, strerror(errno));
		return NULL;
	}

	buf = _malloc(4096);
	if (!buf) {
		log_emerg("chap-secrets: out of memory\n");
		fclose(f);
		return NULL;
	}
	
	while (fgets(buf, 4096, f)) {
		n = split(buf, ptr);
		if (n < 3)
			continue;
		if (!strcmp(buf, username))
			goto found;
	}

out:
	fclose(f);
	_free(buf);
	return NULL;

found:
	pd = _malloc(sizeof(*pd));
	if (!pd) {
		log_emerg("chap-secrets: out of memory\n");
		goto out;
	}

	memset(pd, 0, sizeof(*pd));
	pd->pd.key = &pd_key;
	pd->passwd = _strdup(ptr[1]);
	if (!pd->passwd) {
		log_emerg("chap-secrets: out of memory\n");
		_free(pd);
		goto out;
	}

	pd->ip.addr = conf_gw_ip_address;
	if (n == 3)
		pd->ip.peer_addr = inet_addr(ptr[2]);
	pd->ip.owner = &ipdb;
	
	list_add_tail(&pd->pd.entry, &ppp->pd_list);

	fclose(f);
	_free(buf);

	return pd;
}

static struct cs_pd_t *find_pd(struct ppp_t *ppp)
{
	struct ppp_pd_t *pd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &pd_key) {
			return container_of(pd, typeof(struct cs_pd_t), pd);
		}
	}

	return NULL;
}

static void ev_ppp_finished(struct ppp_t *ppp)
{
	struct cs_pd_t *pd = find_pd(ppp);

	if (!pd)
		return;

	list_del(&pd->pd.entry);
	_free(pd->passwd);
	_free(pd);
}

static struct ipdb_item_t *get_ip(struct ppp_t *ppp)
{
	struct cs_pd_t *pd;
	
	if (!conf_gw_ip_address)
		return NULL;

	pd = find_pd(ppp);

	if (!pd)
		return NULL;

	if (!pd->ip.addr)
		return NULL;

	return &pd->ip;
}

static char* get_passwd(struct pwdb_t *pwdb, struct ppp_t *ppp, const char *username)
{
	struct cs_pd_t *pd = find_pd(ppp);

	if (!pd)
		pd = create_pd(ppp, username);
	
	if (!pd)
		return NULL;
	
	return _strdup(pd->passwd);
}

static struct ipdb_t ipdb = {
	.get = get_ip,
};

static struct pwdb_t pwdb = {
	.get_passwd = get_passwd,
};

static void __init init(void)
{
	const char *opt;

	opt = conf_get_opt("chap-secrets", "chap-secrets");
	if (opt)
		conf_chap_secrets = opt;

	opt = conf_get_opt("chap-secrets", "gw-ip-address");
	if (opt)
		conf_gw_ip_address = inet_addr(opt);

	pwdb_register(&pwdb);
	ipdb_register(&ipdb);
	
	triton_event_register_handler(EV_PPP_FINISHED, (triton_event_func)ev_ppp_finished);
}
