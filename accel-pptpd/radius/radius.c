#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ppp.h"
#include "pwdb.h"
#include "radius.h"

static struct ppp_notified_t notified;

static int check_pap(struct radius_pd_t *rpd, const char *username, va_list args)
{
	struct rad_req_t *req;
	int i, r = PWDB_DENIED;
	int id = va_arg(args, int);
	const char *passwd = va_arg(args, const char *);

	req = rad_req_alloc(rpd, CODE_ACCESS_REQUEST);
	if (!req)
		return PWDB_DENIED;

	if (rad_req_add_str(req, "User-Password", passwd, strlen(passwd)))
		goto out;

	for(i = 0; i < max_try; i++) {
		if (rad_req_send(req))
			goto out;

		if (rad_req_wait(req, timeout))
			goto out;

		if (req->answer)
			break;
	}

out:
	rad_req_free(req);

	return r;
}

static int check_chap_md5(struct radius_pd_t *rpd, const char *username, va_list args)
{
	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
}

static int check_mschap_v1(struct radius_pd_t *rpd, const char *username, va_list args)
{
	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	const uint8_t *lm_response = va_arg(args, const uint8_t *);
	const uint8_t *nt_response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);
}

static int check_mschap_v2(struct radius_pd_t *rpd, const char *username, va_list args)
{
	int id = va_arg(args, int);
	const uint8_t *challenge = va_arg(args, const uint8_t *);
	const uint8_t *peer_challenge = va_arg(args, const uint8_t *);
	const uint8_t *response = va_arg(args, const uint8_t *);
	int flags = va_arg(args, int);
	uint8_t *authenticator = va_arg(args, uint8_t *);
}

static int check(struct pwdb_t *pwdb, struct ppp_t *ppp, const char *username, int type, va_list _args)
{
	int r = PWDB_NO_IMPL;
	va_list args;
	int chap_type;
	struct ppp_pd_t *pd;
	struct radius_pd_t *rpd = NULL;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &notified) {
			rpd = container_of(pd, typeof(*rpd), pd);
			break;
		}
	}

	va_copy(args, _args);

	switch(type) {
		case PPP_PAP:
			r = check_pap(rpd, username, args);
			break;
		case PPP_CHAP:
			chap_type = va_arg(args, int);
			switch(chap_type) {
				case 0x05:
					r = check_chap_md5(rpd, username, args);
					break;
				case 0x80:
					r = check_mschap_v1(rpd, username, args);
					break;
				case 0x81:
					r = check_mschap_v2(rpd, username, args);
					break;
			}
			break;
	}

	va_end(args);

	return r;
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
	struct ppp_pd_t *pd;
	struct radius_pd_t *rpd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &notified) {
			rpd = container_of(pd, typeof(*rpd), pd);
			list_del(&pd->entry);
			free(rpd);
			return;
		}
	}
}

static struct pwdb_t pwdb = {
	.check = check,
};

static struct ppp_notified_t notified = {
	.started = ppp_started,
	.finished = ppp_finished,
};

static void __init radius_init(void)
{
	char *dict = conf_get_opt("radius", "dictionary");
	if (!dict) {
		fprintf(stderr, "radius: dictionary not specified\n");
		_exit(EXIT_FAILURE);
	}
	if (!rad_load_dict(dict))
		_exit(EXIT_FAILURE);
	ppp_register_notified(&notified);
}

