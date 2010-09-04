#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ppp.h"
#include "pwdb.h"
#include "radius.h"

struct radius_pd_t
{
	struct ppp_pd_t pd;
	struct ppp_t *ppp;
};

static struct ppp_notified_t notified;

int cleartext_check(struct pwdb_t *pwdb, struct ppp_t *ppp, const char *username, const char *password)
{
	return PWDB_NO_IMPL;
}
int encrypted_check(struct pwdb_t *pwdb, struct ppp_t *ppp, const char *username, int type, va_list args)
{
	return PWDB_NO_IMPL;
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

struct pwdb_t pwdb = {
	.cleartext_check = cleartext_check,
	.encrypted_check = encrypted_check,
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

