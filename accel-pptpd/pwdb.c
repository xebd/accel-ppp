#include <stdlib.h>

#include "triton.h"

#include "pwdb.h"

#include "memdebug.h"

static LIST_HEAD(pwdb_handlers);

int __export pwdb_check(struct ppp_t *ppp, const char *username, int type, ...)
{
	struct pwdb_t *pwdb;
	int r, res = PWDB_NO_IMPL;
	va_list args;

	va_start(args, type);

	list_for_each_entry(pwdb, &pwdb_handlers, entry) {
		if (!pwdb->check)
			continue;
		r = pwdb->check(pwdb, ppp, username, type, args);
		if (r == PWDB_NO_IMPL)
			continue;
		if (r == PWDB_SUCCESS)
			return PWDB_SUCCESS;
		res = r;
	}

	return res;
}
__export char *pwdb_get_passwd(struct ppp_t *ppp, const char *username)
{
	struct pwdb_t *pwdb;
	char *r = NULL;

	list_for_each_entry(pwdb, &pwdb_handlers, entry) {
		if (!pwdb->get_passwd)
			continue;
		r = pwdb->get_passwd(pwdb, ppp, username);
		if (r)
			break;
	}

	return r;
}

void __export pwdb_register(struct pwdb_t *pwdb)
{
	list_add_tail(&pwdb->entry, &pwdb_handlers);
}
void __export pwdb_unregister(struct pwdb_t *pwdb)
{
	list_del(&pwdb->entry);
}

