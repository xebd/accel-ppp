#include <stdlib.h>

#include "triton.h"

#include "pwdb.h"

static LIST_HEAD(pwdb_handlers);

int __export pwdb_cleartext_check(struct ppp_t *ppp, const char *username,const char *password)
{
	struct pwdb_t *pwdb;
	int r = PWDB_NO_IMPL;

	list_for_each_entry(pwdb, &pwdb_handlers, entry) {
		if (!pwdb->cleartext_check)
			continue;
		r = pwdb->cleartext_check(pwdb, ppp, username, password);
		if (r == PWDB_NO_IMPL)
			continue;
		break;
	}

	return r;
}
int __export pwdb_encrypted_check(struct ppp_t *ppp, const char *username, int type, ...)
{
	struct pwdb_t *pwdb;
	int r = PWDB_NO_IMPL;
	va_list args;

	va_start(args, type);

	list_for_each_entry(pwdb, &pwdb_handlers, entry) {
		if (!pwdb->encrypted_check)
			continue;
		r = pwdb->encrypted_check(pwdb, ppp, username, type, args);
		if (r == PWDB_NO_IMPL)
			continue;
		break;
	}

	return r;

}
__export const char *pwdb_get_passwd(struct ppp_t *ppp, const char *username)
{
	struct pwdb_t *pwdb;
	const char *r = NULL;

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

