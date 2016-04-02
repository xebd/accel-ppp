#include <stdlib.h>
#include <sys/socket.h>

#include "triton.h"

#include "pwdb.h"
#include "ap_session.h"
#include "log.h"

#include "memdebug.h"

static LIST_HEAD(pwdb_handlers);

int __export pwdb_check(struct ap_session *ses, pwdb_callback cb, void *cb_arg, const char *username, int type, ...)
{
	struct pwdb_t *pwdb;
	int r, res = PWDB_NO_IMPL;
	va_list args;

	if (ap_check_username(username)) {
		log_ppp_info1("%s: second session denied\n", username);
		return PWDB_DENIED;
	}

	va_start(args, type);

	list_for_each_entry(pwdb, &pwdb_handlers, entry) {
		if (!pwdb->check)
			continue;
		r = pwdb->check(pwdb, ses, cb, cb_arg, username, type, args);
		if (r == PWDB_NO_IMPL)
			continue;
		res = r;
		if (r == PWDB_SUCCESS || r == PWDB_WAIT)
			break;
	}

	va_end(args);

	return res;
}

__export char *pwdb_get_passwd(struct ap_session *ses, const char *username)
{
	struct pwdb_t *pwdb;
	char *r = NULL;

	list_for_each_entry(pwdb, &pwdb_handlers, entry) {
		if (!pwdb->get_passwd)
			continue;
		r = pwdb->get_passwd(pwdb, ses, username);
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

