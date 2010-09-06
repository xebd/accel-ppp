#ifndef PWDB_H
#define PWDB_H

#include <stdarg.h>
#include "list.h"

struct ppp_t;

#define PWDB_SUCCESS 0
#define PWDB_DENIED  1
#define PWDB_NO_IMPL 2

struct pwdb_t
{
	struct list_head entry;
	int (*check)(struct pwdb_t *, struct ppp_t *, const char *username, int type, va_list args);
	const char* (*get_passwd)(struct pwdb_t *, struct ppp_t *, const char *username);
};

int pwdb_check(struct ppp_t *, const char *username, int type, ...);
const char *pwdb_get_passwd(struct ppp_t *, const char *username);

void pwdb_register(struct pwdb_t *);
void pwdb_unregister(struct pwdb_t *);

#endif

