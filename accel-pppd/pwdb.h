#ifndef PWDB_H
#define PWDB_H

#include <stdarg.h>
#include "list.h"

struct ap_session;

#define CHAP_MD5 5
#define MSCHAP_V1 0x80
#define MSCHAP_V2 0x81

#define PWDB_SUCCESS 0
#define PWDB_DENIED  1
#define PWDB_NO_IMPL 2

struct pwdb_t
{
	struct list_head entry;
	int (*check)(struct pwdb_t *, struct ap_session *, const char *username, int type, va_list args);
	char* (*get_passwd)(struct pwdb_t *, struct ap_session *, const char *username);
};

int pwdb_check(struct ap_session *, const char *username, int type, ...);
char *pwdb_get_passwd(struct ap_session *, const char *username);

void pwdb_register(struct pwdb_t *);
void pwdb_unregister(struct pwdb_t *);

#endif

