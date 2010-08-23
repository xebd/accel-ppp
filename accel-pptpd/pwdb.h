#ifndef PWDB_H
#define PWDB_H

struct ppp_t;

int pwdb_check(struct ppp_t*,const char *username,const char *password);
char *pwdb_get_passwd(struct ppp_t*, const char *username);

#endif

