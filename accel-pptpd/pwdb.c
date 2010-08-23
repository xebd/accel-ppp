#include "pwdb.h"
#include "ppp.h"

int pwdb_check(struct ppp_t *ppp,const char *username,const char *password)
{
	return 0;
}

char *pwdb_get_passwd(struct ppp_t *ppp, const char *username)
{
	return strdup("test");
}
