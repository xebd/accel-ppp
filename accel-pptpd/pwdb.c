#include "pwdb.h"
#include "ppp.h"

__export int pwdb_check(struct ppp_t *ppp,const char *username,const char *password)
{
	return 0;
}

__export char *pwdb_get_passwd(struct ppp_t *ppp, const char *username)
{
	return strdup("test");
}
