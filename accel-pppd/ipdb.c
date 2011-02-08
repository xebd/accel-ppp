#include "triton.h"
#include "ipdb.h"

#include "memdebug.h"

static LIST_HEAD(ipdb_handlers);

struct ipv4db_item_t __export *ipdb_get_ipv4(struct ppp_t *ppp)
{
	struct ipdb_t *ipdb;
	struct ipv4db_item_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv4)
			continue;
		it = ipdb->get_ipv4(ppp);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv4(struct ppp_t *ppp, struct ipv4db_item_t *it)
{
	if (it->owner->put_ipv4)
		it->owner->put_ipv4(ppp, it);
}

struct ipv6db_item_t __export *ipdb_get_ipv6(struct ppp_t *ppp)
{
	struct ipdb_t *ipdb;
	struct ipv6db_item_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv6)
			continue;
		it = ipdb->get_ipv6(ppp);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv6(struct ppp_t *ppp, struct ipv6db_item_t *it)
{
	if (it->owner->put_ipv4)
		it->owner->put_ipv6(ppp, it);
}


void __export ipdb_register(struct ipdb_t *ipdb)
{
	list_add_tail(&ipdb->entry, &ipdb_handlers);
}
