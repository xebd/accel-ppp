#include "triton.h"
#include "ipdb.h"

#include "memdebug.h"

static LIST_HEAD(ipdb_handlers);

__export struct ipdb_item_t *ipdb_get(struct ppp_t *ppp)
{
	struct ipdb_t *ipdb;
	struct ipdb_item_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		it = ipdb->get(ppp);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put(struct ppp_t *ppp, struct ipdb_item_t *it)
{
	if (it->owner->put)
		it->owner->put(ppp, it);
}

void __export ipdb_register(struct ipdb_t *ipdb)
{
	list_add_tail(&ipdb->entry, &ipdb_handlers);
}
