#include "triton.h"
#include "ipdb.h"

static LIST_HEAD(ipdb_handlers);

int __export ipdb_get(struct ppp_t *ppp, in_addr_t *addr, in_addr_t *peer_addr)
{
	struct ipdb_t *ipdb;

	list_for_each_entry(ipdb, &ipdb_handlers, entry)
		if (!ipdb->get(ppp, addr, peer_addr))
			return 0;

	return -1;
}
void __export ipdb_put(struct ppp_t *ppp, in_addr_t addr, in_addr_t peer_addr)
{
	struct ipdb_t *ipdb;

	list_for_each_entry(ipdb, &ipdb_handlers, entry)
		if (ipdb->put)
			ipdb->put(ppp, addr, peer_addr);
}

void __export ipdb_register(struct ipdb_t *ipdb)
{
	list_add_tail(&ipdb->entry, &ipdb_handlers);
}
