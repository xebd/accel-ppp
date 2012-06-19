#include "triton.h"
#include "ipdb.h"

#include "memdebug.h"

static LIST_HEAD(ipdb_handlers);

struct ipv4db_item_t __export *ipdb_get_ipv4(struct ap_session *ses)
{
	struct ipdb_t *ipdb;
	struct ipv4db_item_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv4)
			continue;
		it = ipdb->get_ipv4(ses);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv4(struct ap_session *ses, struct ipv4db_item_t *it)
{
	if (it->owner->put_ipv4)
		it->owner->put_ipv4(ses, it);
}

struct ipv6db_item_t __export *ipdb_get_ipv6(struct ap_session *ses)
{
	struct ipdb_t *ipdb;
	struct ipv6db_item_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv6)
			continue;
		it = ipdb->get_ipv6(ses);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv6(struct ap_session *ses, struct ipv6db_item_t *it)
{
	if (it->owner->put_ipv6)
		it->owner->put_ipv6(ses, it);
}

struct ipv6db_prefix_t __export *ipdb_get_ipv6_prefix(struct ap_session *ses)
{
	struct ipdb_t *ipdb;
	struct ipv6db_prefix_t *it;

	list_for_each_entry(ipdb, &ipdb_handlers, entry) {
		if (!ipdb->get_ipv6_prefix)
			continue;
		it = ipdb->get_ipv6_prefix(ses);
		if (it)
			return it;
	}

	return NULL;
}

void __export ipdb_put_ipv6_prefix(struct ap_session *ses, struct ipv6db_prefix_t *it)
{
	if (it->owner->put_ipv6_prefix)
		it->owner->put_ipv6_prefix(ses, it);
}


void __export ipdb_register(struct ipdb_t *ipdb)
{
	list_add_tail(&ipdb->entry, &ipdb_handlers);
}
