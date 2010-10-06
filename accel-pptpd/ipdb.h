#ifndef IPDB_H
#define IPDB_H

#include <netinet/in.h>

#include "ppp.h"
#include "list.h"

struct ipdb_item_t
{
	struct ipdb_t *owner;
	in_addr_t addr;
	in_addr_t peer_addr;
};

struct ipdb_t
{
	struct list_head entry;
	struct ipdb_item_t *(*get)(struct ppp_t *ppp);
	void (*put)(struct ppp_t *ppp, struct ipdb_item_t *);
};

struct ipdb_item_t *ipdb_get(struct ppp_t *ppp);
void ipdb_put(struct ppp_t *ppp, struct ipdb_item_t *);

void ipdb_register(struct ipdb_t *);

#endif

