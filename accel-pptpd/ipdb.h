#ifndef IPDB_H
#define IPDB_H

#include <netinet/in.h>

#include "ppp.h"
#include "list.h"

struct ipdb_t
{
	struct list_head entry;
	int (*get)(struct ppp_t *ppp, in_addr_t *addr, in_addr_t *peer_addr);
	void (*put)(struct ppp_t *ppp, in_addr_t addr, in_addr_t peer_addr);
};

int ipdb_get(struct ppp_t *ppp, in_addr_t *addr, in_addr_t *peer_addr);
void ipdb_put(struct ppp_t *ppp, in_addr_t addr, in_addr_t peer_addr);

void ipdb_register(struct ipdb_t *);

#endif

