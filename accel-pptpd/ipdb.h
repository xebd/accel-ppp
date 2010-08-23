#ifndef IPDB_H
#define IPDB_H

#include <netinet/in.h>

int ipdb_get(in_addr_t *addr, in_addr_t *peer_addr);

#endif

