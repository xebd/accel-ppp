#ifndef __IPSET_H
#define __IPSET_H

#include <netinet/in.h>

int ipset_add(const char *name, in_addr_t addr);
int ipset_del(const char *name, in_addr_t addr);
int ipset_flush(const char *name);

#endif

