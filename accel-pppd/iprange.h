#ifndef __IPRANGE_H
#define __IPRANGE_H

#include <netinet/in.h>

int iprange_client_check(in_addr_t ipaddr);
int iprange_tunnel_check(in_addr_t ipaddr);

#endif

