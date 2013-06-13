#ifndef __IPLINK_H
#define __IPLINK_H

#include <linux/if_link.h>

typedef int (*iplink_list_func)(int index, int flags, const char *name, void *arg);

int iplink_list(iplink_list_func func, void *arg);
int iplink_get_stats(int ifindex, struct rtnl_link_stats *stats);

int ipaddr_add(int ifindex, in_addr_t addr, int mask);
int ipaddr_del(int ifindex, in_addr_t addr);

int iproute_add(int ifindex, in_addr_t src, in_addr_t dst, int proto);
int iproute_del(int ifindex, in_addr_t dst);

int iprule_add(uint32_t addr, int table);
int iprule_del(uint32_t addr, int table);
#endif
