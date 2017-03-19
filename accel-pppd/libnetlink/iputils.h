#ifndef __IPLINK_H
#define __IPLINK_H

#include <linux/if_link.h>

typedef int (*iplink_list_func)(int index, int flags, const char *name, int iflink, int vid, void *arg);

int iplink_list(iplink_list_func func, void *arg);
int iplink_get_stats(int ifindex, struct rtnl_link_stats *stats);

int iplink_vlan_add(const char *ifname, int ifindex, int vid);
int iplink_vlan_del(int ifindex);
int iplink_vlan_get_vid(int ifindex, int *iflink);

int ipaddr_add(int ifindex, in_addr_t addr, int mask);
int ipaddr_add_peer(int ifindex, in_addr_t addr, int mask, in_addr_t peer_addr);
int ipaddr_del(int ifindex, in_addr_t addr, int mask);

int iproute_add(int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask);
int iproute_del(int ifindex, in_addr_t dst, int proto, int mask);
in_addr_t iproute_get(in_addr_t dst, in_addr_t *gw);

int ip6route_add(int ifindex, struct in6_addr *dst, int prefix_len, int proto);
int ip6route_del(int ifindex, struct in6_addr *dst, int prefix_len);
int ip6addr_add(int ifindex, struct in6_addr *addr, int prefix_len);
int ip6addr_del(int ifindex, struct in6_addr *addr, int prefix_len);

int iprule_add(uint32_t addr, int table);
int iprule_del(uint32_t addr, int table);

struct rtnl_handle *iputils_get_handle();
#endif
