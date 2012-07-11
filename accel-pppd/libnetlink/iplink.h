#ifndef __IPLINK_H
#define __IPLINK_H

#include <linux/if_link.h>

typedef int (*iplink_list_func)(int index, int flags, const char *name, void *arg);

int iplink_list(iplink_list_func func, void *arg);
int iplink_get_stats(int ifindex, struct rtnl_link_stats *stats);

#endif
