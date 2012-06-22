#ifndef __IPLINK_H
#define __IPLINK_H

typedef int (*iplink_list_func)(int index, int flags, const char *name, void *arg);

int iplink_list(iplink_list_func func, void *arg);

#endif
