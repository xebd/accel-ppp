#ifndef __VLAN_MON_H
#define __VLAN_MON_H

typedef void (*vlan_mon_notify)(int ifindex, int vid, int vlan_ifindex);

void vlan_mon_register_proto(int proto, vlan_mon_notify cb);

int vlan_mon_add(int ifindex, int proto, long *mask, int len);
int vlan_mon_add_vid(int ifindex, int proto, int vid);
int vlan_mon_del(int ifindex, int proto);

int make_vlan_name(const char *pattern, const char *parent, int svid, int cvid, char *name);
int parse_vlan_mon(const char *opt, long *mask);

#endif
