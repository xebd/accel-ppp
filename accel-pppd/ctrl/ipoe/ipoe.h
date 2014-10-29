#ifndef __IPOE_H
#define __IPOE_H

#include <stdint.h>
#include <pthread.h>

#include "triton.h"
#include "ap_session.h"
#include "ipdb.h"
#include "dhcpv4.h"

#ifdef RADIUS
#include "radius.h"
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

struct arp_serv;

struct ipoe_serv {
	struct list_head entry;
	struct triton_context_t ctx;
	char *ifname;
	int ifindex;
	uint8_t hwaddr[ETH_ALEN];
	struct list_head sessions;
	struct list_head addr_list;
	struct dhcpv4_serv *dhcpv4;
	struct dhcpv4_relay *dhcpv4_relay;
	struct arp_serv *arp;
	struct list_head disc_list;
	struct list_head req_list;
	struct triton_timer_t disc_timer;
	struct triton_timer_t timer;
	pthread_mutex_t lock;
	int parent_ifindex;
	int vid;
	int opt_mode;
	uint32_t opt_src;
	int opt_arp;
	int opt_username;
#ifdef USE_LUA
	char *opt_lua_username_func;
#endif
	int opt_shared:1;
	int opt_dhcpv4:1;
	int opt_up:1;
	int opt_ifcfg:1;
	int opt_nat:1;
	int opt_ipv6:1;
	int need_close:1;
	int active:1;
};

struct ipoe_session {
	struct list_head entry;
	struct triton_context_t ctx;
	struct triton_timer_t timer;
	struct triton_timer_t l4_redirect_timer;
	struct ipoe_serv *serv;
	struct dhcpv4_serv *dhcpv4;
	struct ap_ctrl ctrl;
	struct ap_session ses;
	uint8_t hwaddr[ETH_ALEN];
	struct dhcpv4_option *client_id;
	struct dhcpv4_option *relay_agent;
	uint8_t *agent_circuit_id;
	uint8_t *agent_remote_id;
	uint32_t xid;
	uint32_t giaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t router;
	uint32_t relay_server_id;
	int l4_redirect_table;
	char *l4_redirect_ipset;
	int mask;
	int lease_time;
	uint8_t *data;
	struct dhcpv4_packet *dhcpv4_request;
	struct dhcpv4_packet *dhcpv4_relay_reply;
	int relay_retransmit;
	int ifindex;
	char *username;
	struct ipv4db_item_t ipv4;
#ifdef RADIUS
	struct rad_plugin_t radius;
#endif
	int ifcfg:1;
	int started:1;
	int terminating:1;
	int dhcp_addr:1;
	int relay_addr:1;
	int l4_redirect:1;
	int l4_redirect_set:1;
};

struct ipoe_session_info {
	struct list_head entry;
	int ifindex;
	uint32_t addr;
	uint32_t peer_addr;
};

struct arp_serv {
	struct triton_md_handler_t h;
	struct ipoe_serv *ipoe;
};

#ifdef USE_LUA
char *ipoe_lua_get_username(struct ipoe_session *, const char *func);
#endif

struct iphdr;
struct ethhdr;

void ipoe_recv_up(int ifindex, struct ethhdr *eth, struct iphdr *iph);
void ipoe_vlan_notify(int ifindex, int vid);

struct ipoe_session *ipoe_session_alloc(void);

struct ipoe_serv *ipoe_find_serv(const char *ifname);

void ipoe_nl_add_net(uint32_t addr, int mask);
void ipoe_nl_delete_nets(void);
void ipoe_nl_add_interface(int ifindex);
void ipoe_nl_delete_interfaces(void);
int ipoe_nl_create(uint32_t peer_addr, uint32_t addr, const char *ifname, uint8_t *hwaddr);
void ipoe_nl_delete(int ifindex);
int ipoe_nl_modify(int ifindex, uint32_t peer_addr, uint32_t addr, const char *ifname, uint8_t *hwaddr);
void ipoe_nl_get_sessions(struct list_head *list);
int ipoe_nl_add_vlan_mon(int ifindex, long *mask, int len);
int ipoe_nl_add_vlan_mon_vid(int ifindex, int vid);
int ipoe_nl_del_vlan_mon(int ifindex);
int ipoe_nl_add_exclude(uint32_t addr, int mask);
void ipoe_nl_del_exclude(uint32_t addr);

struct arp_serv *arpd_start(struct ipoe_serv *ipoe);
void arpd_stop(struct arp_serv *arp);

#endif

