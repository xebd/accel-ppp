#ifndef __IPOE_H
#define __IPOE_H

#include <stdint.h>
#include <pthread.h>

#include "triton.h"
#include "ap_session.h"
#include "dhcpv4.h"

struct ipoe_serv
{
	struct list_head entry;
	struct triton_context_t ctx;
	char *ifname;
	int ifindex;
	int active;
	int opt_single;
	int opt_dhcpv4;
	struct list_head sessions;
	struct dhcpv4_serv *dhcpv4;
	pthread_mutex_t lock;
};

struct dhcp_opt
{
	uint8_t len;
	uint8_t data[0];
};

struct ipoe_session
{
	struct list_head entry;
	struct triton_context_t ctx;
	struct triton_timer_t timer;
	struct ipoe_serv *serv;
	struct ap_ctrl ctrl;
	struct ap_session ses;
	uint8_t hwaddr[6];
	struct dhcp_opt *client_id;
	struct dhcp_opt *agent_circuit_id;
	struct dhcp_opt *agent_remote_id;
	uint32_t xid;
	uint32_t giaddr;
	uint8_t *data;
	struct dhcpv4_packet *dhcpv4_request;
};

#ifdef USE_LUA
int ipoe_lua_set_username(struct ipoe_session *, const char *func);
#endif

#endif

