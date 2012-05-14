#ifndef __EVENTS_H
#define __EVENTS_H

#include <stdint.h>
#include <netinet/in.h>

#define EV_PPP_STARTING     1
#define EV_PPP_STARTED      2
#define EV_PPP_FINISHING    3
#define EV_PPP_FINISHED     4
#define EV_PPP_AUTHORIZED   5
#define EV_CTRL_STARTING    6
#define EV_CTRL_STARTED     7
#define EV_CTRL_FINISHED    8
#define EV_PPP_PRE_UP       9
#define EV_PPP_ACCT_START   10
#define EV_CONFIG_RELOAD		11
#define EV_PPP_AUTH_FAILED  12
#define EV_PPP_PRE_FINISHED 13
#define EV_IP_CHANGED       100
#define EV_SHAPER           101
#define EV_MPPE_KEYS        102
#define EV_DNS              103
#define EV_RADIUS_ACCESS_ACCEPT 200
#define EV_RADIUS_COA           201

struct ppp_t;
struct rad_packet_t;
struct ev_radius_t
{
	struct ppp_t *ppp;
	struct rad_packet_t *request;
	struct rad_packet_t *reply;
	int res;
};

struct ev_mppe_keys_t
{
	struct ppp_t *ppp;
	uint8_t *recv_key;
	uint8_t *send_key;
	int policy;
	int type;
};

struct ev_shaper_t
{
	struct ppp_t *ppp;
	const char *val;
};

struct ev_dns_t
{
	struct ppp_t *ppp;
	in_addr_t dns1;
	in_addr_t dns2;
};

#endif

