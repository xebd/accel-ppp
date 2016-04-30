#ifndef __EVENTS_H
#define __EVENTS_H

#include <stdint.h>
#include <netinet/in.h>

#define EV_SES_STARTING     1
#define EV_SES_STARTED      2
#define EV_SES_FINISHING    3
#define EV_SES_FINISHED     4
#define EV_SES_AUTHORIZED   5
#define EV_CTRL_STARTING    6
#define EV_CTRL_STARTED     7
#define EV_CTRL_FINISHED    8
#define EV_SES_PRE_UP       9
#define EV_SES_ACCT_START   10
#define EV_CONFIG_RELOAD		11
#define EV_SES_AUTH_FAILED  12
#define EV_SES_PRE_FINISHED 13
#define EV_IP_CHANGED       100
#define EV_SHAPER           101
#define EV_MPPE_KEYS        102
#define EV_DNS              103
#define EV_WINS             104
#define EV_FORCE_INTERIM_UPDATE 105
#define EV_RADIUS_ACCESS_ACCEPT 200
#define EV_RADIUS_COA           201

struct ap_session;
struct ppp_t;
struct rad_packet_t;
struct ev_radius_t
{
	struct ap_session *ses;
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
	struct ap_session *ses;
	const char *val;
};

struct ev_dns_t
{
	struct ap_session *ses;
	in_addr_t dns1;
	in_addr_t dns2;
};

struct ev_wins_t
{
	struct ap_session *ses;
	in_addr_t wins1;
	in_addr_t wins2;
};
#endif
