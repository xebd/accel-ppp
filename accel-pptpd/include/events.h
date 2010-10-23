#ifndef __EVENTS_H
#define __EVENTS_H

#include <stdint.h>

#define EV_PPP_STARTING     1
#define EV_PPP_STARTED      2
#define EV_PPP_FINISHING    3
#define EV_PPP_FINISHED     4
#define EV_PPP_AUTHORIZED   5
#define EV_CTRL_STARTING    6
#define EV_CTRL_STARTED     7
#define EV_CTRL_FINISHED    8
#define EV_PPP_PRE_UP       9
#define EV_IP_CHANGED       100
#define EV_SHAPE_CHANGED    101
#define EV_MPPE_KEYS        102
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

#endif

