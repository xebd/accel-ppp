#ifndef __DHCPV4_H
#define __DHCPV4_H

#include <stdint.h>
#include <pthread.h>
#include "list.h"

#include "triton.h"

#define __packed __attribute__((packed))

#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY   2

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

struct dhcpv4_hdr
{
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t sec;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	char sname[64];
	char file[128];
	uint8_t magic[4];
} __packed;

struct dhcpv4_option
{
	struct list_head entry;
	uint8_t type;
	uint8_t len;
	uint8_t *data;
};

struct dhcpv4_packet
{
	struct dhcpv4_hdr *hdr;
	struct list_head options;
	struct dhcpv4_option *client_id;
	struct dhcpv4_option *agent_circuit_id;
	struct dhcpv4_option *agent_remote_id;
	uint32_t request_ip;
	uint32_t server_id;
	int msg_type;
	uint8_t *ptr;
	uint8_t data[0];
};

struct dhcpv4_iprange
{
	struct list_head entry;
	uint32_t routerip;
	uint32_t startip;
	int mask;
	int pos;
	int len;
	pthread_mutex_t lock;
	unsigned long free[0];
}; 

struct dhcpv4_serv
{
	struct triton_context_t *ctx;
	struct triton_md_handler_t hnd;
	int raw_sock;
	uint8_t hwaddr[6];
	void (*recv)(struct dhcpv4_serv *serv, struct dhcpv4_packet *pack);
	struct dhcpv4_iprange *range;
};

struct ap_session;

struct dhcpv4_serv *dhcpv4_create(struct triton_context_t *ctx, const char *ifname, const char *opt);
void dhcpv4_free(struct dhcpv4_serv *);


int dhcpv4_send_reply(int msg_type, struct dhcpv4_serv *serv, struct dhcpv4_packet *req, uint32_t yiaddr, uint32_t siaddr, uint32_t mask, int lease_time);
int dhcpv4_send_nak(struct dhcpv4_serv *serv, struct dhcpv4_packet *req);

void dhcpv4_packet_free(struct dhcpv4_packet *pack);

int dhcpv4_check_options(struct dhcpv4_packet *);
void dhcpv4_print_options(struct dhcpv4_packet *, void (*)(const char *, ...));

void dhcpv4_print_packet(struct dhcpv4_packet *pack, void (*print)(const char *fmt, ...));

int dhcpv4_get_ip(struct dhcpv4_serv *serv, uint32_t *yiaddr, uint32_t *siaddr, int *mask);
void dhcpv4_put_ip(struct dhcpv4_serv *serv, uint32_t ip);
void dhcpv4_reserve_ip(struct dhcpv4_serv *serv, uint32_t ip);

#endif
