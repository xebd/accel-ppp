#ifndef PROXY_PROT_H
#define PROXY_PROT_H

#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#define PROXY_SIG		{ 'P', 'R', 'O', 'X', 'Y' }
#define PROXY_MINLEN		8
#define PROXY_TCP4		"TCP4"
#define PROXY_TCP6		"TCP6"
#define PROXY_UNKNOWN		"UNKNOWN"

#define PROXY2_SIG		{ 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a }
#define PROXY2_MINLEN		16
#define PROXY2_LOCAL		0
#define PROXY2_PROXY		1
#define PROXY2_AF_UNSPEC	0
#define PROXY2_AF_INET		1
#define PROXY2_AF_INET6		2
#define PROXY2_AF_UNIX		3
#define PROXY2_UNSPEC		0
#define PROXY2_STREAM		1
#define PROXY2_DGRAM		2

struct proxy_hdr {
	char line[108];
} __attribute__((packed));

struct proxy2_ipv4 {
	struct in_addr src_addr;
	struct in_addr dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((packed));

struct proxy2_ipv6 {
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((packed));

struct proxy2_unix {
	char src_addr[108];
	char dst_addr[108];
} __attribute__((packed));

union proxy2_addr {
	struct proxy2_ipv4 ipv4_addr;
	struct proxy2_ipv6 ipv6_addr;
	struct proxy2_unix unix_addr;
};

struct proxy2_hdr {
	uint8_t sig[12];	/* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
	uint8_t ver_cmd;	/* protocol version and command */
	uint8_t fam;		/* protocol family and address */
	uint16_t len;		/* number of following bytes part of the header */
	union proxy2_addr __addr[0];
#define ipv4_addr __addr[0].ipv4_addr
#define ipv6_addr __addr[0].ipv6_addr
#define unix_addr __addr[0].unix_addr
} __attribute__((packed));

struct BUG_bad_sizeof_proxy_hdr {
	uint8_t proxy_hdr[sizeof(struct proxy_hdr) < PROXY_MINLEN ? -1 : 0 ];
};

struct BUG_bad_sizeof_proxy2_hdr {
	uint8_t proxy2_hdr[sizeof(struct proxy2_hdr) != PROXY2_MINLEN ? -1 : 0 ];
};

#endif
