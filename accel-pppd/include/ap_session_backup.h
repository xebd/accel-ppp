#ifndef __AP_SESSION_BACKUP_H
#define __AP_SESSION_BACKUP_H

#include <netinet/in.h>
#include <stdint.h>

#define SES_TAG_USERNAME           1
#define SES_TAG_SESSIONID          2
#define SES_TAG_START_TIME         3
#define SES_TAG_IPV4_ADDR          4
#define SES_TAG_IPV4_PEER_ADDR     5
#define SES_TAG_IPV6_INTFID        6
#define SES_TAG_IPV6_PEER_INTFID   7
#define SES_TAG_IPV6_ADDR          8
#define SES_TAG_IFINDEX            9
#define SES_TAG_IFNAME            10


struct ses_tag_ipv6
{
	struct in6_addr addr;
	uint8_t prefix_len;
} __attribute__((packed));

#endif

