#ifndef __PPPOE_H
#define __PPPOE_H

#include <linux/if.h>
#include <linux/if_pppox.h>

/* PPPoE codes */
#define CODE_PADI           0x09
#define CODE_PADO           0x07
#define CODE_PADR           0x19
#define CODE_PADS           0x65
#define CODE_PADT           0xA7
#define CODE_SESS           0x00

/* PPPoE Tags */
#define TAG_END_OF_LIST        0x0000
#define TAG_SERVICE_NAME       0x0101
#define TAG_AC_NAME            0x0102
#define TAG_HOST_UNIQ          0x0103
#define TAG_AC_COOKIE          0x0104
#define TAG_VENDOR_SPECIFIC    0x0105
#define TAG_RELAY_SESSION_ID   0x0110
#define TAG_SERVICE_NAME_ERROR 0x0201
#define TAG_AC_SYSTEM_ERROR    0x0202
#define TAG_GENERIC_ERROR      0x0203

/* Discovery phase states */
#define STATE_SENT_PADI     0
#define STATE_RECEIVED_PADO 1
#define STATE_SENT_PADR     2
#define STATE_SESSION       3
#define STATE_TERMINATED    4

/* Header size of a PPPoE packet */
#define PPPOE_OVERHEAD 6  /* type, code, session, length */
#define HDR_SIZE (sizeof(struct ethhdr) + PPPOE_OVERHEAD)
#define MAX_PPPOE_PAYLOAD (ETH_DATA_LEN - PPPOE_OVERHEAD)
#define MAX_PPPOE_MTU (MAX_PPPOE_PAYLOAD - 2)

#define MAX_SID 65534

struct pppoe_tag_t
{
	struct list_head entry;
	int type;
	int len;
};

struct pppoe_packet_t
{
	uint8_t src[ETH_ALEN];
	uint8_t dst[ETH_ALEN];
	int code;
	uint16_t sid;
	struct list_head tags;
};

#endif

