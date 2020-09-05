#ifndef __L2TP_PROT_H
#define __L2TP_PROT_H

#include <stdint.h>

#define L2TP_PORT 1701

#define L2TP_FLAG_T   0x8000
#define L2TP_FLAG_L   0x4000
#define L2TP_FLAG_S   0x0800
#define L2TP_FLAG_O   0x0200
#define L2TP_FLAG_P   0x0100
#define L2TP_VER_MASK 0x000f

struct l2tp_hdr_t
{
	uint16_t flags;
	uint16_t length;
	union {
		struct {
			uint16_t tid;
			uint16_t sid;
		};
		uint32_t cid;
	};
	uint16_t Ns;
	uint16_t Nr;
} __attribute__((packed));

#define L2TP_AVP_FLAG_M   0x8000
#define L2TP_AVP_FLAG_H   0x4000
#define L2TP_AVP_LEN_MASK 0x03ff

struct l2tp_avp_t
{
	uint16_t flags;
	uint16_t vendor;
	uint16_t type;
	uint8_t val[0];
} __attribute__((packed));

struct l2tp_avp_result_code
{
	uint16_t result_code;
	uint16_t error_code;
	char error_msg[0];
} __attribute__((packed));

#endif
