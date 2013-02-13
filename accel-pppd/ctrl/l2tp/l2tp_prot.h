#ifndef __L2TP_PROT_H
#define __L2TP_PROT_H

#include <stdint.h>

#define L2TP_PORT 1701

struct l2tp_hdr_t
{
	uint8_t P:1;
	uint8_t O:1;
	uint8_t reserved2:1;
	uint8_t S:1;
	uint8_t reserved1:2;
	uint8_t L:1;
	uint8_t T:1;
	uint8_t ver:4;
	uint8_t reserved3:4;
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

/*#define L2TP_T(hdr) (hdr->flags >> 15)
#define L2TP_L(hdr) ((hdr->flags >> 14) & 1)
#define L2TP_S(hdr) ((hdr->flags >> 10) & 1)
#define L2TP_O(hdr) ((hdr->flags >> 8) & 1)
#define L2TP_VER(hdr) (hdr->flags & 0xf)*/

struct l2tp_avp_t
{
	uint16_t length:10;
	uint16_t reserved:4;
	uint16_t H:1;
	uint16_t M:1;
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

