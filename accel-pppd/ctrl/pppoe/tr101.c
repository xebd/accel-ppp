#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "triton.h"
#include "ppp.h"
#include "log.h"
#include "radius.h"
#include "memdebug.h"

#include "pppoe.h"

#define OPT_CIRCUIT_ID                0x01
#define OPT_REMOTE_AGENT_ID           0x02
#define OPT_ACTUAL_DATA_RATE_UP       0x81
#define OPT_ACTUAL_DATA_RATE_DOWN     0x82
#define OPT_MIN_DATA_RATE_UP          0x83
#define OPT_MIN_DATA_RATE_DOWN        0x84

static int tr101_send_request(struct pppoe_tag *tr101, struct rad_packet_t *pack, int type)
{
	uint8_t *ptr = (uint8_t *)tr101->tag_data + 4;
	uint8_t *endptr = (uint8_t *)tr101->tag_data + ntohs(tr101->tag_len);
	int id, len;
	char str[64];

	while (ptr < endptr) {
		if (ptr + 2 > endptr)
			goto inval;
		id = *ptr++;
		len = *ptr++;
		if (ptr + len > endptr)
			goto inval;
		if (type && id > 0x80)
			continue;
		switch (id) {
			case OPT_CIRCUIT_ID:
				if (len > 63)
					goto inval;
				memcpy(str, ptr, len);
				str[len] = 0;
				if (rad_packet_add_str(pack, "ADSL-Forum", "ADSL-Agent-Circuit-Id", str))
					return -1;
				break;
			case OPT_REMOTE_AGENT_ID:
				if (len > 63)
					goto inval;
				memcpy(str, ptr, len);
				str[len] = 0;
				if (rad_packet_add_str(pack, "ADSL-Forum", "ADSL-Agent-Remote-Id", str))
					return -1;
				break;
			case OPT_ACTUAL_DATA_RATE_UP:
				if (len != 6)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Actual-Data-Rate-Upstream", ntohl(*(uint32_t *)ptr)))
					return -1;
				break;
			case OPT_ACTUAL_DATA_RATE_DOWN:
				if (len != 6)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Actual-Data-Rate-Downstream", ntohl(*(uint32_t *)ptr)))
					return -1;
				break;
			case OPT_MIN_DATA_RATE_UP:
				if (len != 6)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Minimum-Data-Rate-Upstream", ntohl(*(uint32_t *)ptr)))
					return -1;
				break;
			case OPT_MIN_DATA_RATE_DOWN:
				if (len != 6)
					goto inval;
				if (rad_packet_add_int(pack, "ADSL-Forum", "Minimum-Data-Rate-Downstream", ntohl(*(uint32_t *)ptr)))
					return -1;
				break;
		}
		ptr += len;
	}

	return 0;

inval:
	log_ppp_warn("pppoe:tr101: invalid tag received\n");
	return -1;
}

int tr101_send_access_request(struct pppoe_tag *tr101, struct rad_packet_t *pack)
{
	return tr101_send_request(tr101, pack, 1);
}

int tr101_send_accounting_request(struct pppoe_tag *tr101, struct rad_packet_t *pack)
{
	return tr101_send_request(tr101, pack, 0);
}
