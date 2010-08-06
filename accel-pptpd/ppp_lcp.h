#ifndef PPP_LCP_H
#define PPP_LCP_H

#include <stdint.h>

/*
 * Options.
 */
#define CI_VENDOR	0	/* Vendor Specific */
#define CI_MRU		1	/* Maximum Receive Unit */
#define CI_ASYNCMAP	2	/* Async Control Character Map */
#define CI_AUTHTYPE	3	/* Authentication Type */
#define CI_QUALITY	4	/* Quality Protocol */
#define CI_MAGIC	5	/* Magic Number */
#define CI_PCOMP	7	/* Protocol Field Compression */
#define CI_ACCOMP 8	/* Address/Control Field Compression */
#define CI_FCSALTERN	9	/* FCS-Alternatives */
#define CI_SDP		10	/* Self-Describing-Pad */
#define CI_NUMBERED	11	/* Numbered-Mode */
#define CI_CALLBACK	13	/* callback */
#define CI_MRRU		17	/* max reconstructed receive unit; multilink */
#define CI_SSNHF	18	/* short sequence numbers for multilink */
#define CI_EPDISC	19	/* endpoint discriminator */
#define CI_MPPLUS	22	/* Multi-Link-Plus-Procedure */
#define CI_LDISC	23	/* Link-Discriminator */
#define CI_LCPAUTH	24	/* LCP Authentication */
#define CI_COBS		25	/* Consistent Overhead Byte Stuffing */
#define CI_PREFELIS	26	/* Prefix Elision */
#define CI_MPHDRFMT	27	/* MP Header Format */
#define CI_I18N		28	/* Internationalization */
#define CI_SDL		29	/* Simple Data Link */

struct lcp_hdr_t
{
	uint16_t proto;
	uint8_t code;
	uint8_t id;
	uint16_t len;
} __attribute__((packed));
struct lcp_opt_hdr_t
{
	uint8_t type;
	uint8_t len;
} __attribute__((packed));
struct lcp_opt8_t
{
	struct lcp_opt_hdr_t hdr;
	uint8_t val;
} __attribute__((packed));
struct lcp_opt16_t
{
	struct lcp_opt_hdr_t hdr;
	uint16_t val;
} __attribute__((packed));
struct lcp_opt32_t
{
	struct lcp_opt_hdr_t hdr;
	uint32_t val;
} __attribute__((packed));



#endif

