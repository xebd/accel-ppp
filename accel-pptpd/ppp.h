#ifndef PPP_H
#define PPP_H

#include <sys/types.h>
#include "ppp_fsm.h"

/*
 * Packet header = Code, id, length.
 */
#define PPP_HEADERLEN	4
#define PPP_MTU 1500

/*
 * Timeouts.
 */
#define DEFTIMEOUT	3	/* Timeout time in seconds */
#define DEFMAXTERMREQS	2	/* Maximum Terminate-Request transmissions */
#define DEFMAXCONFREQS	10	/* Maximum Configure-Request transmissions */
#define DEFMAXNAKLOOPS	5	/* Maximum number of nak loops */

/*
 * Protocol field values.
 */
#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_AT		0x29	/* AppleTalk Protocol */
#define PPP_IPX		0x2b	/* IPX protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define PPP_IPV6CP	0x8057	/* IPv6 Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_ECP		0x8053	/* Encryption Control Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029	/* Callback Control Protocol */
#define PPP_EAP		0xc227	/* Extensible Authentication Protocol */

struct ppp_t
{
	struct triton_md_handler_t *h;
	int fd;
	int chan_fd;
	int unit_fd;

	int chan_idx;
	int unit_idx;

	char *chan_name;

	//options
	int mtu,mru;
	int accomp; // 0 - disabled, 1 - enable, 2 - allow, disabled, 3 - allow,enabled
	int pcomp; // 0 - disabled, 1 - enable, 2 - allow, disabled, 3 - allow,enabled
	// 
	
	int log:1;

	void *out_buf;
	int out_buf_size;
	int out_buf_pos;

	void *in_buf;
	int in_buf_size;

	struct ppp_layer_t *lcp_layer;
	struct list_head layers;
};

struct ppp_fsm_handler_t
{
	void (*reset_conf)(struct ppp_t *ppp);		/* Reset our Configuration Information */
	int  (*conf_length)(struct ppp_t *ppp);		/* Length of our Configuration Information */
	void (*add_conf)(struct ppp_t *ppp, unsigned char *, int *); 		/* Add our Configuration Information */
	int  (*ack_conf)(struct ppp_t *ppp, unsigned char *,int);		/* ACK our Configuration Information */
	int  (*nak_conf)(struct ppp_t *ppp, unsigned char *,int,int);		/* NAK our Configuration Information */
	int  (*rej_conf)(struct ppp_t *ppp, unsigned char *,int);		/* Reject our Configuration Information */
	int  (*req_conf)(struct ppp_t *ppp, unsigned char *,int *,int);		/* Request peer's Configuration Information */
	void (*opened)(struct ppp_t *ppp);			/* Called when fsm reaches OPENED state */
	void (*down)(struct ppp_t *ppp);		/* Called when fsm leaves OPENED state */
	void (*starting)(struct ppp_t *ppp);		/* Called when we want the lower layer */
	void (*finished)(struct ppp_t *ppp);		/* Called when we don't want the lower layer */
	void (*protreject)(struct ppp_t *ppp,int);		/* Called when Protocol-Reject received */
	void (*retransmit)(struct ppp_t *ppp);		/* Retransmission is necessary */
	int  (*extcode)(struct ppp_t *ppp, int, int, unsigned char *, int);		/* Called when unknown code received */
	char *proto_name;		/* String name for protocol (for messages) */
};

struct ppp_hdr_t
{
	u_int8_t code;
	u_int8_t id;
	u_int16_t len;
	u_int8_t data[100];
}__attribute__((packed));

struct ppp_opt_t
{
	u_int8_t type;
	u_int16_t len;
	u_int8_t data[100];
}__attribute__((packed));

struct ppp_t *alloc_ppp(void);
int establish_ppp(struct ppp_t *ppp);
int ppp_send(struct ppp_t *ppp, void *data, int size);

void ppp_init(void);

struct ppp_layer_t* ppp_lcp_init(struct ppp_t *ppp);

#endif
