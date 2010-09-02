#ifndef PPP_H
#define PPP_H

#include <sys/types.h>

#include "triton/triton.h"
#include "list.h"

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

#define PPP_LAYER_LCP  1
#define PPP_LAYER_AUTH 2
#define PPP_LAYER_CCP  3
#define PPP_LAYER_IPCP 4

#define AUTH_MAX	3

struct ppp_t;

struct ppp_ctrl_t
{
	struct triton_ctx_t *ctx;
	void (*started)(struct ppp_t*);
	void (*finished)(struct ppp_t*);
};

struct ppp_t
{
	struct triton_md_handler_t chan_hnd;
	struct triton_md_handler_t unit_hnd;
	int fd;
	int chan_fd;
	int unit_fd;

	int chan_idx;
	int unit_idx;

	char *chan_name;

	struct ppp_ctrl_t *ctrl;

	int log:1;

	void *chan_buf;
	int chan_buf_size;
	void *unit_buf;
	int unit_buf_size;

	struct list_head chan_handlers;
	struct list_head unit_handlers;

	struct list_head layers;
	
	struct ppp_lcp_t *lcp;
};

struct ppp_layer_t;
struct layer_node_t;
struct ppp_layer_data_t
{
	struct list_head entry;
	struct ppp_layer_t *layer;
	struct layer_node_t *node;
	int starting:1;
	int started:1;
};

struct ppp_layer_t
{
	struct list_head entry;
	struct ppp_layer_data_t *(*init)(struct ppp_t *);
	void (*start)(struct ppp_layer_data_t*);
	void (*finish)(struct ppp_layer_data_t*);
	void (*free)(struct ppp_layer_data_t *);
};

struct ppp_handler_t
{
	struct list_head entry;
	int proto;
	void (*recv)(struct ppp_handler_t*);
};

struct ppp_t *alloc_ppp(void);
int establish_ppp(struct ppp_t *ppp);
int ppp_chan_send(struct ppp_t *ppp, void *data, int size);
int ppp_unit_send(struct ppp_t *ppp, void *data, int size);

void ppp_init(void);

struct ppp_fsm_t* ppp_lcp_init(struct ppp_t *ppp);
void ppp_layer_started(struct ppp_t *ppp,struct ppp_layer_data_t*);
void ppp_layer_finished(struct ppp_t *ppp,struct ppp_layer_data_t*);
void ppp_terminate(struct ppp_t *ppp);

void ppp_register_chan_handler(struct ppp_t *, struct ppp_handler_t *);
void ppp_register_unit_handler(struct ppp_t * ,struct ppp_handler_t *);
void ppp_unregister_handler(struct ppp_t *, struct ppp_handler_t *);

int ppp_register_layer(const char *name, struct ppp_layer_t *);
void ppp_unregister_layer(struct ppp_layer_t *);
struct ppp_layer_data_t *ppp_find_layer_data(struct ppp_t *, struct ppp_layer_t *);

#endif
