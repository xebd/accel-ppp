#ifndef PPP_H
#define PPP_H

#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <pthread.h>

#include "triton.h"
#include "list.h"

/*
 * Packet header = Code, id, length.
 */
#define PPP_HEADERLEN	4
#define PPP_MTU 1500


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

#define PPP_SESSIONID_LEN 16
#define PPP_IFNAME_LEN 10

#define PPP_STATE_STARTING  1
#define PPP_STATE_ACTIVE    2
#define PPP_STATE_FINISHING 3

#define TERM_USER_REQUEST 1
#define TERM_SESSION_TIMEOUT 2
#define TERM_ADMIN_RESET 3
#define TERM_USER_ERROR 4
#define TERM_NAS_ERROR 5
#define TERM_AUTH_ERROR 6


struct ppp_t;

struct ppp_ctrl_t
{
	struct triton_context_t *ctx;
	const char *name;
	int max_mtu;
	char *calling_station_id;
	char *called_station_id;
	void (*started)(struct ppp_t*);
	void (*finished)(struct ppp_t*);
};

struct ppp_pd_t
{
	struct list_head entry;
	void *key;
};

struct ppp_t
{
	struct list_head entry;
	struct triton_md_handler_t chan_hnd;
	struct triton_md_handler_t unit_hnd;
	int fd;
	int chan_fd;
	int unit_fd;

	int chan_idx;
	int unit_idx;

	int state;
	char *chan_name;
	char ifname[PPP_IFNAME_LEN];
	char sessionid[PPP_SESSIONID_LEN+1];
	time_t start_time;
	time_t stop_time;
	char *username;
	in_addr_t ipaddr;
	in_addr_t peer_ipaddr;

	struct ppp_ctrl_t *ctrl;

	int terminating:1;
	int terminated:1;
	int terminate_cause;

	void *chan_buf;
	int chan_buf_size;
	void *unit_buf;
	int unit_buf_size;

	struct list_head chan_handlers;
	struct list_head unit_handlers;

	struct list_head layers;
	
	struct ppp_lcp_t *lcp;

	struct list_head pd_list;
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
	int finished:1;
};

struct ppp_layer_t
{
	struct list_head entry;
	struct ppp_layer_data_t *(*init)(struct ppp_t *);
	int (*start)(struct ppp_layer_data_t*);
	void (*finish)(struct ppp_layer_data_t*);
	void (*free)(struct ppp_layer_data_t *);
};

struct ppp_handler_t
{
	struct list_head entry;
	int proto;
	void (*recv)(struct ppp_handler_t*);
	void (*recv_proto_rej)(struct ppp_handler_t *h);
};

struct ppp_stat_t
{
	uint32_t active;
	uint32_t starting;
	uint32_t finishing;
};

struct ppp_t *alloc_ppp(void);
void ppp_init(struct ppp_t *ppp);
int establish_ppp(struct ppp_t *ppp);
int ppp_chan_send(struct ppp_t *ppp, void *data, int size);
int ppp_unit_send(struct ppp_t *ppp, void *data, int size);
void lcp_send_proto_rej(struct ppp_t *ppp, uint16_t proto);
void ppp_recv_proto_rej(struct ppp_t *ppp, uint16_t proto);

struct ppp_fsm_t* ppp_lcp_init(struct ppp_t *ppp);
void ppp_layer_started(struct ppp_t *ppp,struct ppp_layer_data_t*);
void ppp_layer_finished(struct ppp_t *ppp,struct ppp_layer_data_t*);
void ppp_terminate(struct ppp_t *ppp, int hard, int cause);

void ppp_register_chan_handler(struct ppp_t *, struct ppp_handler_t *);
void ppp_register_unit_handler(struct ppp_t * ,struct ppp_handler_t *);
void ppp_unregister_handler(struct ppp_t *, struct ppp_handler_t *);

int ppp_register_layer(const char *name, struct ppp_layer_t *);
void ppp_unregister_layer(struct ppp_layer_t *);
struct ppp_layer_data_t *ppp_find_layer_data(struct ppp_t *, struct ppp_layer_t *);

extern int conf_ppp_verbose;

extern pthread_rwlock_t ppp_lock;
extern struct list_head ppp_list;

extern struct ppp_stat_t ppp_stat;

extern int sock_fd; // internet socket for ioctls
#endif
