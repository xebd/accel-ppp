#ifndef PPP_AUTH_H
#define PPP_AUTH_H

#include "list.h"

struct ppp_layer_t;
struct lcp_opt_hdr_t;
struct lcp_opt32_t;

struct auth_driver_t
{
	struct list_head entry;
	int type;
	int (*get_conf_req)(struct auth_driver_t*, struct ppp_layer_t*, struct lcp_opt32_t*);
	int (*recv_conf_req)(struct auth_driver_t*, struct ppp_layer_t*, struct lcp_opt32_t*);
};

int auth_get_conf_req(struct ppp_layer_t *l, struct lcp_opt32_t *);
int auth_recv_conf_req(struct ppp_layer_t *l, struct lcp_opt_hdr_t *);
int auth_recv_conf_rej(struct ppp_layer_t *l, struct lcp_opt_hdr_t *);
int auth_recv_conf_nak(struct ppp_layer_t *l, struct lcp_opt_hdr_t *);

#endif

