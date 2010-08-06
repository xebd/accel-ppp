#ifndef PPP_FSM_H
#define PPP_FSM_H

#include "triton/triton.h"
#include "list.h"

typedef enum {FSM_Initial=0,FSM_Starting,FSM_Closed,FSM_Stopped,FSM_Closing,FSM_Stopping,FSM_Req_Sent,FSM_Ack_Rcvd,FSM_Ack_Sent,FSM_Opened} FSM_STATE;
/*
 *  CP (LCP, IPCP, etc.) codes.
 */
#define CONFREQ		1	/* Configuration Request */
#define CONFACK		2	/* Configuration Ack */
#define CONFNAK		3	/* Configuration Nak */
#define CONFREJ		4	/* Configuration Reject */
#define TERMREQ		5	/* Termination Request */
#define TERMACK		6	/* Termination Ack */
#define CODEREJ		7	/* Code Reject */
#define ECHOREQ		9	/* Echo Request */
#define ECHOREP		10	/* Echo Reply */

struct ppp_hdr_t;

#define AUTH_MAX	3
struct lcp_options_t
{
	int magic;
	int mtu;
	int mru;
	int accomp; // 0 - disabled, 1 - enable, 2 - allow, disabled, 3 - allow,enabled
	int pcomp;  // 0 - disabled, 1 - enable, 2 - allow, disabled, 3 - allow,enabled
	// negotiated options;
	int neg_mru;
	int neg_mtu;
	int neg_accomp; // -1 - rejected
	int neg_pcomp;
	int neg_auth[AUTH_MAX];
};

struct ppp_layer_t
{
	struct list_head entry;
	struct ppp_layer_t *lower;
	struct ppp_layer_t *upper;

	int proto;
	struct ppp_t *ppp;
	FSM_STATE fsm_state;
	
	union
	{
		struct lcp_options_t lcp;
	}options;

	struct triton_timer_t restart_timer;
	int restart_counter;
	int max_terminate;
	int max_configure;
	int max_failure;

	int id;
	int recv_id;
	int auth[AUTH_MAX];

	int opt_restart:1;
	int opt_passive:1;

	void *last_conf_req;
	//fsm handling
	void (*layer_up)(struct ppp_layer_t*);
	void (*layer_down)(struct ppp_layer_t*);
	void (*layer_started)(struct ppp_layer_t*);
	void (*layer_finished)(struct ppp_layer_t*);
	void (*send_conf_req)(struct ppp_layer_t*);
	void (*send_conf_ack)(struct ppp_layer_t*);
	void (*send_conf_nak)(struct ppp_layer_t*);
	void (*send_conf_rej)(struct ppp_layer_t*);
	void (*recv)(struct ppp_layer_t*);
};

void ppp_fsm_init(struct ppp_layer_t*);
void ppp_fsm_recv(struct ppp_layer_t*);

void ppp_fsm_lower_up(struct ppp_layer_t *layer);
void ppp_fsm_lower_down(struct ppp_layer_t *layer);
void ppp_fsm_open(struct ppp_layer_t *layer);
void ppp_fsm_close(struct ppp_layer_t *layer);
void ppp_fsm_timeout0(struct ppp_layer_t *layer);
void ppp_fsm_timeout1(struct ppp_layer_t *layer);
void ppp_fsm_recv_conf_req_good(struct ppp_layer_t *layer);
void ppp_fsm_recv_conf_req_bad(struct ppp_layer_t *layer);
void ppp_fsm_recv_conf_ack(struct ppp_layer_t *layer);
void ppp_fsm_recv_conf_rej(struct ppp_layer_t *layer);
void ppp_fsm_recv_term_req(struct ppp_layer_t *layer);
void ppp_fsm_recv_term_ack(struct ppp_layer_t *layer);
void ppp_fsm_recv_unk(struct ppp_layer_t *layer);
void ppp_fsm_recv_code_rej_bad(struct ppp_layer_t *layer);
void ppp_fsm_recv_echo(struct ppp_layer_t *layer);

#endif
