#ifndef PPP_FSM_H
#define PPP_FSM_H

#include <stdint.h>

#include "ppp.h"
#include "triton.h"

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
#define PROTOREJ	8	/* Code Reject */
#define ECHOREQ		9	/* Echo Request */
#define ECHOREP		10	/* Echo Reply */
#define DISCARDREQ	11	/* Discard Request */
#define	IDENT		  12	/* Identification */

struct ppp_fsm_t
{
	struct ppp_t *ppp;
	FSM_STATE fsm_state;
	uint16_t proto;

	struct triton_timer_t restart_timer;
	int restart_counter;
	int max_terminate;
	int max_configure;
	int max_failure;
	int conf_failure;

	uint8_t id;
	uint8_t recv_id;

	//fsm handling
	void (*layer_up)(struct ppp_fsm_t*);
	void (*layer_down)(struct ppp_fsm_t*);
	void (*layer_started)(struct ppp_fsm_t*);
	void (*layer_finished)(struct ppp_fsm_t*);
	int (*send_conf_req)(struct ppp_fsm_t*);
	void (*send_conf_ack)(struct ppp_fsm_t*);
	void (*send_conf_nak)(struct ppp_fsm_t*);
	void (*send_conf_rej)(struct ppp_fsm_t*);
	void (*send_code_rej)(struct ppp_fsm_t*);
	void (*send_term_req)(struct ppp_fsm_t*);
	void (*send_term_ack)(struct ppp_fsm_t*);
};

void ppp_fsm_init(struct ppp_fsm_t*);
void ppp_fsm_free(struct ppp_fsm_t*);

int ppp_fsm_lower_up(struct ppp_fsm_t*);
void ppp_fsm_lower_down(struct ppp_fsm_t*);
int ppp_fsm_open(struct ppp_fsm_t*);
void ppp_fsm_close(struct ppp_fsm_t*);
void ppp_fsm_close2(struct ppp_fsm_t *layer);
void ppp_fsm_timeout0(struct ppp_fsm_t *layer);
void ppp_fsm_timeout1(struct ppp_fsm_t *layer);
void ppp_fsm_recv_conf_req_ack(struct ppp_fsm_t *layer);
void ppp_fsm_recv_conf_req_nak(struct ppp_fsm_t *layer);
void ppp_fsm_recv_conf_req_rej(struct ppp_fsm_t *layer);
void ppp_fsm_recv_conf_ack(struct ppp_fsm_t *layer);
void ppp_fsm_recv_conf_rej(struct ppp_fsm_t *layer);
void ppp_fsm_recv_term_req(struct ppp_fsm_t *layer);
void ppp_fsm_recv_term_ack(struct ppp_fsm_t *layer);
void ppp_fsm_recv_unk(struct ppp_fsm_t *layer);
void ppp_fsm_recv_code_rej_bad(struct ppp_fsm_t *layer);

#endif
