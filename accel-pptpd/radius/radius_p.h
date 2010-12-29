#ifndef __RADIUS_P_H
#define __RADIUS_P_H

#include <netinet/in.h>
#include <pthread.h>

#include "triton.h"
#include "radius.h"
#include "ppp.h"
#include "ipdb.h"

struct radius_pd_t
{
	struct list_head entry;
	struct ppp_pd_t pd;
	struct ppp_t *ppp;
	pthread_mutex_t lock;

	struct rad_req_t *auth_req;
	struct rad_req_t *acct_req;
	struct triton_timer_t acct_interim_timer;
	uint32_t acct_input_octets;
	uint32_t acct_output_octets;
	uint32_t acct_input_gigawords;
	uint32_t acct_output_gigawords;

	struct triton_timer_t session_timeout;

	struct rad_packet_t *dm_coa_req;
	struct sockaddr_in dm_coa_addr;

	struct ipdb_item_t ipaddr;
	int acct_interim_interval;
	time_t acct_timestamp;

	uint8_t *attr_class;
	int attr_class_len;
	uint8_t *attr_state;
	int attr_state_len;
	int termination_action;	

	struct list_head plugin_list;
};

struct rad_req_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout;
	uint8_t RA[16];
	struct rad_packet_t *pack;
	struct rad_packet_t *reply;
	in_addr_t server_addr;
	int server_port;

	struct radius_pd_t *rpd;
};

extern int conf_max_try;
extern int conf_timeout;
extern int conf_acct_timeout;
extern int conf_verbose;
extern int conf_interim_verbose;
extern char *conf_nas_identifier;
extern in_addr_t conf_nas_ip_address;
extern in_addr_t conf_bind;
extern in_addr_t conf_gw_ip_address;
extern in_addr_t conf_auth_server;
extern char *conf_auth_secret;
extern int conf_auth_server_port;
extern in_addr_t conf_acct_server;
extern char *conf_acct_secret;
extern int conf_acct_server_port;
extern char *conf_dm_coa_secret;
extern int conf_sid_in_auth;
extern int conf_require_nas_ident;
extern in_addr_t conf_dm_coa_server;
extern int conf_dm_coa_port;
extern int conf_acct_interim_interval;

int rad_check_nas_pack(struct rad_packet_t *pack);
struct radius_pd_t *rad_find_session(const char *sessionid, const char *username, int port_id, in_addr_t ipaddr, const char *csid);
struct radius_pd_t *rad_find_session_pack(struct rad_packet_t *pack);

int rad_dict_load(const char *fname);
void rad_dict_free(struct rad_dict_t *dict);

struct rad_req_t *rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username);
int rad_req_acct_fill(struct rad_req_t *);
void rad_req_free(struct rad_req_t *);
int rad_req_send(struct rad_req_t *, int verbose);
int rad_req_wait(struct rad_req_t *, int);

struct radius_pd_t *find_pd(struct ppp_t *ppp);
int rad_proc_attrs(struct rad_req_t *req);

int rad_auth_pap(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_chap_md5(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_mschap_v1(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_mschap_v2(struct radius_pd_t *rpd, const char *username, va_list args);

int rad_acct_start(struct radius_pd_t *rpd);
void rad_acct_stop(struct radius_pd_t *rpd);

struct rad_packet_t *rad_packet_alloc(int code);
int rad_packet_build(struct rad_packet_t *pack, uint8_t *RA);
int rad_packet_recv(int fd, struct rad_packet_t **, struct sockaddr_in *addr);
void rad_packet_free(struct rad_packet_t *);
void rad_packet_print(struct rad_packet_t *pack, void (*print)(const char *fmt, ...));
int rad_packet_send(struct rad_packet_t *pck, int fd, struct sockaddr_in *addr);

void dm_coa_cancel(struct radius_pd_t *pd);

#endif

