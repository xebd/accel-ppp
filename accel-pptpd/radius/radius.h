#ifndef __RADIUS_H
#define __RADIUS_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>

#include "triton.h"
#include "ppp.h"
#include "ipdb.h"

#define REQ_LENGTH_MAX 4096

#define ATTR_TYPE_INTEGER 0
#define ATTR_TYPE_STRING  1
#define ATTR_TYPE_OCTETS  2
#define ATTR_TYPE_DATE    3
#define ATTR_TYPE_IPADDR  4

#define CODE_ACCESS_REQUEST 1
#define CODE_ACCESS_ACCEPT  2
#define CODE_ACCESS_REJECT  3
#define CODE_ACCESS_CHALLENGE 11

#define CODE_ACCOUNTING_REQUEST  4
#define CODE_ACCOUNTING_RESPONSE 5

#define CODE_DISCONNECT_REQUEST 40
#define CODE_DISCONNECT_ACK     41
#define CODE_DISCONNECT_NAK     42
#define CODE_COA_REQUEST 43
#define CODE_COA_ACK     44
#define CODE_COA_NAK     45

struct radius_pd_t
{
	struct list_head entry;
	struct ppp_pd_t pd;
	struct ppp_t *ppp;
	pthread_mutex_t lock;

	struct rad_req_t *acct_req;
	struct triton_timer_t acct_interim_timer;

	struct rad_packet_t *dm_coa_req;
	struct sockaddr_in dm_coa_addr;

	struct ipdb_item_t ipaddr;
	int acct_interim_interval;
};

typedef union
{
		int integer;
		char *string;
		uint8_t *octets;
		time_t date;
		in_addr_t ipaddr;
} rad_value_t;

struct rad_dict_t
{
	struct list_head items;
};

struct rad_dict_value_t
{
	struct list_head entry;
	rad_value_t val;
	const char *name;
};

struct rad_dict_attr_t
{
	struct list_head entry;
	const char *name;
	int id;
	int type;
	struct list_head values;
};

struct rad_attr_t
{
	struct list_head entry;
	struct rad_dict_attr_t *attr;
	//struct rad_dict_value_t *val;
	rad_value_t val;
	int len;
};

struct rad_packet_t
{
	int code;
	int id;
	int len;
	struct list_head attrs;
	void *buf;
};
struct rad_req_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout;
	uint8_t RA[16];
	struct rad_packet_t *pack;
	struct rad_packet_t *reply;
	const char *server_name;
	int server_port;

	struct radius_pd_t *rpd;
};


extern int conf_max_try;
extern int conf_timeout;
extern int conf_verbose;
extern char *conf_nas_identifier;
extern char *conf_nas_ip_address;
extern char *conf_gw_ip_address;
extern char *conf_auth_server;
extern char *conf_auth_secret;
extern int conf_auth_server_port;
extern char *conf_acct_server;
extern char *conf_acct_secret;
extern int conf_acct_server_port;
extern char *conf_dm_coa_secret;

int rad_check_nas_pack(struct rad_packet_t *pack);
struct radius_pd_t *rad_find_session(const char *sessionid, const char *username, int port_id, in_addr_t ipaddr);
struct radius_pd_t *rad_find_session_pack(struct rad_packet_t *pack);

int rad_dict_load(const char *fname);
void rad_dict_free(struct rad_dict_t *dict);
struct rad_dict_attr_t *rad_dict_find_attr(const char *name);
struct rad_dict_attr_t *rad_dict_find_attr_id(int type);
struct rad_dict_value_t *rad_dict_find_val_name(struct rad_dict_attr_t *, const char *name);
struct rad_dict_value_t *rad_dict_find_val(struct rad_dict_attr_t *, rad_value_t val);

struct rad_req_t *rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username);
int rad_req_acct_fill(struct rad_req_t *);
void rad_req_free(struct rad_req_t *);
int rad_req_send(struct rad_req_t *);
int rad_req_wait(struct rad_req_t *, int);

struct rad_attr_t *rad_packet_find_attr(struct rad_packet_t *pack, const char *name);
int rad_packet_add_int(struct rad_packet_t *pack, const char *name, int val);
int rad_packet_add_val(struct rad_packet_t *pack, const char *name, const char *val);
int rad_packet_add_str(struct rad_packet_t *pack, const char *name, const char *val, int len);
int rad_packet_add_octets(struct rad_packet_t *pack, const char *name, uint8_t *val, int len);
int rad_packet_change_int(struct rad_packet_t *pack, const char *name, int val);
int rad_packet_change_val(struct rad_packet_t *pack, const char *name, const char *val);

struct rad_packet_t *rad_packet_alloc(int code);
int rad_packet_build(struct rad_packet_t *pack, uint8_t *RA);
struct rad_packet_t *rad_packet_recv(int fd, struct sockaddr_in *addr);
void rad_packet_free(struct rad_packet_t *);
void rad_packet_print(struct rad_packet_t *pack, void (*print)(const char *fmt, ...));
int rad_packet_send(struct rad_packet_t *pck, int fd, struct sockaddr_in *addr);

struct radius_pd_t *find_pd(struct ppp_t *ppp);
void rad_proc_attrs(struct rad_req_t *req);

int rad_auth_pap(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_chap_md5(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_mschap_v1(struct radius_pd_t *rpd, const char *username, va_list args);
int rad_auth_mschap_v2(struct radius_pd_t *rpd, const char *username, va_list args);

int rad_acct_start(struct radius_pd_t *rpd);
void rad_acct_stop(struct radius_pd_t *rpd);

#endif

