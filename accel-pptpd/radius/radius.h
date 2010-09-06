#ifndef __RADIUS_H
#define __RADIUS_H

#include <netinet/in.h>
#include "triton.h"
#include "ppp.h"

#define REQ_LENGTH_MAX 4096

#define ATTR_TYPE_INTEGER 0
#define ATTR_TYPE_STRING  1
#define ATTR_TYPE_DATE    2
#define ATTR_TYPE_IPADDR  3

#define CODE_ACCESS_REQUEST 1

struct radius_pd_t
{
	struct ppp_pd_t pd;
	struct ppp_t *ppp;
};

typedef union
{
		int integer;
		const char *string;
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

struct rad_req_attr_t
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
	struct triton_md_handler_t hnd;
	struct triton_timer_t timeout;
	struct rad_packet_t pack;
	struct rad_packet_t *reply;
	const char *server_name;
	int server_port;

	struct radius_pd_t *rpd;
};


extern int conf_max_try;
extern int conf_timeout;
extern char *conf_nas_identifier;
extern char *conf_nas_ip_address;

int rad_dict_load(const char *fname);
void rad_dict_free(struct rad_dict_t *dict);
struct rad_dict_attr_t *rad_dict_find_attr(const char *name);
struct rad_dict_attr_t *rad_dict_find_attr_type(int type);
struct rad_dict_value_t *rad_dict_find_val(struct rad_dict_attr_t *, const char *name);

struct rad_req_t *rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username);
void rad_req_free(struct rad_req_t *);
int rad_req_send(struct rad_req_t *);
int rad_req_wait(struct rad_req_t *, int);
int rad_req_add_int(struct rad_req_t *req, const char *name, int val);
int rad_req_add_val(struct rad_req_t *req, const char *name, const char *val, int len);
int rad_req_add_str(struct rad_req_t *req, const char *name, const char *val, int len);

int rad_packet_build(struct rad_packet_t *pack);
struct rad_packet_t *rad_packet_recv(int fd);
void rad_packet_free(struct rad_packet_t *);


#endif

