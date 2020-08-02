#ifndef PPP_AUTH_H
#define PPP_AUTH_H

#include <stdint.h>

#include "list.h"
#include "ppp.h"

struct ppp_auth_handler_t;

struct auth_data_t
{
	struct list_head entry;
	int proto;
	int state;
	int len;
	struct ppp_auth_handler_t *h;
};

struct ppp_auth_handler_t
{
	struct list_head entry;
	const char *name;
	struct auth_data_t* (*init)(struct ppp_t*);
	int (*send_conf_req)(struct ppp_t*, struct auth_data_t*, uint8_t*);
	int (*start)(struct ppp_t*, struct auth_data_t*);
	int (*finish)(struct ppp_t*, struct auth_data_t*);
	void (*free)(struct ppp_t*,struct auth_data_t*);
	int (*check)(uint8_t *);
	int (*restart)(struct ppp_t*,struct auth_data_t*);
};

int ppp_auth_register_handler(struct ppp_auth_handler_t*);

int ppp_auth_succeeded(struct ppp_t *ppp, char *username);
void ppp_auth_failed(struct ppp_t *ppp, char *username);
int ppp_auth_restart(struct ppp_t *ppp);

#endif

