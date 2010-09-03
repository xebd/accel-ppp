#ifndef TRITON_H
#define TRITON_H

#include <sys/time.h>

#include "list.h"

struct triton_ctx_t
{
	const void *tpd; // triton private data, don't touch!
	void (*close)(struct triton_ctx_t*);
	void (*free)(struct triton_ctx_t*);
};

struct triton_md_handler_t
{
	const void *tpd; // triton private data, don't touch!
	int fd;
	int (*read)(struct triton_md_handler_t *);
	int (*write)(struct triton_md_handler_t *);
};

struct triton_timer_t
{
	const void *tpd; // triton private data, don't touch!
	struct timeval expire_tv;
	int period;
	void (*expire)(struct triton_timer_t *);
};

struct conf_option_t
{
	struct list_head entry;
	char *name;
	char *val;
};

struct conf_sect_t
{
	const char *name;	
	struct list_head items;
};

void triton_register_ctx(struct triton_ctx_t *);
void triton_unregister_ctx(struct triton_ctx_t *);

#define MD_MODE_READ 1
#define MD_MODE_WRITE 2
void triton_md_register_handler(struct triton_ctx_t *, struct triton_md_handler_t *);
void triton_md_unregister_handler(struct triton_md_handler_t *h);
int triton_md_enable_handler(struct triton_md_handler_t *h, int mode);
int triton_md_disable_handler(struct triton_md_handler_t *h,int mode);

int triton_timer_add(struct triton_ctx_t *ctx, struct triton_timer_t*,int abs_time);
int triton_timer_mod(struct triton_timer_t *,int abs_time);
void triton_timer_del(struct triton_timer_t *);

struct conf_sect_t *conf_get_section(const char *name);
char *conf_get_opt(const char *sect, const char *name);

#define TRITON_OK          0
#define TRITON_ERR_NOCOMP -1
#define TRITON_ERR_NOSUPP -2
#define TRITON_ERR_NOINTF -3
#define TRITON_ERR_EXISTS -4
#define TRITON_ERR_NOCHAN -5
#define TRITON_ERR_NOMSG  -6
#define TRITON_ERR_BUSY   -5

int triton_init(const char *conf_file);
void triton_run(void);
void triton_terminate(void);


#define __init __attribute__((constructor))
#define __export __attribute__((visibility("default")))

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#endif
