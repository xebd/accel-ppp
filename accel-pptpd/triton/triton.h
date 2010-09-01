#ifndef TRITON_H
#define TRITON_H

#include <sys/time.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "list.h"
#include "spinlock.h"

struct triton_thread_t
{
	struct list_head entry;
	struct list_head entry2;
	pthread_t thread;
	int terminate:1;
	struct triton_ctx_t *ctx;
};

struct triton_ctx_t
{
	struct list_head entry;
	struct list_head entry2;
	spinlock_t lock;
	struct list_head handlers;
	struct list_head timers;

	struct triton_thread_t *thread;
	struct list_head pending_handlers;
	struct list_head pending_timers;
	int queued:1;
	int need_close:1;
	int need_free:1;

	void (*close)(struct triton_ctx_t*);
	void (*free)(struct triton_ctx_t*);
};

struct triton_md_handler_t
{
	//triton part
	//==========
	struct list_head entry;
	struct list_head entry2;
	struct triton_ctx_t *ctx;
	struct epoll_event epoll_event;
	uint32_t trig_epoll_events;
	int pending:1;
	//=========

	//user part
	//=========
	int fd;

	int (*read)(struct triton_md_handler_t *);
	int (*write)(struct triton_md_handler_t *);
	//=========
};

struct triton_timer_t
{
	struct list_head entry;
	struct list_head entry2;
	struct epoll_event epoll_event;
	struct triton_ctx_t *ctx;
	int fd;
	int pending:1;

	struct timeval expire_tv;
	int period;
	int (*expire)(struct triton_timer_t *);
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
void triton_md_register_handler(struct triton_md_handler_t *h);
void triton_md_unregister_handler(struct triton_md_handler_t *h);
int triton_md_enable_handler(struct triton_md_handler_t *h, int mode);
int triton_md_disable_handler(struct triton_md_handler_t *h,int mode);

int triton_timer_add(struct triton_timer_t*,int abs_time);
int triton_timer_mod(struct triton_timer_t*,int abs_time);
void triton_timer_del(struct triton_timer_t*);

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

#endif
