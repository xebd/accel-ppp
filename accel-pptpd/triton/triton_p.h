#ifndef TRITON_P_H
#define TRITON_P_H

#include <pthread.h>
#include <sys/epoll.h>

#include "triton.h"
#include "list.h"
#include "spinlock.h"

struct _triton_thread_t
{
	struct list_head entry;
	struct list_head entry2;
	pthread_t thread;
	int terminate:1;
	struct _triton_ctx_t *ctx;
};

struct _triton_ctx_t
{
	struct list_head entry;
	struct list_head entry2;
	spinlock_t lock;
	struct list_head handlers;
	struct list_head timers;

	struct _triton_thread_t *thread;
	struct list_head pending_handlers;
	struct list_head pending_timers;
	int queued:1;
	int need_close:1;
	int need_free:1;

	struct triton_ctx_t *ud;
};

struct _triton_md_handler_t
{
	struct list_head entry;
	struct list_head entry2;
	struct _triton_ctx_t *ctx;
	struct epoll_event epoll_event;
	uint32_t trig_epoll_events;
	int pending:1;
	struct triton_md_handler_t *ud;
};

struct _triton_timer_t
{
	struct list_head entry;
	struct list_head entry2;
	struct epoll_event epoll_event;
	struct _triton_ctx_t *ctx;
	int fd;
	int pending:1;
	struct triton_timer_t *ud;
};

typedef void * mempool_t;
mempool_t *mempool_create(int size);
void *mempool_alloc(mempool_t*);
void mempool_free(void*);

int log_init(void);
int md_init();
void md_run();
void md_terminate();
int timer_init();
void timer_run();
void timer_terminate();
struct triton_ctx_t *default_ctx;
int triton_queue_ctx(struct _triton_ctx_t*);
void triton_thread_wakeup(struct _triton_thread_t*);
int conf_load(const char *fname);
void triton_log_error(const char *fmt,...);
void triton_log_debug(const char *fmt,...);
int load_modules(const char *name);

#endif
