#ifndef TRITON_H
#define TRITON_H

#include <sys/time.h>
#include <pthread.h>
#include <sys/epoll.h>

struct triton_thread_t
{
	struct list_head entry;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	pthread_t thread;
	int terminate:1;
	int destroing:1;
	struct timeval tv;
	struct triton_ctx_t *ctx;
};

struct triton_ctx_t
{
	struct list_head entry;
	struct list_head entry2;
	pthread_mutex_t lock;
	struct list_head handlers;
	struct list_head timers;

	triton_thread_t *thread;
	struct list_head pending_handlers;
	struct list_head pending_timers;
	int queued:1;
	int close:1;
};

struct triton_md_handler_t
{
	//triton part
	//==========
	struct list_head entry;
	struct list_head entry2;
	struct triton_ctx_t *ctx;
	struct epoll_event epoll_event;
	uint32_t trig_epoll_event;
	int pending:1;
	//=========

	//user part
	//=========
	int fd;

	int (*read)(struct triton_md_handler_t *);
	int (*write)(struct triton_md_handler_t *);
	void (*close)(struct triton_md_handler_t *);
	//=========
};

struct triton_timer_t
{
	struct list_head entry;
	int active;
	int pending:1;

	struct timeval expire_tv;
	int period;
	int (*expire)(struct triton_timer_t *);
};

#define MD_MODE_READ 1
#define MD_MODE_WRITE 2
void triton_md_register_handler(struct triton_md_handler_t *h);
void triton_md_unregister_handler(struct triton_md_handler_t *h);
void triton_md_enable_handler(struct triton_md_handler_t *h, int mode);
void triton_md_disable_handler(struct triton_md_handler_t *h,int mode);
void triton_md_set_timeout(struct triton_md_handler_t *h, int msec);

void triton_timer_add(struct triton_timer_t*);
void triton_timer_del(struct triton_timer_t*);

typedef void (*triton_ss_func)(void);
void triton_timer_single_shot1(int twait,triton_ss_func,int argc,...);
void triton_timer_single_shot2(struct  timeval *shot_tv,triton_ss_func,int argc,...);
void triton_timer_single_shot3(int tv_sec,int tv_usec,triton_ss_func,int argc,...);

int triton_get_int_option(const char *str);
const char* triton_get_str_option(const char *str);
double triton_get_double_option(const char *str);

void triton_terminate(void);
void triton_process_events(void);

#define TRITON_OK          0
#define TRITON_ERR_NOCOMP -1
#define TRITON_ERR_NOSUPP -2
#define TRITON_ERR_NOINTF -3
#define TRITON_ERR_EXISTS -4
#define TRITON_ERR_NOCHAN -5
#define TRITON_ERR_NOMSG  -6
#define TRITON_ERR_BUSY   -5

int triton_init(const char *conf_file);
int triton_run(int (*post_init)(void*),void *arg);

#endif
