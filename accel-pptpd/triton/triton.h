#ifndef TRITON_H
#define TRITON_H

#include <sys/time.h>

struct triton_md_handler_t
{
	int fd;
	int twait;
	void *pd;

	void (*read)(struct triton_md_handler_t *h);
	void (*write)(struct triton_md_handler_t *h);
	void (*timeout)(struct triton_md_handler_t *h);
};

#define MD_MODE_READ 1
#define MD_MODE_WRITE 2
void triton_md_register_handler(struct triton_md_handler_t *h);
void triton_md_unregister_handler(struct triton_md_handler_t *h);
void triton_md_enable_handler(struct triton_md_handler_t *h, int mode);
void triton_md_disable_handler(struct triton_md_handler_t *h,int mode);
int triton_md_wait(struct triton_md_handler_t *h);
int triton_md_wait2(int fd,int mode,int timeout);

struct triton_timer_t
{
	struct timeval expire_tv;
	int period;
	void *pd;
	int active;

	int (*expire)(struct triton_timer_t*);
};

void triton_timer_add(struct triton_timer_t*);
void triton_timer_del(struct triton_timer_t*);

typedef void (*triton_ss_func)(void);
void triton_timer_single_shot1(int twait,triton_ss_func,int argc,...);
void triton_timer_single_shot2(struct  timeval *shot_tv,triton_ss_func,int argc,...);
void triton_timer_single_shot3(int tv_sec,int tv_usec,triton_ss_func,int argc,...);

typedef void (*triton_event_func)(void);
void triton_event_register_handler(int ev_id,triton_event_func,int argc,...);
void triton_event_unregister_handler(int ev_id,triton_event_func);
void triton_event_fire(int ev_id,int argc,...);

int triton_get_int_option(const char *str);
const char* triton_get_str_option(const char *str);
double triton_get_double_option(const char *str);

void triton_terminate(void);
void triton_process_events(void);

#ifdef USE_CORO
#define DEF_COROUTINE_STACK 64*1024
typedef void (*triton_coroutine_func)(void*);
long int triton_coroutine_create(int stack_size,triton_coroutine_func func,void *arg,int run);
void triton_coroutine_delete(long int id);
void triton_coroutine_wakeup(long int id);
void triton_coroutine_schedule();
int triton_coroutine_schedule_timeout(int msec);
#endif

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
