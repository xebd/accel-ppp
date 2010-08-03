#ifndef TRITON_P_H
#define TRITON_P_H

#include "triton.h"
#include "list.h"

#include <stdarg.h>
#include <ucontext.h>

#define MAX_ARGS 32

struct option_t
{
	struct list_head entry;

	char *name;
	char *val;
};

struct md_handler_t
{
	struct list_head entry;

	int fd;
	int del;
	int timeout;
	int volatile in_handler;

	struct coroutine_t *coro;

	struct triton_md_handler_t *handler;
};

struct timer_t
{
	struct list_head entry;
	int del;
	struct triton_timer_t *timer;
};

struct timer_single_shot_t
{
	struct list_head entry;

	struct timeval expire_tv;
	int arg_cnt;
	void *args;
	triton_ss_func ss_func;
};

struct event_handler_t
{
	struct list_head entry;

	int arg_cnt;
	void *args;
	triton_event_func event_func;
};
struct event_t
{
	struct list_head entry;

	int ev_id;
	struct list_head handlers;
};

struct coroutine_t
{
	struct list_head entry;
	ucontext_t uc;
	struct timeval timeout;
	struct timeval time;
};


extern struct list_head components;
extern void md_run();
extern void md_terminate();
extern int timer_prepare(struct timeval *tv);
extern void timer_check(struct timeval *tv);
extern int coroutine_get_timeout(struct timeval *tv);
extern void coroutine_check_timeout(struct timeval *tv);
extern void event_init();
extern struct coroutine_t *current_coro;
void schedule(void);

//#define BROKEN_GCC

#ifdef BROKEN_GCC
#define dyn_call(func,arg_cnt,args)\
{\
	switch(arg_cnt)\
	{\
		case 0: \
		{\
			typedef void (*func0)(void);\
			((func0)func)();\
			break;\
		}\
		case 1: \
		{\
			typedef void (*func0)(long);\
			((func0)func)(*((long*)args+0));\
			break;\
		}\
		case 2: \
		{\
			typedef void (*func0)(long,long);\
			((func0)func)(*((long*)args+0),*((long*)args+1));\
			break;\
		}\
		case 3: \
		{\
			typedef void (*func0)(long,long,long);\
			((func0)func)(*((long*)args+0),*((long*)args+1),*((long*)args+2));\
			break;\
		}\
		case 4: \
		{\
			typedef void (*func0)(long,long,long,long);\
			((func0)func)(*((long*)args+0),*((long*)args+1),*((long*)args+2),*((long*)args+3));\
			break;\
		}\
	}\
}
#else
#define dyn_call(func,arg_cnt,args)\
{\
	int aaa=arg_cnt*sizeof(long);\
	asm("subl %2,%%esp; \n\
			 movl %%esp,%%edi;\n\
			 movl %0,%%esi;\n\
			 cld;\n\
			 rep movsl;\n\
			 call *%1;\n\
			 addl %2,%%esp\n"::"m" (args),"m" (func),"g" (aaa),"c"(arg_cnt):"%edi","%esi","%esp");\
}
#endif

#endif
