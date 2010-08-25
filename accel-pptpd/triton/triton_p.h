#ifndef TRITON_P_H
#define TRITON_P_H

#include "triton.h"
#include "list.h"

#include <stdarg.h>

#define MAX_ARGS 32

struct option_t
{
	struct list_head entry;

	char *name;
	char *val;
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

extern void md_run();
extern void md_terminate();
extern void timer_run();
extern void timer_terminate();
extern struct triton_ctx_t *default_ctx;

#endif
