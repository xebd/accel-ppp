#ifndef TRITON_P_H
#define TRITON_P_H

#include "triton.h"
#include "list.h"

int log_init(void);
int md_init();
void md_run();
void md_terminate();
int timer_init();
void timer_run();
void timer_terminate();
struct triton_ctx_t *default_ctx;
int triton_queue_ctx(struct triton_ctx_t*);
void triton_thread_wakeup(struct triton_thread_t*);
int conf_load(const char *fname);
void triton_log_error(const char *fmt,...);
void triton_log_debug(const char *fmt,...);

#endif
