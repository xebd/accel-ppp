#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "triton_p.h"

static pthread_thread_t timer_thr;

static pthread_mutex_t timers_lock=PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(timers);

static timespec expire_ts;
static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;

static void tv_add(struct timeval *tv,int msec);


void timer_init(void)
{
}

void timer_run(void)
{
	pthread_create(&timer_thr,NULL,timer_thread,NULL);
}

void timer_terminate(void)
{
	pthread_cancel(&timer_thr);
	pthread_join(&timer_thr);
}

void *timer_thread(void *arg)
{
	struct triton_timer_t *t;
	struct timeval tv;

	pthread_mutex_lock(&timers_lock);
	while(1)
	{
		if (expire_ts.tv_sec)
			pthread_cond_timedwait(&cond,&timers_lock,&expire_ts);
		else
			pthread_cond_wait(&cond,&timers_lock);

		gettimeofday(&tv,NULL);
		while(1)
		{
			if (list_empty(&timers))
			{
				expire_ts.tv_sec=0;
				break;
			}
			t=list_entry(timers.next,typeof(*t),entry);
			if (t->expire_tv.tv_sec>tv.tv_sec || (t->expire_tv.tv_sec==tv.tv_sec && t->expire_tv.tv_usec>=tv.tv_usec))
			{
				expire_ts.tv_sec=t->expire_tv.tv_sec;
				expire_ts.tv_nsec=t->expire_tv.tv_usec*1000;
				break;
			}
			list_del(&t->entry3);
			pthread_mutex_lock(&t->ctx->lock);
			t->pending=1;
			list_add_tail(&t->entry2,&t->ctx->pending_timers);
			triton_queue_ctx(&t->ctx);
			pthread_mutex_unlock(&t->ctx->lock);
		}
	}
}

void triton_timer_add(struct triton_timer_t *t)
{
	struct triton_timer_t *t1;
	pthread_mutex_lock(&timers_lock);
	list_for_each_entry(t1,&timers,entry3)
	{
		if (t->expire_tv.tv_sec<t1.expire_tv.tv_sec || (t->expire_tv.tv_sec==t1->expire_tv.tv_sec && t->expire_tv.tv_usec<t1->expire_tv.tv_usec))
			break;
	}
	list_add_tail(&t->entry3,&t1->entry3);
	pthread_mutex_unlock(&timers_lock);
}
void triton_timer_del(struct triton_timer_t *t)
{
	pthread_mutex_lock(&timers_lock);
	pthread_mutex_lock(&t->ctx->lock);
	if (t->pending)
		list_del(&t->entry2);
	else
	{
		list_del(&t->entry3);
		if (t->expire_tv.tv_sec<expire_ts.tv_sec || (t->expire_tv.tv_sec==expire_ts.tv_sec && t->expire_tv.tv_usec<expire_ts.tv_nsec/1000))
			pthread_cond_signal(&cond);
	}
	pthread_mutex_unlock(&t->ctx->lock);
	pthread_mutex_unlock(&timers_lock);
}
