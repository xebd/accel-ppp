#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <string.h>

#include "triton_p.h"

static pthread_thread_t timer_thr;
static void *timer_thread(void *arg);

static spinlock_t timers_lock=SPINLOCK_INITIALIZER;
static LIST_HEAD(timers);

extern int max_events;
static epoll_fd;
static struct epoll_event *epoll_events;

static void tv_add(struct timeval *tv,int msec);

void timer_init(void)
{
	epoll_fd=epoll_create(1);
	if (epoll_fd<0)
	{
		perror("epoll_create");
		return -1;
	}

	epoll_events=malloc(max_events * sizeof(struct epoll_event));
	if (!epoll_events)
	{
		fprintf(stderr,"cann't allocate memory\n");
		return -1;
	}
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
	int i,n,r;
	struct triton_timer_t *t;
	
	n=epoll_wait(epoll_fd,epoll_events,MAX_EVENTS,-1);
	if (n<0)
	{
		if (errno!=EINTR)
		perror("epoll_wait");
		continue;
	}
	if (n==0)
		return;
	
	for(i=0; i<n; i++)
	{
		t=(struct triton_md_handler_t*)epoll_events[i].data.ptr;
		spin_lock(&t->ctx->lock);
		list_add_tail(&t->entry2,&t->ctx->pending_timers);
		t->pending=1;
		r=triton_queue_ctx(t->ctx);
		spin_unlock(&t->ctx->lock);
		if (r)
			triton_thread_wakeup(ctx->thread);
	}
}

int triton_timer_add(struct triton_timer_t *t)
{
	t->epoll_event.data.ptr=t;
	t->epoll_event.events=EPOLLIN|EPOLLET;
	if (!t->ctx)
		t->ctx=default_ctx;
	t->fd=timerfd_create(CLOCK_MONOTONIC,0);
	if (t->fd<0)
	{
		fprintf(stderr,"timer: timerfd_create failed: %s\n",strerror(errno));
		return -1;
	}
	
	if (triton_timer_mod(t))
	{
		close(t->fd);
		return -1;
	}
	
	spin_lock(&t->ctx->lock);
	list_add_tail(&t->entry,&t->ctx->timers);
	spin_unlock(&t->ctx->lock);
	
	if (epoll_ctl(epoll_fd,EPOLL_CTL_ADD,t->fd,&t->epoll_event))
	{
		fprintf(stderr,"timer: epoll_ctl failed: %s\n",strerror(errno));
		spin_lock(&t->ctx->lock);
		list_del(&t->entry);
		spin_unlock(&t->ctx->lock);
		close(t->fd);
		return -1;
	}

	return 0;
}
int triton_timer_mod(struct triton_timer_t *t)
{
	int flags;

	struct itimerspec ts=
	{
		.it_value.tv_sec=t->expire_tv.tv_sec,
		.it_value.tv_nsec=t->expire_tv.tv_usec*1000,
		.it_interval.tv_sec=t->period/1000,
		.it_interval.tv_nsec=t->period%1000*1000,
	};

	if (t->expire_tv.tv_sec==0 && t->expire_tv.tv_usec==0)
	{
		ts.it_value=ts.interval;
		flags=0;
	}else 
		flags=TFD_TIMER_ABSTIME;

	if (timerfd_settime(t->fd,flags,&ts,NULL))
	{
		fprintf(stderr,"timer: timerfd_settime failed: %s\n",strerror(errno));
		return -1;
	}

	return 0;
}
void triton_timer_del(struct triton_timer_t *t)
{
	epoll_ctl(epoll_fd,EPOLL_CTL_DEL,t->fd,&t->epoll_event);
	close(t->fd);
	spin_lock(&t->ctx->lock);
	list_del(&t->entry);
	if (t->pending)
		list_del(&t->entry2);
	spin_unlock(&t->ctx->lock);
}

