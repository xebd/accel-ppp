#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>

#include "triton_p.h"

int max_events=128;

static int epoll_fd;
static struct epoll_event *epoll_events;

static pthread_t md_thr;
static void* md_thread(void *arg)

int md_init()
{
	epoll_fd=epoll_create(0);
	if (epoll_fd<0)
	{
		perror("epoll_create");
		return -1;
	}

	epoll_events=malloc(MAX_EVENTS * sizeof(struct epoll_event));
	if (!epoll_events)
	{
		fprintf(stderr,"cann't allocate memory\n");
		return -1;
	}

	default_ctx=malloc(sizeof(*default_ctx));
	if (!default_ctx)
	{
		fprintf(stderr,"cann't allocate memory\n");
		return -1;
	}

	triton_register_ctx(default_ctx);	

	return 0;
}
void md_run()
{
	pthread_create(&md_thr,md_thread,NULL);
}

void md_terminate()
{
	pthread_join(&md_thr);	
}

static void* md_thread(void *arg)
{
	int max_fd=0,t,r;
	struct triton_md_handler_t *h;
	struct timeval tv1,tv2,twait0;
	struct list_head *p1,*p2;
	int timeout,i,n;
	
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
		h=(struct triton_md_handler_t*)epoll_events[i].data.ptr;
		spin_lock(&h->ctx->lock);
		h->trig_epoll_events=epoll_events[i].events;
		list_add_tail(&h->entry2,&h->ctx->pending_handlers);
		h->pending=1;
		r=triton_queue_ctx(h->ctx);
		spin_unlock(&h->ctx->lock);
		if (r)
			triton_thread_wakeup(ctx->thread);
	}
}

void triton_md_register_handler(struct triton_md_handler_t *h)
{
	h->epoll_event.data.ptr=h;
	if (!h->ctx)
		h->ctx=default_ctx;
	pthread_mutex_lock(&h->ctx->lock);
	list_add_tail(&h->entry,&h->ctx->handlers);
	pthread_mutex_unlock(&h->ctx->lock);
}
void triton_md_unregister_handler(struct triton_md_handler_t *h)
{
	pthread_mutex_lock(&h->ctx->lock);
	list_del(&h->entry);
	if (h->pending)
		list_del(&h->entry2);
	pthread_lock_unlock(&h->ctx->lock);
}
int triton_md_enable_handler(struct triton_md_handler_t *h, int mode)
{
	int r;
	int events=h->epoll_event.events;

	if (mode&MD_MODE_READ)
		h->epoll_event.events|=EPOLLIN;
	if (mode&MD_MODE_WRITE)
		h->epoll_event.events|=EPOLLOUT;
	
	h->epoll_event.events|=EPOLLET;
	
	if (events)
		r=epoll_ctl(epoll_fd,EPOLL_CTL_MOD,h->fd,&h->epoll_event);
	else
		r=epoll_ctl(epoll_fd,EPOLL_CTL_ADD,h->fd,&h->epoll_event);
	
	return r;
}
int triton_md_disable_handler(struct triton_md_handler_t *h,int mode)
{
	if (h->epoll_events.events)
		return -1;
	
	if (mode&MD_MODE_READ)
		h->epoll_event.events&=~EPOLLIN;
	if (mode&MD_MODE_WRITE)
		h->epoll_event.events&=~EPOLLOUT;

	if (h->epoll_event.events&(EPOLLIN|EPOLLOUT))
		r=epoll_ctl(epoll_fd,EPOLL_CTL_MOD,h->fd,&h->epoll_event);
	else
	{
		h->epoll_event.events=0;
		r=epoll_ctl(epoll_fd,EPOLL_CTL_DEL,h->fd,NULL);
	}

	return r;
}

