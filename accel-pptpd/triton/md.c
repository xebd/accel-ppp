#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "triton_p.h"

extern int max_events;

static int epoll_fd;
static struct epoll_event *epoll_events;

static pthread_t md_thr;
static void *md_thread(void *arg);

int md_init(void)
{
	epoll_fd = epoll_create(1);
	if (epoll_fd < 0) {
		perror("md:epoll_create");
		return -1;
	}

	epoll_events = malloc(max_events * sizeof(struct epoll_event));
	if (!epoll_events) {
		fprintf(stderr,"md:cann't allocate memory\n");
		return -1;
	}

	return 0;
}
void md_run(void)
{
	if (pthread_create(&md_thr, NULL, md_thread, NULL)) {
		triton_log_error("md:pthread_create: %s", strerror(errno));
		_exit(-1);
	}
}

void md_terminate(void)
{
	pthread_cancel(md_thr);	
	pthread_join(md_thr, NULL);	
}

static void *md_thread(void *arg)
{
	int i,n,r;
	struct triton_md_handler_t *h;

	while(1) {
		n = epoll_wait(epoll_fd, epoll_events, max_events, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			triton_log_error("md:epoll_wait: %s", strerror(errno));
			_exit(-1);
		}
		
		for(i = 0; i < n; i++) {
			h = (struct triton_md_handler_t *)epoll_events[i].data.ptr;
			spin_lock(&h->ctx->lock);
			h->trig_epoll_events = epoll_events[i].events;
			list_add_tail(&h->entry2, &h->ctx->pending_handlers);
			h->pending = 1;
			r=triton_queue_ctx(h->ctx);
			spin_unlock(&h->ctx->lock);
			if (r)
				triton_thread_wakeup(h->ctx->thread);
		}
	}

	return NULL;
}

void triton_md_register_handler(struct triton_md_handler_t *h)
{
	h->epoll_event.data.ptr = h;
	if (!h->ctx)
		h->ctx = default_ctx;
	spin_lock(&h->ctx->lock);
	list_add_tail(&h->entry, &h->ctx->handlers);
	spin_unlock(&h->ctx->lock);
}
void triton_md_unregister_handler(struct triton_md_handler_t *h)
{
	spin_lock(&h->ctx->lock);
	list_del(&h->entry);
	if (h->pending)
		list_del(&h->entry2);
	spin_unlock(&h->ctx->lock);
}
int triton_md_enable_handler(struct triton_md_handler_t *h, int mode)
{
	int r;
	int events = h->epoll_event.events;

	if (mode & MD_MODE_READ)
		h->epoll_event.events |= EPOLLIN;
	if (mode & MD_MODE_WRITE)
		h->epoll_event.events |= EPOLLOUT;
	
	h->epoll_event.events |= EPOLLET;
	
	if (events)
		r = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, h->fd, &h->epoll_event);
	else
		r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, h->fd, &h->epoll_event);

	if (r)
		triton_log_error("md:epoll_ctl: %s",strerror(errno));

	return r;
}
int triton_md_disable_handler(struct triton_md_handler_t *h,int mode)
{
	int r=0;

	if (!h->epoll_event.events)
		return -1;
	
	if (mode & MD_MODE_READ)
		h->epoll_event.events &= ~EPOLLIN;
	if (mode & MD_MODE_WRITE)
		h->epoll_event.events &= ~EPOLLOUT;

	if (h->epoll_event.events & (EPOLLIN | EPOLLOUT))
		r = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, h->fd, &h->epoll_event);
	else {
		h->epoll_event.events = 0;
		r = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, h->fd, NULL);
	}

	if (r)
		triton_log_error("md:epoll_ctl: %s",strerror(errno));

	return r;
}

