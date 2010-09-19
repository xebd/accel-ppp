#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "triton_p.h"

#include "memdebug.h"

extern int max_events;
static int epoll_fd;
static struct epoll_event *epoll_events;

static pthread_t timer_thr;
static void *timer_thread(void *arg);

static mempool_t *timer_pool;

int timer_init(void)
{
	epoll_fd = epoll_create(1);
	if (epoll_fd < 0) {
		perror("timer:epoll_create");
		return -1;
	}

	epoll_events = _malloc(max_events * sizeof(struct epoll_event));
	if (!epoll_events) {
		fprintf(stderr,"timer:cann't allocate memory\n");
		return -1;
	}

	timer_pool = mempool_create(sizeof(struct _triton_timer_t));

	return 0;
}

void timer_run(void)
{
	if (pthread_create(&timer_thr, NULL, timer_thread, NULL)) {
		triton_log_error("timer:pthread_create: %s",strerror(errno));
		_exit(-1);
	}
}

void timer_terminate(void)
{
	pthread_cancel(timer_thr);
	pthread_join(timer_thr, NULL);
}

void *timer_thread(void *arg)
{
	int i,n,r;
	struct _triton_timer_t *t;
	sigset_t set;

	sigfillset(&set);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	sigemptyset(&set);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGSEGV);
	sigaddset(&set, SIGFPE);
	sigaddset(&set, SIGILL);
	sigaddset(&set, SIGBUS);
	pthread_sigmask(SIG_UNBLOCK, &set, NULL);

	while(1) {
		n = epoll_wait(epoll_fd, epoll_events, max_events, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			triton_log_error("timer:epoll_wait: %s", strerror(errno));
			_exit(-1);
		}
		
		for(i = 0; i < n; i++) {
			t = (struct _triton_timer_t *)epoll_events[i].data.ptr;
			spin_lock(&t->ctx->lock);
			if (t->ud) {
				if (!t->pending) {
					list_add_tail(&t->entry2, &t->ctx->pending_timers);
					t->pending = 1;
					r = triton_queue_ctx(t->ctx);
				} else
					r = 0;
			} else
				r = 0;
			spin_unlock(&t->ctx->lock);
			if (r)
				triton_thread_wakeup(t->ctx->thread);
		}
	}

	return NULL;
}

int __export triton_timer_add(struct triton_context_t *ctx, struct triton_timer_t *ud, int abs_time)
{
	struct _triton_timer_t *t = mempool_alloc(timer_pool);

	memset(t, 0, sizeof(*t));
	t->ud = ud;
	t->epoll_event.data.ptr = t;
	t->epoll_event.events = EPOLLIN | EPOLLET;
	if (ctx)
		t->ctx = (struct _triton_context_t *)ctx->tpd;
	else
		t->ctx = (struct _triton_context_t *)default_ctx->tpd;
	t->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (t->fd < 0) {
		triton_log_error("timer:timerfd_create: %s" ,strerror(errno));
		mempool_free(t);
		return -1;
	}
	
	ud->tpd = t;

	if (triton_timer_mod(ud, abs_time)) {
		close(t->fd);
		mempool_free(t);
		return -1;
	}
	
	spin_lock(&t->ctx->lock);
	list_add_tail(&t->entry, &t->ctx->timers);
	spin_unlock(&t->ctx->lock);
	
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, t->fd, &t->epoll_event)) {
		triton_log_error("timer:epoll_ctl: %s", strerror(errno));
		spin_lock(&t->ctx->lock);
		t->ud = NULL;
		list_del(&t->entry);
		spin_unlock(&t->ctx->lock);
		close(t->fd);
		mempool_free(t);
		ud->tpd = NULL;
		return -1;
	}

	__sync_fetch_and_add(&triton_stat.timer_count, 1);
	
	return 0;
}
int __export triton_timer_mod(struct triton_timer_t *ud,int abs_time)
{
	struct _triton_timer_t *t = (struct _triton_timer_t *)ud->tpd;
	struct itimerspec ts =	{
		.it_value.tv_sec = ud->expire_tv.tv_sec,
		.it_value.tv_nsec = ud->expire_tv.tv_usec * 1000,
		.it_interval.tv_sec = ud->period / 1000,
		.it_interval.tv_nsec = (ud->period % 1000) * 1000,
	};

	if (ud->expire_tv.tv_sec == 0 && ud->expire_tv.tv_usec == 0)
		ts.it_value = ts.it_interval;

	if (timerfd_settime(t->fd, abs_time ? TFD_TIMER_ABSTIME : 0, &ts, NULL)) {
		triton_log_error("timer:timerfd_settime: %s", strerror(errno));
		return -1;
	}

	return 0;
}
void __export triton_timer_del(struct triton_timer_t *ud)
{
	struct _triton_timer_t *t = (struct _triton_timer_t *)ud->tpd;
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, t->fd, &t->epoll_event);
	close(t->fd);
	spin_lock(&t->ctx->lock);
	list_del(&t->entry);
	if (t->pending)
		list_del(&t->entry2);
	t->ud = NULL;
	spin_unlock(&t->ctx->lock);
	sched_yield();
	mempool_free(t);
	ud->tpd = NULL;
	
	__sync_fetch_and_sub(&triton_stat.timer_count, 1);
}

