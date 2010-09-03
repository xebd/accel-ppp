#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "triton_p.h"

int thread_count = 4;
int max_events = 64;

static spinlock_t threads_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(threads);
static LIST_HEAD(sleep_threads);

static LIST_HEAD(ctx_queue);

static spinlock_t ctx_list_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(ctx_list);

struct triton_ctx_t *default_ctx;
static int terminate;

static mempool_t *ctx_pool;

void triton_thread_wakeup(struct _triton_thread_t *thread)
{
	pthread_kill(thread->thread, SIGUSR1);
}

static void* triton_thread(struct _triton_thread_t *thread)
{
	struct _triton_md_handler_t *h;
	struct _triton_timer_t *t;
	sigset_t set;
	int sig;
	uint64_t tt;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGQUIT);

	while(1){
		sigwait(&set, &sig);

cont:
		if (thread->ctx->need_close) {
			if (thread->ctx->ud->close)
				thread->ctx->ud->close(thread->ctx->ud);
			thread->ctx->need_close = 0;
		}

		while (1) {
			spin_lock(&thread->ctx->lock);
			if (!list_empty(&thread->ctx->pending_timers)) {
				t = list_entry(thread->ctx->pending_timers.next, typeof(*t), entry2);
				list_del(&t->entry2);
				t->pending = 0;
				spin_unlock(&thread->ctx->lock);
				read(t->fd, &tt, sizeof(tt));
				t->ud->expire(t->ud);
			}
			if (!list_empty(&thread->ctx->pending_handlers)) {
				h = list_entry(thread->ctx->pending_handlers.next, typeof(*h), entry2);
				list_del(&h->entry2);
				h->pending = 0;
				spin_unlock(&thread->ctx->lock);

				if (h->trig_epoll_events & (EPOLLIN | EPOLLERR | EPOLLHUP))
					if (h->ud->read)
						if (h->ud->read(h->ud))
							continue;
				if (h->trig_epoll_events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
					if (h->ud->write)
						if (h->ud->write(h->ud))
							continue;
				h->trig_epoll_events = 0;
				continue;
			}
			thread->ctx->thread = NULL;
			spin_unlock(&thread->ctx->lock);
			if (thread->ctx->need_free)
				mempool_free(thread->ctx);
			thread->ctx = NULL;
			break;
		}
	
		spin_lock(&threads_lock);
		if (!list_empty(&ctx_queue)) {
			thread->ctx = list_entry(ctx_queue.next, typeof(*thread->ctx), entry2);
			list_del(&thread->ctx->entry2);
			spin_unlock(&threads_lock);
			spin_lock(&thread->ctx->lock);
			thread->ctx->thread = thread;
			thread->ctx->queued = 0;
			spin_unlock(&thread->ctx->lock);
			goto cont;
		} else {
			if (!terminate)
				list_add(&thread->entry2, &sleep_threads);
			spin_unlock(&threads_lock);
			if (terminate)
				return NULL;
		}
	}
}

struct _triton_thread_t *create_thread()
{
	struct _triton_thread_t *thread = malloc(sizeof(*thread));
	if (!thread)
		return NULL;

	memset(thread, 0, sizeof(*thread));
	if (pthread_create(&thread->thread, NULL, (void*(*)(void*))triton_thread, thread)) {
		triton_log_error("pthread_create: %s", strerror(errno));
		return NULL;
	}

	return thread;
}

int triton_queue_ctx(struct _triton_ctx_t *ctx)
{
	if (ctx->thread || ctx->queued)
		return 0;

	spin_lock(&threads_lock);
	if (list_empty(&sleep_threads)) {
		list_add_tail(&ctx->entry2, &ctx_queue);
		spin_unlock(&threads_lock);
		ctx->queued = 1;
		return 0;
	}

	ctx->thread = list_entry(sleep_threads.next, typeof(*ctx->thread), entry2);
	ctx->thread->ctx = ctx;
	list_del(&ctx->thread->entry2);
	spin_unlock(&threads_lock);

	return 1;
}

void __export triton_register_ctx(struct triton_ctx_t *ud)
{
	struct _triton_ctx_t *ctx = mempool_alloc(ctx_pool);

	memset(ctx, 0, sizeof(*ctx));
	ctx->ud = ud;
	spinlock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->handlers);
	INIT_LIST_HEAD(&ctx->timers);
	INIT_LIST_HEAD(&ctx->pending_handlers);
	INIT_LIST_HEAD(&ctx->pending_timers);

	ud->tpd = ctx;

	spin_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry, &ctx_list);
	spin_unlock(&ctx_list_lock);
}

void __export triton_unregister_ctx(struct triton_ctx_t *ud)
{
	struct _triton_ctx_t *ctx = (struct _triton_ctx_t *)ud->tpd;

	if (!list_empty(&ctx->handlers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: handlers is not empty");
		abort();
	}
	if (!list_empty(&ctx->pending_handlers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: pending_handlers is not empty");
		abort();
	}
	if (!list_empty(&ctx->timers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: timers is not empty");
		abort();
	}
	if (!list_empty(&ctx->pending_timers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: pending_timers is not empty");
		abort();
	}

	ctx->need_free = 1;
	spin_lock(&ctx_list_lock);
	list_del(&ctx->entry);
	spin_unlock(&ctx_list_lock);
}

int __export triton_init(const char *conf_file)
{
	ctx_pool = mempool_create(sizeof(struct _triton_ctx_t));

	default_ctx = malloc(sizeof(*default_ctx));
	if (!default_ctx) {
		fprintf(stderr,"cann't allocate memory\n");
		return -1;
	}
	triton_register_ctx(default_ctx);	

	if (conf_load(conf_file))
		return -1;

	if (log_init())
		return -1;

	if (md_init())
		return -1;

	if (timer_init())
		return -1;
	
	return 0;
}

void __export triton_run()
{
	struct _triton_thread_t *t;
	int i;

	for(i = 0; i < thread_count; i++) {
		t = create_thread();
		if (!t)
			_exit(-1);

		list_add_tail(&t->entry, &threads);
		list_add_tail(&t->entry2, &sleep_threads);
	}

	md_run();
	timer_run();
}

void __export triton_terminate()
{
	struct _triton_ctx_t *ctx;
	struct _triton_thread_t *t;
	
	md_terminate();
	timer_terminate();
	
	spin_lock(&ctx_list_lock);
	list_for_each_entry(ctx, &ctx_list, entry) {
		spin_lock(&ctx->lock);
		ctx->need_close = 1;
		triton_queue_ctx(ctx);
		spin_unlock(&ctx->lock);
	}
	spin_unlock(&ctx_list_lock);

	spin_lock(&threads_lock);
	terminate = 1;
	spin_unlock(&threads_lock);
	
	list_for_each_entry(t, &threads, entry)
		triton_thread_wakeup(t);
	
	list_for_each_entry(t, &threads, entry)
		pthread_join(t->thread, NULL);
}

