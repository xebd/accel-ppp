#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "triton_p.h"

int thread_count = 64;
int max_events = 64;

static spinlock_t threads_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(threads);
static LIST_HEAD(sleep_threads);

static LIST_HEAD(ctx_queue);

static spinlock_t ctx_list_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(ctx_list);

struct triton_ctx_t *default_ctx;
static int terminate;

void triton_thread_wakeup(struct triton_thread_t *thread)
{
	pthread_kill(thread->thread, SIGUSR1);
}

static void* triton_thread(struct triton_thread_t *thread)
{
	struct triton_md_handler_t *h;
	struct triton_timer_t *t;
	sigset_t set;
	int sig;

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGQUIT);

	while(1){
		sigwait(&set, &sig);

cont:
		if (thread->ctx->need_close) {
			thread->ctx->close(thread->ctx);
			thread->ctx->need_close = 0;
		}

		while (1) {
			spin_lock(&thread->ctx->lock);
			if (!list_empty(&thread->ctx->pending_timers)) {
				t = list_entry(thread->ctx->pending_timers.next, typeof(*t), entry2);
				list_del(&t->entry2);
				spin_unlock(&thread->ctx->lock);
				if (t->expire(t))
					continue;
			}
			if (!list_empty(&thread->ctx->pending_handlers)) {
				h = list_entry(thread->ctx->pending_handlers.next, typeof(*h), entry2);
				list_del(&h->entry2);
				h->pending = 0;
				spin_unlock(&thread->ctx->lock);

				if (h->trig_epoll_events & (EPOLLIN | EPOLLERR | EPOLLHUP))
					if (h->read)
						if (h->read(h))
							continue;
				if (h->trig_epoll_events & EPOLLOUT)
					if (h->write)
						if (h->write(h))
							continue;
				h->trig_epoll_events = 0;
				continue;
			}
			thread->ctx->thread = NULL;
			spin_unlock(&thread->ctx->lock);
			if (thread->ctx->need_free)
				thread->ctx->free(thread->ctx);
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

struct triton_thread_t *create_thread()
{
	struct triton_thread_t *thread = malloc(sizeof(*thread));
	if (!thread)
		return NULL;

	memset(thread, 0, sizeof(*thread));
	if (pthread_create(&thread->thread, NULL, (void*(*)(void*))triton_thread, thread)) {
		triton_log_error("pthread_create: %s", strerror(errno));
		return NULL;
	}

	return thread;
}

int triton_queue_ctx(struct triton_ctx_t *ctx)
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
	list_del(&ctx->thread->entry2);
	spin_unlock(&threads_lock);

	return 1;
}

void triton_register_ctx(struct triton_ctx_t *ctx)
{
	spinlock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->handlers);
	INIT_LIST_HEAD(&ctx->timers);
	INIT_LIST_HEAD(&ctx->pending_handlers);
	INIT_LIST_HEAD(&ctx->pending_timers);

	spin_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry, &ctx_list);
	spin_unlock(&ctx_list_lock);
}

void triton_unregister_ctx(struct triton_ctx_t *ctx)
{
	ctx->need_free = 1;
	spin_lock(&ctx_list_lock);
	list_del(&ctx->entry);
	spin_unlock(&ctx_list_lock);
}

int triton_init(const char *conf_file)
{
	default_ctx=malloc(sizeof(*default_ctx));
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

void triton_run()
{
	struct triton_thread_t *t;
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

void triton_terminate()
{
	struct triton_ctx_t *ctx;
	struct triton_thread_t *t;
	
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

