#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "triton_p.h"
#include "memdebug.h"

int thread_count = 1;
int max_events = 64;

static spinlock_t threads_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(threads);
static LIST_HEAD(sleep_threads);

static LIST_HEAD(ctx_queue);

static spinlock_t ctx_list_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(ctx_list);

struct triton_context_t *default_ctx;
static int terminate;

static mempool_t *ctx_pool;
static mempool_t *call_pool;

__export struct triton_stat_t triton_stat;

void triton_thread_wakeup(struct _triton_thread_t *thread)
{
	pthread_kill(thread->thread, SIGUSR1);
}

static void* triton_thread(struct _triton_thread_t *thread)
{
	sigset_t set;

	sigfillset(&set);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGBUS);
	pthread_sigmask(SIG_SETMASK, &set, NULL);

	sigdelset(&set, SIGUSR1);
	sigdelset(&set, SIGQUIT);

	while (1) {
		__sync_fetch_and_sub(&triton_stat.thread_active, 1);
		sigsuspend(&set);
		__sync_fetch_and_add(&triton_stat.thread_active, 1);

cont:
		if (thread->ctx->ud->before_switch)
			thread->ctx->ud->before_switch(thread->ctx->ud, thread->ctx->bf_arg);
		if (swapcontext(&thread->uctx, &thread->ctx->uctx))
			triton_log_error("swapcontext: %s\n", strerror(errno));
	
		if (thread->ctx->need_free)
			mempool_free(thread->ctx);
		thread->ctx = NULL;

		spin_lock(&threads_lock);
		if (!list_empty(&ctx_queue)) {
			thread->ctx = list_entry(ctx_queue.next, typeof(*thread->ctx), entry2);
			list_del(&thread->ctx->entry2);
			spin_unlock(&threads_lock);
			spin_lock(&thread->ctx->lock);
			thread->ctx->thread = thread;
			thread->ctx->queued = 0;
			spin_unlock(&thread->ctx->lock);
			__sync_fetch_and_sub(&triton_stat.context_pending, 1);
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

static void ctx_thread(struct _triton_context_t *ctx)
{
	struct _triton_md_handler_t *h;
	struct _triton_timer_t *t;
	struct _triton_ctx_call_t *call;
	uint64_t tt;
	ucontext_t *uctx;

	while (1) {
		uctx = &ctx->thread->uctx;
		if (ctx->need_close) {
			if (ctx->ud->close)
				ctx->ud->close(ctx->ud);
			ctx->need_close = 0;
		}

		while (1) {
			spin_lock(&ctx->lock);
			if (!list_empty(&ctx->pending_timers)) {
				t = list_entry(ctx->pending_timers.next, typeof(*t), entry2);
				list_del(&t->entry2);
				t->pending = 0;
				spin_unlock(&ctx->lock);
				read(t->fd, &tt, sizeof(tt));
				t->ud->expire(t->ud);
				continue;
			}
			if (!list_empty(&ctx->pending_handlers)) {
				h = list_entry(ctx->pending_handlers.next, typeof(*h), entry2);
				list_del(&h->entry2);
				h->pending = 0;
				spin_unlock(&ctx->lock);
				if (h->trig_epoll_events & (EPOLLIN | EPOLLERR | EPOLLHUP))
					if (h->ud && h->ud->read)
						h->ud->read(h->ud);
				if (h->trig_epoll_events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
					if (h->ud && h->ud->write)
						h->ud->write(h->ud);
				h->trig_epoll_events = 0;
				continue;
			}
			if (!list_empty(&ctx->pending_calls)) {
				call = list_entry(ctx->pending_calls.next, typeof(*call), entry);
				list_del(&call->entry);
				spin_unlock(&ctx->lock);
				call->func(call->arg);
				mempool_free(call);
			}
			ctx->thread = NULL;
			spin_unlock(&ctx->lock);
			
			if (swapcontext(&ctx->uctx, uctx))
				triton_log_error("swapcontext: %s\n", strerror(errno));
		}
	}
}

struct _triton_thread_t *create_thread()
{
	struct _triton_thread_t *thread = _malloc(sizeof(*thread));
	if (!thread)
		return NULL;

	memset(thread, 0, sizeof(*thread));
	if (pthread_create(&thread->thread, NULL, (void*(*)(void*))triton_thread, thread)) {
		triton_log_error("pthread_create: %s", strerror(errno));
		return NULL;
	}

	triton_stat.thread_count++;
	triton_stat.thread_active++;

	return thread;
}

int triton_queue_ctx(struct _triton_context_t *ctx)
{
	if (ctx->thread || ctx->queued || ctx->sleeping)
		return 0;

	spin_lock(&threads_lock);
	if (list_empty(&sleep_threads)) {
		list_add_tail(&ctx->entry2, &ctx_queue);
		spin_unlock(&threads_lock);
		ctx->queued = 1;
		__sync_fetch_and_add(&triton_stat.context_pending, 1);
		return 0;
	}

	ctx->thread = list_entry(sleep_threads.next, typeof(*ctx->thread), entry2);
	ctx->thread->ctx = ctx;
	list_del(&ctx->thread->entry2);
	spin_unlock(&threads_lock);

	return 1;
}

int __export triton_context_register(struct triton_context_t *ud, void *bf_arg)
{
	struct _triton_context_t *ctx = mempool_alloc(ctx_pool);

	if (!ctx)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ud = ud;
	ctx->bf_arg = bf_arg;
	spinlock_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->handlers);
	INIT_LIST_HEAD(&ctx->timers);
	INIT_LIST_HEAD(&ctx->pending_handlers);
	INIT_LIST_HEAD(&ctx->pending_timers);
	INIT_LIST_HEAD(&ctx->pending_calls);

	if (getcontext(&ctx->uctx)) {
		triton_log_error("getcontext: %s\n", strerror(errno));
		_free(ctx);
		return -1;
	}

	ctx->uctx.uc_stack.ss_size = CTX_STACK_SIZE;
	ctx->uctx.uc_stack.ss_sp = _malloc(CTX_STACK_SIZE);
	if (!ctx->uctx.uc_stack.ss_sp) {
		triton_log_error("out of memory\n");
		_free(ctx);
		return -1;
	}
	makecontext(&ctx->uctx, (void (*)())ctx_thread, 1, ctx);

	ud->tpd = ctx;

	spin_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry, &ctx_list);
	spin_unlock(&ctx_list_lock);

	__sync_fetch_and_add(&triton_stat.context_count, 1);

	return 0;
}

void __export triton_context_unregister(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	struct _triton_ctx_call_t *call;

	while (!list_empty(&ctx->pending_calls)) {
		call = list_entry(ctx->pending_calls.next, typeof(*call), entry);
		list_del(&call->entry);
		mempool_free(call);
	}

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
		{
			struct _triton_timer_t *t;
			while(!list_empty(&ctx->timers)) {
				t = list_entry(ctx->timers.next, typeof(*t), entry);
				t->ud->expire(t->ud);
				list_del(&t->entry);
			}
		}
		abort();
	}
	if (!list_empty(&ctx->pending_timers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: pending_timers is not empty");
		abort();
	}

	_free(ctx->uctx.uc_stack.ss_sp);

	ctx->need_free = 1;
	spin_lock(&ctx_list_lock);
	list_del(&ctx->entry);
	spin_unlock(&ctx_list_lock);
	
	__sync_fetch_and_sub(&triton_stat.context_count, 1);
}
void __export triton_context_schedule(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	ucontext_t *uctx = &ctx->thread->uctx;

	spin_lock(&ctx->lock);
	ctx->sleeping = 1;
	ctx->thread = NULL;
	spin_unlock(&ctx->lock);

	if (swapcontext(&ctx->uctx, uctx))
		triton_log_error("swaswpntext: %s\n", strerror(errno));
	
	__sync_fetch_and_add(&triton_stat.context_sleeping, 1);
}

void __export triton_context_wakeup(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	int r;

	spin_lock(&ctx->lock);
	ctx->sleeping = 0;
	r = triton_queue_ctx(ctx);
	spin_unlock(&ctx->lock);

	if (r)
		triton_thread_wakeup(ctx->thread);
	
	__sync_fetch_and_sub(&triton_stat.context_sleeping, 1);
}

int __export triton_context_call(struct triton_context_t *ud, void (*func)(void *), void *arg)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	struct _triton_ctx_call_t *call = mempool_alloc(call_pool);
	int r;

	if (!call)
		return -1;
	
	call->func = func;
	call->arg = arg;

	spin_lock(&ctx->lock);
	list_add_tail(&call->entry, &ctx->pending_calls);
	r = triton_queue_ctx(ctx);
	spin_unlock(&ctx->lock);

	if (r)
		triton_thread_wakeup(ctx->thread);

	return 0;
}

int __export triton_init(const char *conf_file)
{
	ctx_pool = mempool_create(sizeof(struct _triton_context_t));
	call_pool = mempool_create(sizeof(struct _triton_ctx_call_t));

	default_ctx = _malloc(sizeof(*default_ctx));
	if (!default_ctx) {
		fprintf(stderr,"cann't allocate memory\n");
		return -1;
	}
	triton_context_register(default_ctx, NULL);	

	if (conf_load(conf_file))
		return -1;

	if (log_init())
		return -1;

	if (md_init())
		return -1;

	if (timer_init())
		return -1;

	if (event_init())
		return -1;

	return 0;
}

int __export triton_load_modules(const char *mod_sect)
{
	if (load_modules(mod_sect))
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
	struct _triton_context_t *ctx;
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

