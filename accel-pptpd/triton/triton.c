#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "triton_p.h"
#include "memdebug.h"

int thread_count = 2;
int max_events = 64;

static spinlock_t threads_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(threads);
static LIST_HEAD(sleep_threads);

static LIST_HEAD(ctx_queue);

static spinlock_t ctx_list_lock = SPINLOCK_INITIALIZER;
static LIST_HEAD(ctx_list);

static int terminate;
static int need_terminate;

static mempool_t *ctx_pool;
static mempool_t *call_pool;
static mempool_t *ctx_stack_pool;

__export struct triton_stat_t triton_stat;

#define log_debug2(fmt, ...)

void triton_thread_wakeup(struct _triton_thread_t *thread)
{
	log_debug2("wake up thread %p\n", thread);
	pthread_kill(thread->thread, SIGUSR1);
}

static void* triton_thread(struct _triton_thread_t *thread)
{
	sigset_t set;
	int sig;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGQUIT);

	while (1) {
		spin_lock(&threads_lock);
		if (!list_empty(&ctx_queue)) {
			thread->ctx = list_entry(ctx_queue.next, typeof(*thread->ctx), entry2);
			log_debug2("thread: %p: dequeued ctx %p\n", thread, thread->ctx);
			list_del(&thread->ctx->entry2);
			spin_unlock(&threads_lock);
			spin_lock(&thread->ctx->lock);
			thread->ctx->thread = thread;
			thread->ctx->queued = 0;
			spin_unlock(&thread->ctx->lock);
			__sync_sub_and_fetch(&triton_stat.context_pending, 1);
		} else {
			log_debug2("thread: %p: sleeping\n", thread);
			if (!terminate)
				list_add(&thread->entry2, &sleep_threads);
			spin_unlock(&threads_lock);
			if (terminate)
				return NULL;

			__sync_sub_and_fetch(&triton_stat.thread_active, 1);
			//printf("thread %p: enter sigwait\n", thread);
			sigwait(&set, &sig);
			//printf("thread %p: exit sigwait\n", thread);
			__sync_add_and_fetch(&triton_stat.thread_active, 1);

			if (!thread->ctx)
				continue;
		}

cont:
		log_debug2("thread %p: ctx=%p %p\n", thread, thread->ctx, thread->ctx ? thread->ctx->thread : NULL);
		if (thread->ctx->ud->before_switch)
			thread->ctx->ud->before_switch(thread->ctx->ud, thread->ctx->bf_arg);

		log_debug2("thread %p: switch to %p\n", thread, thread->ctx);
		while (1) {	
			if (swapcontext(&thread->uctx, &thread->ctx->uctx)) {
				if (errno == EINTR)
					continue;
				triton_log_error("swapcontext: %s\n", strerror(errno));
			} else
				break;
		}
		log_debug2("thread %p: switch from %p %p\n", thread, thread->ctx, thread->ctx->thread);

		if (thread->ctx->thread) {
			spin_lock(&thread->ctx->lock);
			if (thread->ctx->pending) {
				spin_unlock(&thread->ctx->lock);
				goto cont;
			}
			thread->ctx->thread = NULL;
			spin_unlock(&thread->ctx->lock);

			if (thread->ctx->need_free) {
				log_debug2("- context %p removed\n", thread->ctx);
				spin_lock(&thread->ctx->lock);
				spin_unlock(&thread->ctx->lock);
				mempool_free(thread->ctx->uctx.uc_stack.ss_sp);
				mempool_free(thread->ctx);
			}
		}

		thread->ctx = NULL;
	}
}

static void ctx_thread(struct _triton_context_t *ctx)
{
	struct _triton_md_handler_t *h;
	struct _triton_timer_t *t;
	struct _triton_ctx_call_t *call;
	uint64_t tt;

	while (1) {
		log_debug2("ctx %p %p: enter\n", ctx, ctx->thread);
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
				__sync_sub_and_fetch(&triton_stat.timer_pending, 1);
				read(t->fd, &tt, sizeof(tt));
				t->ud->expire(t->ud);
				continue;
			}
			if (!list_empty(&ctx->pending_handlers)) {
				h = list_entry(ctx->pending_handlers.next, typeof(*h), entry2);
				list_del(&h->entry2);
				h->pending = 0;
				spin_unlock(&ctx->lock);
				__sync_sub_and_fetch(&triton_stat.md_handler_pending, 1);
				if (h->trig_epoll_events & (EPOLLIN | EPOLLERR | EPOLLHUP))
					if (h->ud && h->ud->read)
						if (h->ud->read(h->ud))
							continue;
				if (h->trig_epoll_events & (EPOLLOUT | EPOLLERR | EPOLLHUP))
					if (h->ud && h->ud->write)
						if (h->ud->write(h->ud))
							continue;
				h->trig_epoll_events = 0;
				continue;
			}
			if (!list_empty(&ctx->pending_calls)) {
				call = list_entry(ctx->pending_calls.next, typeof(*call), entry);
				list_del(&call->entry);
				spin_unlock(&ctx->lock);
				call->func(call->arg);
				mempool_free(call);
				continue;
			}
			ctx->pending = 0;
			spin_unlock(&ctx->lock);
			break;	
		}

		log_debug2("ctx %p %p: exit\n", ctx, ctx->thread);
		while (1) {
			if (swapcontext(&ctx->uctx, &ctx->thread->uctx)) {
				if (errno == EINTR)
					continue;
				triton_log_error("swapcontext: %s\n", strerror(errno));
			} else
				break;
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

	__sync_add_and_fetch(&triton_stat.thread_count, 1);
	__sync_add_and_fetch(&triton_stat.thread_active, 1);

	return thread;
}

int triton_queue_ctx(struct _triton_context_t *ctx)
{
	ctx->pending = 1;
	if (ctx->thread || ctx->queued || ctx->sleeping)
		return 0;

	spin_lock(&threads_lock);
	if (list_empty(&sleep_threads)) {
		if (ctx->priority)
			list_add(&ctx->entry2, &ctx_queue);
		else
			list_add_tail(&ctx->entry2, &ctx_queue);
		spin_unlock(&threads_lock);
		ctx->queued = 1;
		log_debug2("ctx %p: queued\n", ctx);
		__sync_add_and_fetch(&triton_stat.context_pending, 1);
		return 0;
	}

	ctx->thread = list_entry(sleep_threads.next, typeof(*ctx->thread), entry2);
	ctx->thread->ctx = ctx;
	log_debug2("ctx %p: assigned to thread %p\n", ctx, ctx->thread);
	list_del(&ctx->thread->entry2);
	spin_unlock(&threads_lock);

	return 1;
}

int __export triton_context_register(struct triton_context_t *ud, void *bf_arg)
{
	struct _triton_context_t *ctx = mempool_alloc(ctx_pool);

	log_debug2("ctx %p: register\n", ctx);
	if (!ctx)
		return -1;

	memset(ctx, 0, sizeof(*ctx));
	ctx->ud = ud;
	ctx->bf_arg = bf_arg;
	ctx->sleeping = 1;
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
	ctx->uctx.uc_stack.ss_sp = mempool_alloc(ctx_stack_pool);
	if (!ctx->uctx.uc_stack.ss_sp) {
		triton_log_error("out of memory\n");
		_free(ctx);
		return -1;
	}
	sigfillset(&ctx->uctx.uc_sigmask);
	makecontext(&ctx->uctx, (void (*)())ctx_thread, 1, ctx);

	ud->tpd = ctx;

	spin_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry, &ctx_list);
	spin_unlock(&ctx_list_lock);

	__sync_add_and_fetch(&triton_stat.context_sleeping, 1);
	__sync_add_and_fetch(&triton_stat.context_count, 1);

	return 0;
}

void __export triton_context_unregister(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	struct _triton_ctx_call_t *call;
	struct _triton_thread_t *t;

	log_debug2("ctx %p: unregister\n");

	while (!list_empty(&ctx->pending_calls)) {
		call = list_entry(ctx->pending_calls.next, typeof(*call), entry);
		list_del(&call->entry);
		mempool_free(call);
	}

	if (!list_empty(&ctx->handlers)) {
		triton_log_error("BUG:ctx:triton_unregister_ctx: handlers is not empty");
		{
			struct _triton_md_handler_t *h;
			list_for_each_entry(h, &ctx->handlers, entry)
				if (h->ud)
					printf("%p\n", h->ud);
		}
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
	if (need_terminate && list_empty(&ctx_list))
		terminate = 1;
	spin_unlock(&ctx_list_lock);
	
	__sync_sub_and_fetch(&triton_stat.context_count, 1);

	if (terminate) {
		list_for_each_entry(t, &threads, entry)
			triton_thread_wakeup(t);
	}
}

void __export triton_context_set_priority(struct triton_context_t *ud, int prio)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	
	ctx->priority = prio > 0;
}

void __export triton_context_schedule(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	ucontext_t *uctx = &ctx->thread->uctx;

	spin_lock(&ctx->lock);
	if (ctx->wakeup) {
		ctx->wakeup = 0;
		spin_unlock(&ctx->lock);
		return;
	}
	ctx->sleeping = 1;
	ctx->thread = NULL;
	spin_unlock(&ctx->lock);

	__sync_add_and_fetch(&triton_stat.context_sleeping, 1);

	log_debug2("ctx %p: enter schedule\n", ctx);
	if (swapcontext(&ctx->uctx, uctx))
		triton_log_error("swaswpntext: %s\n", strerror(errno));
	log_debug2("ctx %p: exit schedule\n", ctx);
}

void triton_context_print(void)
{
	struct _triton_context_t *ctx;

	list_for_each_entry(ctx, &ctx_list, entry)
		printf("%p\n", ctx);
}

int __export triton_context_wakeup(struct triton_context_t *ud)
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	int r;

	log_debug2("ctx %p: wakeup\n", ctx);

	spin_lock(&ctx->lock);
	if (!ctx->sleeping) {
		ctx->wakeup = 1;
		spin_unlock(&ctx->lock);
		return -1;
	}
	ctx->sleeping = 0;
	r = triton_queue_ctx(ctx);
	spin_unlock(&ctx->lock);

	if (r)
		triton_thread_wakeup(ctx->thread);
	
	__sync_sub_and_fetch(&triton_stat.context_sleeping, 1);

	return 0;
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

void __export triton_cancel_call(struct triton_context_t *ud, void (*func)(void *))
{
	struct _triton_context_t *ctx = (struct _triton_context_t *)ud->tpd;
	struct list_head *pos, *n;
	struct _triton_ctx_call_t *call;

	list_for_each_safe(pos, n, &ctx->pending_calls) {
		call = list_entry(pos, typeof(*call), entry);
		if (call->func != func)
			continue;
		list_del(&call->entry);
		mempool_free(call);
	}
}

int __export triton_init(const char *conf_file)
{
	ctx_pool = mempool_create2(sizeof(struct _triton_context_t));
	ctx_stack_pool = mempool_create2(CTX_STACK_SIZE);
	call_pool = mempool_create(sizeof(struct _triton_ctx_call_t));

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
	char *opt;

	opt = conf_get_opt("core", "thread-count");
	if (opt && atoi(opt) > 0)
		thread_count = atoi(opt);

	for(i = 0; i < thread_count; i++) {
		t = create_thread();
		if (!t)
			_exit(-1);

		list_add_tail(&t->entry, &threads);
	}

	time(&triton_stat.start_time);

	md_run();
	timer_run();
}

void __export triton_terminate()
{
	struct _triton_context_t *ctx;
	struct _triton_thread_t *t;
	int r;

	need_terminate = 1;

	spin_lock(&ctx_list_lock);
	list_for_each_entry(ctx, &ctx_list, entry) {
		spin_lock(&ctx->lock);
		ctx->need_close = 1;
		r = triton_queue_ctx(ctx);
		if (r)
			triton_thread_wakeup(ctx->thread);
		spin_unlock(&ctx->lock);
	}
	spin_unlock(&ctx_list_lock);

	list_for_each_entry(t, &threads, entry)
		pthread_join(t->thread, NULL);
	
	md_terminate();
	timer_terminate();
}

