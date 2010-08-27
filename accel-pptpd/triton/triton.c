#include <signal.h>

#include "triton_p.h"

int thread_count=64;

static spinlock_t threads_lock=SPINLOCK_INITIALIZER;
static LIST_HEAD(threads);
static int threads_count;

static spinlock_t ctx_queue_lock=SPINLOCK_INITIALIZER;
static LIST_HEAD(ctx_queue);

static spinlock_t ctx_list_lock=SPINLOCK_INITIALIZER;
static LIST_HEAD(ctx_list);

struct triton_ctx_t *default_ctx;

void triton_thread_wakeup(struct triton_thread_t *thread)
{
	pthread_kill(&thread->thread,SIGUSR1);
}

static void* triton_thread(struct triton_thread_t *thread)
{
	struct triton_md_handler_t *h;
	struct triton_timer_t *t;
	sigset_t set;
	int sig;

	sigemptyset(&set);
	sigaddset(&set,SIGUSR1);
	sigaddset(&set,SIGQUIT);

	while(1)
	{
		sigwait(&set,&sig);

		if (thread->terminate)
			return NULL;

cont:
		if (thread->ctx->close)
		{
			list_for_each_entry(h,&thread->ctx->handlers,entry)
				if (h->close)
					h->close(h);
			thread->ctx->close=0;
		}

		while (1)
		{
			spin_lock(&thread->ctx->lock);
			if (!list_empty(&thread->ctx->pending_timers))
			{
				t=list_entry(thread->ctx->pending_timers.next);
				list_del(&t->entry2);
				spin_unlock(&thread->ctx->lock);
				if (t->expire(t))
					continue;
			}
			if (!list_empty(&thread->ctx->pending_events))
			{
				h=list_entry(thread->ctx->pending_events.next);
				list_del(&h->entry2);
				h->pending=0;
				spin_unlock(&thread->ctx->lock);

				if (h->trig_epoll_events&(EPOLLIN|EPOLLERR|EPOLLHUP))
					if (h->read)
						if (h->read(h))
							continue;
				if (h->trig_epoll_events&(EPOLLOUT|EPOLLERR|EPOLLHUP))
					if (h->write)
						if (h->write(h))
							continue;
				h->trig_epoll_events=0;
				continue;
			}
			thread->ctx->thread=NULL;
			spin_unlock(&thread->ctx->lock);
			thread->ctx=NULL;
			break;
		}
	
		spin_lock(&threads_lock);
		if (!list_empty(&ctx_queue))
		{
			thread->ctx=list_entry(ctx_queue.next);
			list_del(&thread->ctx->entry2);
			spin_unlock(&threads_lock);
			spin_lock(&thread->ctx->lock);
			ctx->thread=thread;
			ctx->queue=0;
			spin_unlock(&thread->ctx->lock);
			goto cont;
		}else
		{
			list_add(&thread->entry,&threads);
			spin_unlock(&threads_lock);
		}
	}
}

struct triton_thread_t *create_thread()
{
	struct triton_thread_t *thread=malloc(sizeof(*thread));

	memset(thread,0,sizeof(*thread));
	pthread_mutex_init(&thread->lock);
	pthread_cond_init(&thread->cond);
	pthread_create(&thread->thread,NULL,md_thread,thread);
	++threads_count;

	return thread;
}

void triton_queue_ctx(struct triton_ctx_t *ctx)
{
	if (ctx->thread || ctx->queued)
		return 0;

	spin_lock(&threads_lock);
	if (list_empty(&threads))
	{
		list_add_tail(&ctx->entry2,&ctx_queue);
		spin_unlock(&threads_lock);
		ctx->queued=1;
		return 0;
	}

	ctx->thread=list_entry(threads.next);
	list_del(&ctx->thread->entry);
	spin_unlock(&threads_lock);

	return 1;
}

void triton_register_ctx(struct triton_ctx_t *ctx)
{
	pthread_mutex_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->handlers);
	INIT_LIST_HEAD(&ctx->timers);
	INIT_LIST_HEAD(&ctx->pending_handlers);
	INIT_LIST_HEAD(&ctx->pending_timers);

	spin_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry,&ctx_list);
	spin_unlock(&ctx_list_lock);
}

void triton_unregister_ctx(struct triton_ctx_t *ctx)
{
	spin_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry,&ctx_list);
	spin_unlock(&ctx_list_lock);
}

void triton_init()
{
	md_init();
	timer_init();
}

void triton_run()
{
	struct triton_thread_t *t;
	int i;

	for(i=0;i<max_threads;i++)
	{
		t=create_thread();
		list_add_tail(&t->entry,&threads);
	}
	md_run();
	timer_run();
}

void triton_terminate()
{
	struct triton_ctx_t *ctx;
	pthread_mutex_lock(&ctx_list_lock);
	list_for_each_entry(ctx,&ctx_list,entry)
	{
		pthread_mutex_lock(&ctx->lock);
		ctx->close=1;
		triton_queue_ctx(ctx);
		pthread_mutex_unlock(&ctx->lock);
	}
	pthread_mutex_unlock(&ctx_list_lock);

	timer_terminate();
	md_terminate();
}

