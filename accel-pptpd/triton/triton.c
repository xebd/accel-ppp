#include "triton_p.h"

int max_threads=128;
int thread_idletime=60; //seconds

static pthread_mutex_t threads_lock=PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(threads);
static int threads_count;

static pthread_mutex_t ctx_queue_lock=PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(ctx_queue);

static pthread_mutex_t ctx_list_lock=PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(ctx_list);

struct triton_ctx_t *default_ctx;

void triton_thread_wakeup(struct triton_thread_t *thread)
{
	pthread_mutex_lock(&h->ctx->thread->lock);
	pthread_cont_signal(&h->ctx->thread->cond);
	pthread_mutex_unlock(&h->ctx->thread->lock);
}

static void* triton_thread(struct triton_thread_t *thread)
{
	struct triton_md_handler_t *h;
	struct triton_timer_t *t;
	struct timespec abstime;

	while(1)
	{
		abstime.tv_time=time(NULL)+thread_idletime;
		abstime.tv_nsec=0;
		pthread_mutex_lock(&thread->lock);
		if (pthread_cond_timedwait(&thread->cond,&thread->lock,&abstime) && !thread->ctx)
			thread->destroing=1;
		pthread_mutex_unlock(&thread->lock);

		if (thread->terminate)
			return NULL;

		if (thread->destroing)
		{
			pthread_mutex_lock(&threads_lock);
			list_del(&thread->entry);
			--threads_count;
			pthread_mutex_unlock(&threads_lock);
			free(thread);
			return NULL;
		}

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
			pthread_mutex_lock(&thread->ctx->lock);
			if (list_empty(&thread->ctx->pending_timers))
			{
				pthread_mutex_unlock(&thread->ctx->lock);
				break;
			}
			t=list_entry(thread->ctx->pending_timers.next);
			list_del(&t->entry2);
			pthread_mutex_unlock(&thread->ctx->lock);
			if (t->expire(t))
				continue;
		}

		while (1)
		{
			pthread_mutex_lock(&thread->ctx->lock);
			if (list_empty(&thread->ctx->pending_events))
			{
				pthread_mutex_unlock(&thread->ctx->lock);
				break;
			}
		
			h=list_entry(thread->ctx->pending_events.next);
			list_del(&h->entry2);
			h->pending=0;
			pthread_mutex_unlock(&thread->ctx->lock);

			if (h->trig_epoll_events&(EPOLLIN|EPOLLERR|EPOLLHUP))
				if (h->read)
					if (h->read(h))
						continue;
			if (h->trig_epoll_events&(EPOLLOUT|EPOLLERR|EPOLLHUP))
				if (h->write)
					if (h->write(h))
						continue;
			h->trig_epoll_events=0;
			/*if (h->twait==0)
				if (h->timeout)
					if (h->timeout(h))
						continue;
			if (h->twait>0)
				triton_md_set_timeout(h,h->twait);*/
		}
	
		pthread_mutex_lock(&thread->ctx->lock);
		if (!list_empty(&thread->ctx->pending_events) || !list_empty(&thread->ctx->pending_timers))
		{
			pthread_mutex_unlock(&thread->ctx->lock);
			goto cont;
		}
		thread->ctx->thread=NULL;
		thread->ctx=NULL;
		pthread_mutex_unlock(&thread->ctx->lock);

		pthread_mutex_lock(&threads_lock);
		if (!list_empty(&ctx_queue))
		{
			thread->ctx=list_entry(ctx_queue.next);
			pthread_mutex_lock(&thread->ctx->lock);
			list_del(&ctx->entry2);
			ctx->thread=thread;
			ctx->queue=0;
			pthread_mutex_unlock(&thread->ctx->lock);
			pthread_mutex_unlock(&threads_lock);
			goto cont;
		}
		list_add(&thread->entry,&threads);
		pthread_mutex_unlock(&threads_lock);
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
		return;

	pthread_mutex_lock(&threads_lock);
	if (list_empty(&threads))
	{
		if (threads_count>=max_threads)
		{
			list_add_tail(&ctx->entry2,&ctx_queue);
			ctx->queued=1;
			pthread_mutex_unlock(&threads_lock);
			return;
		}
		ctx->thread=create_thread();
	}else
	{
		ctx->thread=list_entry(threads.next);
		pthread_mutex_lock(&ctx->thread->lock);
		if (ctx->thread->destroing)
		{
			pthread_mutex_unlock(&ctx->thread->lock);
			ctx->thread=create_thread();
		}else
		{
			list_del(&ctx->thread->entry);
			pthread_mutex_unlock(&ctx->thread->lock);
		}
	}
	pthread_mutex_unlock(&threads_lock);
	triton_thread_wakeup(ctx->thread);
}

void triton_register_ctx(struct triton_ctx_t *ctx)
{
	pthread_mutex_init(&ctx->lock);
	INIT_LIST_HEAD(&ctx->handlers);
	INIT_LIST_HEAD(&ctx->timers);
	INIT_LIST_HEAD(&ctx->pending_handlers);
	INIT_LIST_HEAD(&ctx->pending_timers);

	pthread_mutex_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry,&ctx_list);
	pthread_mutex_unlock(&ctx_list_lock);
}

void triton_unregister_ctx(struct triton_ctx_t *ctx)
{
	pthread_mutex_lock(&ctx_list_lock);
	list_add_tail(&ctx->entry,&ctx_list);
	pthread_mutex_unlock(&ctx_list_lock);
}

void triton_init()
{
	md_init();
	timer_init();
}

void triton_run()
{
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

