#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>

#include "triton_p.h"

#define USE_GET_TIME

static __thread struct list_head handlers;
static __thread fd_set read_fds;
static __thread fd_set write_fds;
static __thread fd_set read_fds0;
static __thread fd_set write_fds0;
static __thread int md_term;

asm(".hidden md_init");
asm(".hidden md_run");
asm(".hidden md_terminate");

static void _triton_process_events(int wait);

void md_init()
{
	INIT_LIST_HEAD(&handlers);

	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);

	signal(SIGPIPE,SIG_IGN);

	#ifdef USE_CORO
	triton_coroutine_create(0,md_run,0,1);
	#endif
}
void md_run()
{
	md_term=0;

	while(!md_term)
	{
		_triton_process_events(1);
	}
}


#ifdef USE_CORO
asm(".hidden cur_uc");
ucontext_t cur_uc;
#endif

static void _triton_process_events(int wait)
{
	int max_fd=0,t;
	struct md_handler_t *md_h;
	struct timeval tv1,tv2,twait0;
	struct list_head *p1,*p2;
	int twait,n;
	int _break=0;
	
		gettimeofday(&tv1,NULL);
		_break=0;

 		if (wait)
		{
			twait=timer_prepare(&tv1);
			#ifdef USE_CORO
			t=coroutine_get_timeout(&tv1);
			#else
			t=-1;
			#endif
			if (t>=0 && (twait==-1 || t<twait)) twait=t;

			list_for_each_entry(md_h,&handlers,entry)
			{
				if (md_h->in_handler) continue;
				if (md_h->handler->twait>=0 && (twait==-1 || md_h->handler->twait<twait)) twait=md_h->handler->twait;
			}
		}else
		{
			twait=0;
		}

		read_fds0=read_fds; write_fds0=write_fds;

		list_for_each_entry(md_h,&handlers,entry)
		{
			if (md_h->in_handler)
			{
				FD_CLR(md_h->fd,&read_fds0);
				FD_CLR(md_h->fd,&write_fds0);
			}else
			{
				if (md_h->fd>max_fd) max_fd=md_h->fd;
			}
		}

		twait0=(struct timeval){twait/1000,(twait%1000)*1000};
		n=select(max_fd+1,&read_fds0,&write_fds0,NULL,twait>=0?&twait0:NULL);

		gettimeofday(&tv2,NULL);
		twait=(tv2.tv_sec-tv1.tv_sec)*1000+(tv2.tv_usec-tv1.tv_usec)/1000;

		list_for_each_safe(p1,p2,&handlers)
		{
			md_h=list_entry(p1,struct md_handler_t,entry);
			//if (!md_h->del)
			{
				if (md_h->handler->twait>=0)
				{
					md_h->handler->twait-=twait;
					if (md_h->handler->twait<=0) md_h->timeout=1;
				}
			}
		}

		timer_check(&tv2);
		gettimeofday(&tv2,NULL);
		#ifdef USE_CORO
		coroutine_check_timeout(&tv2);
		#endif

		list_for_each_safe(p1,p2,&handlers)
		{
			md_h=list_entry(p1,struct md_handler_t,entry);
			if (md_h->in_handler) continue;
			if (!md_h->del)
			{
				if (md_h->timeout)
				{
					md_h->timeout=0;
					#ifdef USE_CORO
					md_h->in_handler=1;
					if (md_h->coro)
					{
						long int id=(long int)md_h->coro;
						md_h->coro=NULL;
						triton_coroutine_wakeup(id);
					}else
					#endif
					{
						md_h->handler->timeout(md_h->handler);
					}
					md_h->in_handler=0;
					if (_break) return;
				}
			}
		}

		if (n<0)
		{
			perror("triton: md(select)");
			//goto check_timeout;
		}
		if (n>0)
		{
			list_for_each_safe(p1,p2,&handlers)
			{
				md_h=list_entry(p1,struct md_handler_t,entry);
				if (md_h->in_handler) continue;
				if (md_h->del) continue;
				md_h->in_handler=1;
				if (FD_ISSET(md_h->fd,&read_fds0))
				{
					if (md_h->handler->read==md_h->handler->write)
						FD_CLR(md_h->fd,&write_fds0);

					#ifdef USE_CORO
					if (md_h->coro)
					{
						long int id=(long int)md_h->coro;
						md_h->coro=NULL;
						triton_coroutine_wakeup(id);
					}else
					#endif
					{
						md_h->handler->read(md_h->handler);
					}
				}
				if (!md_h->del && FD_ISSET(md_h->fd,&write_fds0) && md_h->handler->write)
				{
					#ifdef USE_CORO
					if (md_h->coro)
					{
						long int id=(long int)md_h->coro;
						md_h->coro=NULL;
						triton_coroutine_wakeup(id);
					}else
					#endif
					{
						md_h->handler->write(md_h->handler);
					}
				}
				md_h->in_handler=0;
				if (_break) return;
			}
		}
//check_timeout:

		for(p1=handlers.next; p1!=&handlers;)
		{
			md_h=list_entry(p1,struct md_handler_t,entry);
			p1=p1->next;
			if (md_h->del)
			{
				list_del(&md_h->entry);
				free(md_h);
			}
		}

		if (!wait) _break=1;
}

void triton_process_events(void)
{
	_triton_process_events(0);
}

void md_terminate()
{
	md_term=1;
}

void triton_md_register_handler(struct triton_md_handler_t *h)
{
	struct md_handler_t *md_h;

	list_for_each_entry(md_h,&handlers,entry)
	{
		if (md_h->handler==h)
		{
			if (!md_h->del)
			{
				printf("triton: bug: double triton_md_register_handler\n");
				abort();
			}
			md_h->del=0;
			md_h->in_handler=0;
			md_h->coro=0;
			md_h->fd=0;
			return;
		}
	}

	md_h=(struct md_handler_t *)malloc(sizeof(struct md_handler_t));
	memset(md_h,0,sizeof(*md_h));
	md_h->handler=h;

	list_add_tail(&md_h->entry,&handlers);
}
void triton_md_unregister_handler(struct triton_md_handler_t *h)
{
	struct md_handler_t *md_h;

	list_for_each_entry(md_h,&handlers,entry)
	{
		if (md_h->handler==h)
		{
			triton_md_disable_handler(h,0);
			/*list_del(&md_h->entry);
			free(md_h);
			return;*/
			md_h->del=1;
			return;
		}
	}
}
void triton_md_enable_handler(struct triton_md_handler_t *h, int mode)
{
	struct md_handler_t *md_h;

	list_for_each_entry(md_h,&handlers,entry)
	{
		if (md_h->handler==h)
		{
			md_h->fd=h->fd;
			break;
		}
	}
	if (mode)
	{
		if (mode&MD_MODE_READ)
			FD_SET(h->fd,&read_fds);
		if (mode&MD_MODE_WRITE)
			FD_SET(h->fd,&write_fds);
	}else
	{
			FD_SET(h->fd,&read_fds);
			FD_SET(h->fd,&write_fds);
	}
}
void triton_md_disable_handler(struct triton_md_handler_t *h,int mode)
{
	if (mode)
	{
		if (mode&MD_MODE_READ)
			FD_CLR(h->fd,&read_fds);
		if (mode&MD_MODE_WRITE)
			FD_CLR(h->fd,&write_fds);
	}else
	{
		FD_CLR(h->fd,&read_fds);
		FD_CLR(h->fd,&write_fds);
	}
}

#ifdef USE_CORO
int triton_md_wait(struct triton_md_handler_t *h)
{
	struct md_handler_t *md_h;
	int res=0;

	list_for_each_entry(md_h,&handlers,entry)
	{
		if (md_h->handler==h) break;
	}

	md_h->in_handler=0;

	md_h->coro=current_coro;
	triton_coroutine_schedule();

	if (FD_ISSET(md_h->fd,&read_fds0)) res|=MD_MODE_READ;
	if (FD_ISSET(md_h->fd,&write_fds0)) res|=MD_MODE_WRITE;
  return res;
}
int triton_md_wait2(int fd,int mode,int timeout)
{
	int r;
	struct triton_md_handler_t h=
	{
		.fd=fd,
		.twait=timeout,
	};
	triton_md_register_handler(&h);
	triton_md_enable_handler(&h,mode);
	r=triton_md_wait(&h);
	triton_md_unregister_handler(&h);
  return r;
}
#endif
