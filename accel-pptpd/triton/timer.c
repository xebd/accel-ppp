#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "triton_p.h"

static __thread struct list_head timers;
static __thread struct list_head timers_ss;
static __thread int in_timer;

asm(".hidden timer_prepare");
asm(".hidden timer_check");
asm(".hidden timer_init");

static void tv_add(struct timeval *tv,int msec);


void timer_init(void)
{
	INIT_LIST_HEAD(&timers);
	INIT_LIST_HEAD(&timers_ss);
	in_timer=0;
}

void triton_timer_add(struct triton_timer_t*tt)
{
	struct timer_t *t=(struct timer_t *)malloc(sizeof(struct timer_t));

	t->del=0;
	t->timer=tt;
	tt->active=1;

	list_add_tail(&t->entry,&timers);
}
void triton_timer_del(struct triton_timer_t*tt)
{
	struct timer_t *t;

	list_for_each_entry(t,&timers,entry)
	{
		if (t->timer==tt)
		{
			tt->active=0;
			if (in_timer)
			{
				t->del=1;
			}else
			{
				list_del(&t->entry);
				free(t);
			}
			return;
		}
	}
}
void triton_timer_single_shot1(int twait,triton_ss_func func,int arg_cnt,...)
{
	struct timeval tv;
	struct timer_single_shot_t *t=(struct timer_single_shot_t *)malloc(sizeof(struct timer_single_shot_t));

	memset(t,0,sizeof(*t));

	gettimeofday(&tv,NULL);

	tv_add(&tv,twait);

	t->ss_func=func;
	t->expire_tv=tv;//(struct timeval){tv.tv_sec+twait/1000,tv.tv_usec+(twait%1000)*1000000};
	if (arg_cnt)
	{
		va_list p;
		va_start(p,arg_cnt);
		t->arg_cnt=arg_cnt;
		t->args=malloc(arg_cnt*sizeof(long));
		#ifdef BROKEN_GCC
		for(i=0; i<arg_cnt; i++)
			*((long*)t->args+i)=va_arg(p,long);
		#else
		memcpy(t->args,p,arg_cnt*sizeof(long));
		#endif
		va_end(p);
	}

	list_add_tail(&t->entry,&timers_ss);
}
void triton_timer_single_shot2(struct timeval *tv,triton_ss_func func,int arg_cnt,...)
{
	struct timer_single_shot_t *t=(struct timer_single_shot_t *)malloc(sizeof(struct timer_single_shot_t));

	memset(t,0,sizeof(*t));

	t->ss_func=func;
	t->expire_tv=*tv;//(struct timeval){tv.tv_sec+twait/1000,tv.tv_usec+(twait%1000)*1000000};
	if (arg_cnt)
	{
		va_list p;
		va_start(p,arg_cnt);
		t->arg_cnt=arg_cnt;
		t->args=malloc(arg_cnt*sizeof(long));
		#ifdef BROKEN_GCC
		for(i=0; i<arg_cnt; i++)
			*((long*)t->args+i)=va_arg(p,long);
		#else
		memcpy(t->args,p,arg_cnt*sizeof(long));
		#endif
		va_end(p);
	}

	list_add_tail(&t->entry,&timers_ss);
}
void triton_timer_single_shot3(int tv_sec,int tv_usec,triton_ss_func func,int arg_cnt,...)
{
	struct timer_single_shot_t *t=(struct timer_single_shot_t *)malloc(sizeof(struct timer_single_shot_t));

	memset(t,0,sizeof(*t));

	t->ss_func=func;
	t->expire_tv.tv_sec=tv_sec;
	t->expire_tv.tv_usec=tv_usec;
	if (arg_cnt)
	{
		va_list p;
		va_start(p,arg_cnt);
		t->arg_cnt=arg_cnt;
		t->args=malloc(arg_cnt*sizeof(long));
		#ifdef BROKEN_GCC
		for(i=0; i<arg_cnt; i++)
			*((int*)t->args+i)=va_arg(p,long);
		#else
		memcpy(t->args,p,arg_cnt*sizeof(long));
		#endif
		va_end(p);
	}

	list_add_tail(&t->entry,&timers_ss);
}

int timer_prepare(struct timeval *tv)
{
	struct timer_t *t;
	struct timer_single_shot_t *ss_t;

	int twait=-1,twait0;

	list_for_each_entry(t,&timers,entry)
	{
		twait0=(t->timer->expire_tv.tv_sec-tv->tv_sec)*1000+
					 (t->timer->expire_tv.tv_usec-tv->tv_usec)/1000;
		if (twait0<0) twait0=0;
		if (twait0>=0 && (twait==-1 || twait0<twait))
			twait=twait0;
	}

	if (twait)
	{
		list_for_each_entry(ss_t,&timers_ss,entry)
		{
			twait0=(ss_t->expire_tv.tv_sec-tv->tv_sec)*1000+
						(ss_t->expire_tv.tv_usec-tv->tv_usec)/1000;
			if (twait0<0) twait0=0;
			if (twait0>=0 && (twait==-1 || twait0<twait))
				twait=twait0;
		}
	}

	return twait;
}


void timer_check(struct timeval *tv)
{
	struct timer_t *t;
	struct timer_single_shot_t *ss_t;
	struct list_head *p1,*p2;
	int twait0;

	in_timer=1;

	list_for_each_safe(p1,p2,&timers)
	{
		t=list_entry(p1,struct timer_t,entry);
		if (t->del) continue;
		twait0=(t->timer->expire_tv.tv_sec-tv->tv_sec)*1000+
					 (t->timer->expire_tv.tv_usec-tv->tv_usec)/1000;
		if (twait0<=0)
		{
			if (!t->timer->expire(t->timer))
			{
				t->timer->active=0;
				list_del(&t->entry);
				free(t);
				continue;
			}
			if (t->timer->period)
			{
				tv_add(&t->timer->expire_tv,t->timer->period);
			}
		}
	}

	list_for_each_safe(p1,p2,&timers_ss)
	{
		ss_t=list_entry(p1,struct timer_single_shot_t,entry);
		twait0=(ss_t->expire_tv.tv_sec-tv->tv_sec)*1000+
					 (ss_t->expire_tv.tv_usec-tv->tv_usec)/1000;
		if (twait0<=0)
		{
			list_del(&ss_t->entry);
			if (ss_t->arg_cnt)
			{
				//args_p=&ss_t->args;
				//memcpy(pp+ARG_OFFSET,ss_t->args,ss_t->arg_cnt*sizeof(int));
				//__builtin_apply(ss_t->ss_func,pp,ARG_OFFSET+ss_t->arg_cnt*sizeof(int));
				dyn_call(ss_t->ss_func,ss_t->arg_cnt,ss_t->args);
				free(ss_t->args);
			}else ss_t->ss_func();
			free(ss_t);
		}
	}

	list_for_each_safe(p1,p2,&timers)
	{
		t=list_entry(p1,struct timer_t,entry);
		if (t->del)
		{
			list_del(&t->entry);
			t->timer->active=0;
			free(t);
		}
	}
	in_timer=0;
}

static void tv_add(struct timeval *tv,int msec)
{
	tv->tv_sec+=msec/1000;
	tv->tv_usec+=(msec%1000)*1000;
	if (tv->tv_usec>=1000000)
	{
		tv->tv_sec++;
		tv->tv_usec-=1000000;
	}
}
