#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>

#include "triton_p.h"

#ifdef USE_CORO

static LIST_HEAD(coroutines);
asm(".hidden current_coro");
struct coroutine_t *current_coro=NULL;
//asm(".hidden sched_uc");
static ucontext_t sched_uc;

asm(".hidden schedule");
void schedule(void)
{
	struct coroutine_t *coro;
	struct list_head *p;
	while(1)
	{
		current_coro=NULL;
		for(p=coroutines.next; p!=&coroutines; p=p->next)
		{
			coro=list_entry(p,typeof(*current_coro),entry);
			if (coro->time.tv_sec)
			{
				if (!current_coro) current_coro=coro;
				else if (coro->time.tv_sec<current_coro->time.tv_sec) continue;
				else if (coro->time.tv_sec>current_coro->time.tv_sec || coro->time.tv_usec>current_coro->time.tv_usec) current_coro=coro;
			}
		}
		if (current_coro)
		{
			get_time(&current_coro->time);
			swapcontext(&sched_uc,&current_coro->uc);
			//break;
		}else
		{
			printf("triton: coroutine: bug: no current coro !!!\n");
			exit(-1);
		}
	}
}

void coroutine_init(void)
{
	getcontext(&sched_uc);
	sched_uc.uc_stack.ss_sp=malloc(DEF_COROUTINE_STACK);
	sched_uc.uc_stack.ss_size=DEF_COROUTINE_STACK;
	makecontext(&sched_uc,schedule,0);
}

void triton_coroutine_schedule()
{
	memset(&current_coro->time,0,sizeof(current_coro->time));
	memset(&current_coro->timeout,0,sizeof(current_coro->timeout));
	swapcontext(&current_coro->uc,&sched_uc);
}

long int triton_coroutine_create(int stack_size,triton_coroutine_func func,void *arg,int run)
{
	struct coroutine_t *coro=malloc(sizeof(*coro));
	memset(coro,0,sizeof(*coro));

	if (!stack_size) stack_size=DEF_COROUTINE_STACK;//+SIGSTKSZ;

	getcontext(&coro->uc);
	coro->uc.uc_link=&sched_uc;
	coro->uc.uc_stack.ss_sp=malloc(stack_size);
	coro->uc.uc_stack.ss_size=stack_size;
	makecontext(&coro->uc,(void (*)(void))func,1,arg);

	if (run) coro->time.tv_sec=1;

	list_add(&coro->entry,&coroutines);

	return (long int)coro;
}
void triton_coroutine_delete(long int id)
{
	struct coroutine_t *coro=(struct coroutine_t *)id;

	list_del(&coro->entry);
	free(coro->uc.uc_stack.ss_sp);
}
int triton_coroutine_schedule_timeout(int msec)
{
	//current_coro->msleep=msec;
	struct timeval tv;
	int t;
	get_time(&current_coro->timeout);
	current_coro->timeout.tv_sec+=msec/1000;
	current_coro->timeout.tv_usec+=(msec%1000)*1000;
	if (current_coro->timeout.tv_usec>=1000000)
	{
		current_coro->timeout.tv_sec++;
		current_coro->timeout.tv_usec-=1000000;
	}
	//triton_coroutine_schedule();
	memset(&current_coro->time,0,sizeof(current_coro->time));
	//memset(&current_coro->timeout,0,sizeof(current_coro->timeout));
	swapcontext(&current_coro->uc,&sched_uc);
	get_time(&tv);
	t=(current_coro->timeout.tv_sec-tv.tv_sec)*1000+(current_coro->timeout.tv_usec-tv.tv_usec)/1000;
	if (t<0) t=0;
	return t;
}
void triton_coroutine_wakeup(long int id)
{
	struct coroutine_t *coro=(struct coroutine_t *)id;
	struct coroutine_t *cur_coro=current_coro;
	get_time(&current_coro->time);
	current_coro=coro;
	swapcontext(&cur_coro->uc,&coro->uc);
}

asm(".hidden coroutine_get_timeout");
int coroutine_get_timeout(struct timeval *tv)
{
	struct coroutine_t *coro;
	struct list_head *p;
	int twait,t=-1;
	for(p=coroutines.next; p!=&coroutines; p=p->next)
	{
		coro=list_entry(p,typeof(*coro),entry);
		if (coro->timeout.tv_sec)
		{
			twait=(coro->timeout.tv_sec-tv->tv_sec)*1000+(coro->timeout.tv_usec-tv->tv_usec)/1000;
			if (t==-1 || twait<t) t=twait;
		}
	}
	return t;
}
asm(".hidden coroutine_check_timeout");
void coroutine_check_timeout(struct timeval *tv)
{
	struct coroutine_t *coro;
	struct list_head *p;
	for(p=coroutines.next; p!=&coroutines;)
	{
		coro=list_entry(p,typeof(*coro),entry);
		p=p->next;
		if (coro->timeout.tv_sec && (tv->tv_sec>coro->timeout.tv_sec || (tv->tv_sec==coro->timeout.tv_sec && tv->tv_usec>=coro->timeout.tv_usec)))
		{
			triton_coroutine_wakeup((long int)coro);
		}
	}
}

#endif
