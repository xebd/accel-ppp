#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "triton_p.h"

#define EVENTS1_SIZE 1024

static __thread struct list_head events2;
static __thread struct event_t *events1;
static __thread long *args;

asm(".hidden event_init");

static struct event_t *find_event(int ev_id);
static struct event_t *create_event(int ev_id);

void event_init(void)
{
	int i;
	args=malloc(MAX_ARGS*sizeof(long));
	events1=(struct event_t *)malloc(EVENTS1_SIZE*sizeof(struct event_t));

	for (i=0; i<EVENTS1_SIZE; i++)
	{
		events1[i].ev_id=i;
		INIT_LIST_HEAD(&events1[i].handlers);
	}
	
	INIT_LIST_HEAD(&events2);
}

void triton_event_register_handler(int ev_id,triton_event_func func,int arg_cnt,...)
{
	struct event_t *ev;
	struct event_handler_t *ev_h;

	ev=find_event(ev_id);
	if (!ev)
		ev=create_event(ev_id);

	ev_h=(struct event_handler_t*)malloc(sizeof(struct event_handler_t));
	memset(ev_h,0,sizeof(*ev_h));
	ev_h->event_func=func;
	if (arg_cnt)
	{
		va_list p;
		va_start(p,arg_cnt);
		ev_h->arg_cnt=arg_cnt;
		ev_h->args=malloc(arg_cnt*sizeof(long));
		#ifdef BROKEN_GCC
		for(i=0; i<arg_cnt; i++)
			*((int*)ev_h->args+i)=va_arg(p,long);
		#else
		memcpy(ev_h->args,p,arg_cnt*sizeof(long));
		#endif
		va_end(p);
	}

	list_add_tail(&ev_h->entry,&ev->handlers);
}
void triton_event_unregister_handler(int ev_id,triton_event_func func)
{
	struct event_t *ev;
	struct event_handler_t *ev_h;

	ev=find_event(ev_id);
	if (!ev)
		return;

	list_for_each_entry(ev_h,&ev->handlers,entry)
	{
		if (ev_h->event_func==func)
		{
			list_del(&ev_h->entry);
			if (ev_h->args) free(ev_h->args);
			free(ev_h);

			if (list_empty(&ev->handlers) && ev_id>=EVENTS1_SIZE)
			{
				list_del(&ev->entry);
				free(ev);
			}
			return;
		}
	}
}

/*#define dyn_call(func,arg_cnt,args)\
	asm("movl %%esp,%%edi;\n\
			 movl %0,%%esi;\n\
			 movl %1,%%ecx;\n\
			 cld;\n\
			 rep movsl;\n\
			 call *%2;\n"::"m" (args),"m" (arg_cnt),"m" (func):"%edi","%esi","%ecx");*/
			 
void triton_event_fire(int ev_id,int arg_cnt,...)
{
	struct event_t *ev;
	struct event_handler_t *ev_h;
	struct list_head *p1,*p2;
	va_list p;
	//void *args_p=&args;
	//char pp[ARG_OFFSET+MAX_ARGS*sizeof(int)];
	//memcpy(pp,__builtin_apply_args(),ARG_OFFSET);

	ev=find_event(ev_id);
	if (!ev)
		return;

	list_for_each_safe(p1,p2,&ev->handlers)
	{
		ev_h=list_entry(p1,struct event_handler_t,entry);
		if (ev_h->arg_cnt) memcpy(args,ev_h->args,ev_h->arg_cnt*sizeof(long));
	  va_start(p,arg_cnt);
		#ifdef BROKEN_GCC
		for(i=0; i<arg_cnt; i++)
			args[ev_h->arg_cnt+i]=va_arg(p,long);
		#else
		memcpy(args+ev_h->arg_cnt,p,arg_cnt*sizeof(long));
		#endif
		//memcpy(pp+ARG_OFFSET,args,(ev_h->arg_cnt+arg_cnt)*sizeof(int));
		//__builtin_apply(ev_h->event_func,pp,ARG_OFFSET+(ev_h->arg_cnt+arg_cnt)*sizeof(int));
		//ev_h->event_func(ev_id,arg);
		//__builtin_apply(ev_h->event_func,args_p,(ev_h->arg_cnt+arg_cnt)*sizeof(int));
		dyn_call(ev_h->event_func,ev_h->arg_cnt+arg_cnt,args);
	}

	va_end(p);
}

static struct event_t *find_event(int ev_id)
{
	struct event_t *ev;
	if (ev_id<EVENTS1_SIZE)
		return events1+ev_id;

	list_for_each_entry(ev,&events2,entry)
	{
		if (ev->ev_id==ev_id)
			return ev;
	}
	return NULL;
}
static struct event_t *create_event(int ev_id)
{
	struct event_t *ev=(struct event_t *)malloc(sizeof(struct event_t));

	INIT_LIST_HEAD(&ev->handlers);

	list_add_tail(&ev->entry,&events2);

	return ev;
}
