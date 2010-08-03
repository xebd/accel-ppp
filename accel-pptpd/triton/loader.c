#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>

#include "conf_file.h"
#include "triton_p.h"

void md_init(void);
void event_init(void);
void timer_init(void);

struct thread_arg_t
{
	int (*post_init)(void*);
	void *arg;
};

void *thread(struct thread_arg_t *arg)
{
	printf("triton: starting new thread\n");
	#ifdef USE_CORO
	coroutine_init();
	#endif
	md_init();
	event_init();
	timer_init();
	
	arg->post_init(arg->arg);
	
	free(arg);
	
	//conf_file_load(cf_name);
	#ifdef USE_CORO
	schedule();
	#else
	md_run();
	#endif
	
	return NULL;
}

int triton_init(const char *conf_file)
{
	return 0;
}
int triton_run(int (*post_init)(void*),void *arg)
{
	pthread_t thr;
	struct thread_arg_t *thr_arg=malloc(sizeof(*thr_arg));
	thr_arg->post_init=post_init;
	thr_arg->arg=arg;
	return pthread_create(&thr,NULL,(void*(*)(void*))thread,thr_arg);
}
