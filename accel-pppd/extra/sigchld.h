#ifndef __SIGCHLD_H
#define __SIGCHLD_H

#include <pthread.h>
#include "list.h"

struct sigchld_handler_t
{
	struct list_head entry;
	pthread_mutex_t lock;
	pid_t pid;
	void (*handler)(struct sigchld_handler_t *, int status);
};

void sigchld_register_handler(struct sigchld_handler_t *);
void sigchld_unregister_handler(struct sigchld_handler_t *);
void sigchld_lock();
void sigchld_unlock();

#endif

