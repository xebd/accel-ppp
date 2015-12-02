#ifndef __EVENT_H__
#define __EVENT_H__

#include <sys/epoll.h>
#include "list.h"

#define EVENT_READ 1
#define EVENT_WRITE 2

struct event_handler {
	struct list_head entry;
	struct list_head entry2;
	struct timespec timeout_ts;
	int fd;
	struct epoll_event epoll_event;
	int (*read)(struct event_handler *);
	int (*write)(struct event_handler *);
	void (*timeout)(struct event_handler *);
	void (*close)(struct event_handler *);
};

struct event_deferred {
	struct event_deferred *next;
	void (*fn)(struct event_deferred *);
};

int event_init(void);
void event_loop();
void event_process(int timeout);
void event_terminate(void);
int event_add_handler(struct event_handler *h, int mode);
int event_enable_handler(struct event_handler *h, int mode);
int event_disable_handler(struct event_handler *h, int mode);
int event_mod_handler(struct event_handler *h, int mode);
int event_del_handler(struct event_handler *h, int close);
void event_set_timeout(struct event_handler *h, int msec);
void event_add_deferred(struct event_deferred *d);

static inline void event_init_handler(struct event_handler *h)
{
	h->entry.next = NULL;
}

#endif
