#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "event.h"

#define MAX_EVENT 128

static int epoll_fd;
static struct epoll_event *epoll_events;
static struct event_deferred *deferred_list;
static LIST_HEAD(timers);
static LIST_HEAD(handlers);
static int term;

int event_init(void)
{
	epoll_fd = epoll_create(1);
	if (epoll_fd < 0) {
		perror("epoll_create");
		return -1;
	}

	if (!epoll_events)
		epoll_events = malloc(MAX_EVENT * sizeof(struct epoll_event));

	term = 0;

	INIT_LIST_HEAD(&timers);
	INIT_LIST_HEAD(&handlers);

	return 0;
}

static int get_timeout()
{
	struct event_handler *h;
	struct timespec ts;

	if (list_empty(&timers))
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	h = list_entry(timers.next, typeof(*h), entry2);

	if (ts.tv_sec > h->timeout_ts.tv_sec || (ts.tv_sec == h->timeout_ts.tv_sec && ts.tv_nsec >= h->timeout_ts.tv_nsec))
		return 0;

	return (h->timeout_ts.tv_sec - ts.tv_sec)*1000 + (h->timeout_ts.tv_nsec - ts.tv_nsec)/1000000;
}

static void check_timeout()
{
	struct event_handler *h;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	while (!list_empty(&timers)) {
		h = list_entry(timers.next, typeof(*h), entry2);

		if (ts.tv_sec > h->timeout_ts.tv_sec || (ts.tv_sec == h->timeout_ts.tv_sec && ts.tv_nsec >= h->timeout_ts.tv_nsec)) {
			list_del(&h->entry2);
			h->entry2.next = NULL;
			h->timeout(h);
		} else
			break;
	}
}

void event_process(int timeout)
{
	int i, n;
	struct event_handler *h;
	struct event_deferred *d;
	uint32_t events;
	struct list_head *pos, *t;

	if (timeout == -1)
		timeout = get_timeout();
	else if (timeout > 0) {
		int t = get_timeout();
		if (t >= 0 && t < timeout)
			timeout = t;
	}

	n = epoll_wait(epoll_fd, epoll_events, MAX_EVENT, timeout);
	if (n <= 0)
		return;

	for(i = 0; i < n && !term; i++) {
		h = (struct event_handler *)epoll_events[i].data.ptr;

		if (h->fd == -1)
			continue;

		if (!h->epoll_event.events)
			continue;

		events = epoll_events[i].events & h->epoll_event.events;

		if ((events & (EPOLLIN|EPOLLHUP)) && h->read) {
			if (h->read(h))
				continue;
		}

		if ((events & (EPOLLOUT|EPOLLHUP)) && h->write) {
			if (h->write(h))
				continue;
		}
	}

	check_timeout();

	while (deferred_list) {
		d = deferred_list;
		deferred_list = deferred_list->next;
		d->fn(d);
	}

	if (term) {
		list_for_each_safe(pos, t, &handlers) {
			h = list_entry(pos, typeof(*h), entry);
			if (h->close)
				h->close(h);
		}

		while (deferred_list) {
			d = deferred_list;
			deferred_list = deferred_list->next;
			d->fn(d);
		}

		close(epoll_fd);
	}
}

void event_loop()
{
	while (!term)
		event_process(-1);
}

void event_terminate(void)
{
	term = 1;
}

int event_add_handler(struct event_handler *h, int mode)
{
	list_add_tail(&h->entry, &handlers);

	h->epoll_event.data.ptr = h;
	h->epoll_event.events = EPOLLET;

	if (mode & EVENT_READ)
		h->epoll_event.events |= EPOLLIN;

	if (mode & EVENT_WRITE)
		h->epoll_event.events |= EPOLLOUT;

	return epoll_ctl(epoll_fd, EPOLL_CTL_ADD, h->fd, &h->epoll_event);
}

int event_mod_handler(struct event_handler *h, int mode)
{
	h->epoll_event.data.ptr = h;
	h->epoll_event.events = EPOLLET;

	if (mode & EVENT_READ)
		h->epoll_event.events |= EPOLLIN;

	if (mode & EVENT_WRITE)
		h->epoll_event.events |= EPOLLOUT;

	return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, h->fd, &h->epoll_event);
}

int event_enable_handler(struct event_handler *h, int mode)
{
	uint32_t events = h->epoll_event.events;

	if (mode & EVENT_READ)
		h->epoll_event.events |= EPOLLIN;

	if (mode & EVENT_WRITE)
		h->epoll_event.events |= EPOLLOUT;

	if (events == h->epoll_event.events)
		return 0;

	return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, h->fd, &h->epoll_event);
}

int event_disable_handler(struct event_handler *h, int mode)
{
	uint32_t events = h->epoll_event.events;

	if (mode & EVENT_READ)
		h->epoll_event.events &= ~EPOLLIN;

	if (mode & EVENT_WRITE)
		h->epoll_event.events &= ~EPOLLOUT;

	if (events == h->epoll_event.events)
		return 0;

	return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, h->fd, &h->epoll_event);
}

int event_del_handler(struct event_handler *h, int c)
{
	if (!h->entry.next)
		return 0;

	if (h->entry2.next) {
		list_del(&h->entry2);
		h->entry2.next = NULL;
	}

	list_del(&h->entry);

	if (c) {
		close(h->fd);
		h->fd = -1;
		return 0;
	}

	h->epoll_event.events = 0;

	return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, h->fd, NULL);
}

void event_set_timeout(struct event_handler *h, int msec)
{
	struct event_handler *h1;
	struct list_head *pos;
	struct timespec ts;

	if (h->entry2.next)
		list_del(&h->entry2);

	if (msec == -1) {
		h->entry2.next = NULL;
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);

	ts.tv_sec += msec / 1000;
	ts.tv_nsec += (msec % 1000) * 1000000;

	if (ts.tv_nsec >= 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}

	h->timeout_ts = ts;

	pos = timers.prev;

	while (pos != &timers) {
		h1 = list_entry(pos, typeof(*h1), entry2);

		if (ts.tv_sec > h1->timeout_ts.tv_sec || (ts.tv_sec == h1->timeout_ts.tv_sec && ts.tv_nsec >= h1->timeout_ts.tv_nsec))
			break;

		pos = pos->prev;
	}

	list_add(&h->entry2, pos);
}

void event_add_deferred(struct event_deferred *d)
{
	d->next = deferred_list;
	deferred_list = d;
}

