#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "triton.h"
#include "radius_p.h"

#include "memdebug.h"

static int num;
static LIST_HEAD(serv_list);

static struct rad_server_t *__rad_server_get(int type, struct rad_server_t *exclude)
{
	struct rad_server_t *s, *s0 = NULL;
	struct timespec ts;
	
	clock_gettime(CLOCK_MONOTONIC, &ts);

	list_for_each_entry(s, &serv_list, entry) {
		if (s == exclude)
			continue;

		if (s->fail_time && ts.tv_sec < s->fail_time)
			continue;

		if (type == RAD_SERV_AUTH && !s->auth_addr)
			continue;
		else if (type == RAD_SERV_ACCT && !s->acct_addr)
			continue;

		if (!s0) {
			s0 = s;
			continue;
		}

		if (s->client_cnt[type] < s0->client_cnt[type])
			s0 = s;
	}

	if (!s0)
		return NULL;

	__sync_add_and_fetch(&s0->client_cnt[type], 1);

	return s0;
}

struct rad_server_t *rad_server_get(int type)
{
	return __rad_server_get(type, NULL);
}

void rad_server_put(struct rad_server_t *s, int type)
{
	__sync_sub_and_fetch(&s->client_cnt[type], 1);
}

int rad_server_req_enter(struct rad_req_t *req)
{
	struct timespec ts;
	
	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ts.tv_sec < req->serv->fail_time)
		return -1;

	if (!req->serv->max_req_cnt)
		return 0;

	pthread_mutex_lock(&req->serv->lock);
	
	if (ts.tv_sec < req->serv->fail_time) {
		pthread_mutex_unlock(&req->serv->lock);
		return -1;
	}

	if (req->serv->req_cnt >= req->serv->max_req_cnt) {
		list_add_tail(&req->entry, &req->serv->req_queue);
		pthread_mutex_unlock(&req->serv->lock);
		triton_context_schedule();
		pthread_mutex_lock(&req->serv->lock);

		if (ts.tv_sec < req->serv->fail_time) {
			pthread_mutex_unlock(&req->serv->lock);
			return -1;
		}
	}

	req->serv->req_cnt++;
	pthread_mutex_unlock(&req->serv->lock);

	return 0;
}

void rad_server_req_exit(struct rad_req_t *req)
{
	struct rad_req_t *r = NULL;
	
	if (!req->serv->max_req_cnt)
		return;

	pthread_mutex_lock(&req->serv->lock);
	req->serv->req_cnt--;
	if (req->serv->req_cnt < req->serv->max_req_cnt && !list_empty(&req->serv->req_queue)) {
		r = list_entry(req->serv->req_queue.next, typeof(*r), entry);
		list_del(&r->entry);
	}
	pthread_mutex_unlock(&req->serv->lock);

	if (r)
		triton_context_wakeup(r->rpd->ppp->ctrl->ctx);
}

int rad_server_realloc(struct rad_req_t *req)
{
	struct rad_server_t *s = __rad_server_get(req->type, req->serv);

	if (!s)
		return -1;

	if (req->serv)
		rad_server_put(req->serv, req->type);

	req->serv = s;

	if (req->hnd.fd != -1) {
		if (req->hnd.tpd)
			triton_md_unregister_handler(&req->hnd);
		close(req->hnd.fd);
		req->hnd.fd = -1;
	}

	if (req->type == RAD_SERV_ACCT) {
		req->server_addr = req->serv->acct_addr;
		req->server_port = req->serv->acct_port;
	} else {
		req->server_addr = req->serv->auth_addr;
		req->server_port = req->serv->auth_port;
	}

	return 0;
}

void rad_server_fail(struct rad_server_t *s)
{
	struct rad_req_t *r;
	struct timespec ts;
	
	clock_gettime(CLOCK_MONOTONIC, &ts);

	pthread_mutex_lock(&s->lock);

	if (ts.tv_sec > s->fail_time) {
		s->fail_time = ts.tv_sec + s->conf_fail_time;
		log_ppp_warn("radius: server(%i) not responding\n", s->id);
		log_warn("radius: server(%i) not responding\n", s->id);
	}

	while (!list_empty(&s->req_queue)) {
		r = list_entry(s->req_queue.next, typeof(*r), entry);
		list_del(&r->entry);
		triton_context_wakeup(r->rpd->ppp->ctrl->ctx);
	}
	pthread_mutex_unlock(&s->lock);
}

void rad_server_timeout(struct rad_server_t *s)
{
	if (__sync_add_and_fetch(&s->timeout_cnt, 1) >= conf_max_try)
		rad_server_fail(s);
}

void rad_server_reply(struct rad_server_t *s)
{
	__sync_synchronize();
	s->timeout_cnt = 0;
}

static void __add_server(struct rad_server_t *s)
{
	s->id = ++num;
	INIT_LIST_HEAD(&s->req_queue);
	pthread_mutex_init(&s->lock, NULL);
	s->conf_fail_time = conf_fail_time;
	list_add_tail(&s->entry, &serv_list);
}

static int parse_server_old(const char *opt, in_addr_t *addr, int *port, char **secret)
{
	char *str = _strdup(opt);
	char *p1, *p2;

	p1 = strstr(str, ":");
	p2 = strstr(str, ",");

	if (p1)
		*p1 = 0;
	if (p2)
		*p2 = 0;
	else
		return -1;
	
	*addr = inet_addr(str);
	
	if (p1) {
		*port = atoi(p1 + 1);
		if (*port <=0 )
			return -1;
	}

	p1 = _strdup(p2 + 1);
	p2 = *secret;
	*secret = p1;
	if (p2)
		_free(p2);
	
	_free(str);

	return 0;
}

static void add_server_old(void)
{
	const char *opt;
	struct rad_server_t *s = _malloc(sizeof(*s));

	memset(s, 0, sizeof(*s));

	opt = conf_get_opt("radius", "auth-server");
	if (opt) {
		if (parse_server_old(opt, &s->auth_addr, &s->auth_port, &s->auth_secret)) {
			log_emerg("radius: failed to parse 'auth-server'\n");
			goto out;
		}
	}

	opt = conf_get_opt("radius", "acct-server");
	if (opt) {
		if (parse_server_old(opt, &s->acct_addr, &s->acct_port, &s->acct_secret)) {
			log_emerg("radius: failed to parse 'acct-server'\n");
			goto out;
		}
		conf_accounting = 1;
	}

	if (s->auth_addr || s->acct_addr) {
		__add_server(s);
		return;
	}

out:
	_free(s);
}

static int parse_server(const char *_opt, struct rad_server_t *s)
{
	char *opt = _strdup(_opt);
	char *ptr1, *ptr2, *ptr3, *endptr;

	ptr1 = strchr(opt, ',');
	if (!ptr1)
		goto out;
	
	ptr2 = strchr(ptr1 + 1, ',');

	if (ptr2)
		ptr3 = strchr(ptr2 + 1, ',');
	else
		ptr3 = NULL;
	
	*ptr1 = 0;
	if (ptr2)
		*ptr2 = 0;
	if (ptr3)
		*ptr3 = 0;

	s->auth_addr = s->acct_addr = inet_addr(opt);

	if (ptr2) {
		if (ptr2[1]) {
			s->auth_port = strtol(ptr2 + 1, &endptr, 10);
			if (*endptr)
				goto out;
		}
		if (!s->auth_port)
			s->auth_addr = 0;
	} else
		s->auth_port = 1812;
	
	if (ptr3) {
		if (ptr3[1]) {
			s->acct_port = strtol(ptr3 + 1, &endptr, 10);
			if (*endptr)
				goto out;
		}
		if (!s->acct_port)
			s->acct_addr = 0;
	} else
		s->acct_port = 1813;

	if (!s->auth_addr && !s->acct_addr)
		goto out;

	if (s->auth_addr)
		s->auth_secret = _strdup(ptr1 + 1);
	
	if (s->acct_addr) {
		s->acct_secret = _strdup(ptr1 + 1);
		conf_accounting = 1;
	}

	return 0;

out:
	_free(opt);

	return -1;
}

static void add_server(const char *opt)
{
	struct rad_server_t *s = _malloc(sizeof(*s));
	
	memset(s, 0, sizeof(*s));

	if (parse_server(opt, s)) {
		log_emerg("radius: failed to parse '%s'\n", opt);
		_free(s);
		return;
	}

	__add_server(s);
}

static void init(void)
{
	struct conf_sect_t *s = conf_get_section("radius");
	struct conf_option_t *opt;

	add_server_old();


	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "server"))
			continue;
		add_server(opt->val);
	}
}

DEFINE_INIT(21, init);
