#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

#include "triton/mempool.h"
#include "events.h"
#include "ppp.h"

#include "log.h"

struct log_pd_t
{
	struct ppp_pd_t pd;
	struct ppp_t *ppp;
	struct list_head msgs;
	struct log_msg_t *msg;
};

struct _log_msg_t
{
	struct list_head entry;
	int level;
	struct timeval timestamp;
	struct list_head chunks;
	uint8_t refs;
};

static int log_level=10;
static int conf_copy = 0;

static LIST_HEAD(targets);
static mempool_t msg_pool;
static mempool_t _msg_pool;
static mempool_t chunk_pool;

static __thread struct ppp_t *cur_ppp;
static __thread struct _log_msg_t *cur_msg;
static __thread char stat_buf[LOG_MAX_SIZE+1];

static FILE *emerg_file;

static void *pd_key;

static void _log_free_msg(struct _log_msg_t *msg);
static struct log_msg_t *clone_msg(struct _log_msg_t *msg);
static int add_msg(struct _log_msg_t *msg, const char *buf);
static struct log_pd_t *find_pd(struct ppp_t *ppp);

static void do_log(int level, const char *fmt, va_list ap, struct ppp_t *ppp)
{
	struct log_target_t *t;
	struct log_msg_t *m;
	struct log_pd_t *lpd;

	if (list_empty(&targets))
		return;

	vsnprintf(stat_buf, LOG_MAX_SIZE, fmt, ap);
	if (!cur_msg) {
		cur_msg = mempool_alloc(_msg_pool);
		if (!cur_msg)
			return;
		INIT_LIST_HEAD(&cur_msg->chunks);
		cur_msg->refs = 1;
		cur_msg->level = level;
		gettimeofday(&cur_msg->timestamp, NULL);
	}

	if (add_msg(cur_msg, stat_buf))
		goto out;

	if (stat_buf[strlen(stat_buf) - 1] != '\n')
		return;

	if (ppp && !ppp->username) {
		lpd = find_pd(ppp);
		list_add_tail(&cur_msg->entry, &lpd->msgs);
	}

	list_for_each_entry(t, &targets, entry) {
		if (ppp) {
			if (t->session_log) {
				m = clone_msg(cur_msg);
				if (!m)
					break;
				t->session_log(ppp, m);
			}
		}
		if (!ppp || conf_copy) {
			if (t->log) {
				m = clone_msg(cur_msg);
				if (!m)
					break;
				t->log(m);
			}
		}
	}

out:
	if (!ppp || ppp->username)
		_log_free_msg(cur_msg);
	cur_msg = NULL;
}

void __export log_error(const char *fmt,...)
{
	if (log_level >= LOG_ERROR) {
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_ERROR, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_warn(const char *fmt,...)
{
	if (log_level >= LOG_WARN) {
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_WARN, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_info(const char *fmt,...)
{
	if (log_level >= LOG_INFO) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_debug(const char *fmt,...)
{
	if (log_level >= LOG_DEBUG) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_DEBUG, fmt, ap, NULL);
		va_end(ap);
	}
}

void __export log_msg(const char *fmt,...)
{
	va_list ap;
	va_start(ap, fmt);
	do_log(LOG_MSG, fmt, ap, NULL);
	va_end(ap);
}

void __export log_ppp_error(const char *fmt,...)
{
	if (log_level >= LOG_ERROR) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_ERROR, fmt, ap, cur_ppp);
		va_end(ap);
	}
}

void __export log_ppp_warn(const char *fmt,...)
{
	if (log_level >= LOG_WARN) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_WARN, fmt, ap, cur_ppp);
		va_end(ap);
	}
}

void __export log_ppp_info(const char *fmt,...)
{
	if (log_level >= LOG_INFO) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO, fmt, ap, cur_ppp);
		va_end(ap);
	}
}

void __export log_ppp_debug(const char *fmt,...)
{
	if (log_level >= LOG_DEBUG) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_DEBUG, fmt, ap, cur_ppp);
		va_end(ap);
	}
}

void __export log_ppp_msg(const char *fmt,...)
{
	va_list ap;
	va_start(ap, fmt);
	do_log(LOG_MSG, fmt, ap, cur_ppp);
	va_end(ap);
}

void __export log_emerg(const char *fmt, ...)
{
	if (emerg_file) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(emerg_file, fmt, ap);
		va_end(ap);
	}
}

void __export log_free_msg(struct log_msg_t *m)
{
	struct _log_msg_t *msg = (struct _log_msg_t *)m->lpd;

	mempool_free(m->hdr);
	_log_free_msg(msg);

	mempool_free(m);
}


static void _log_free_msg(struct _log_msg_t *msg)
{
	struct log_chunk_t *chunk;

	if (__sync_sub_and_fetch(&msg->refs, 1))
		return;
	
	while(!list_empty(&msg->chunks)) {
		chunk = list_entry(msg->chunks.next, typeof(*chunk), entry);
		list_del(&chunk->entry);
		mempool_free(chunk);
	}

	mempool_free(msg);
}

static struct log_msg_t *clone_msg(struct _log_msg_t *msg)
{
	struct log_msg_t *m = mempool_alloc(msg_pool);
	if (!m) {
		log_emerg("log: out of memory\n");
		return NULL;
	}
	
	m->hdr = mempool_alloc(chunk_pool);
	if (!m->hdr) {
		log_emerg("log: out of memory\n");
		mempool_free(m);
		return NULL;
	}	

	m->hdr->len = 0;
	m->lpd = msg;
	m->chunks = &msg->chunks;
	m->timestamp = msg->timestamp;
	m->level = msg->level;

	__sync_add_and_fetch(&msg->refs, 1);

	return m;
}

static int add_msg(struct _log_msg_t *msg, const char *buf)
{
	struct log_chunk_t *chunk;
	int i, len, chunk_cnt;
	
	len = strlen(buf);
	chunk_cnt = (len - 1)/LOG_CHUNK_SIZE + 1;

	for (i = 0; i < chunk_cnt; i++) {
		chunk = mempool_alloc(chunk_pool);
		if (!chunk)
			return -1;

		chunk->len = i == chunk_cnt -1 ? len - i * LOG_CHUNK_SIZE : LOG_CHUNK_SIZE;
		memcpy(chunk->msg, buf + i * LOG_CHUNK_SIZE, chunk->len);
		chunk->msg[chunk->len] = 0;

		list_add_tail(&chunk->entry, &msg->chunks);
	}

	return 0;
}

static struct log_pd_t *find_pd(struct ppp_t *ppp)
{
	struct ppp_pd_t *pd;
	struct log_pd_t *lpd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &pd_key) {
			lpd = container_of(pd, typeof(*lpd), pd);
			return lpd;
		}
	}
	list_for_each_entry(pd, &ppp->pd_list, entry)
		printf("%p %p\n", pd->key, &pd_key);
	log_emerg("log:BUG: pd not found\n");
	abort();
}

static void ev_ctrl_starting(struct ppp_t *ppp)
{
	struct log_pd_t *lpd = malloc(sizeof(*lpd));
	if (!lpd) {
		log_emerg("log: out of memory\n");
		return;
	}

	memset(lpd, 0, sizeof(*lpd));
	lpd->pd.key = &pd_key;
	lpd->ppp = ppp;
	INIT_LIST_HEAD(&lpd->msgs);
	list_add_tail(&lpd->pd.entry, &ppp->pd_list);
}

static void ev_ctrl_finished(struct ppp_t *ppp)
{
	struct log_pd_t *lpd = find_pd(ppp);
	struct _log_msg_t *msg;
	struct log_msg_t *m;
	struct log_target_t *t;

	if (lpd->msg) {
		log_emerg("log:BUG: lpd->msg is not NULL\n");
		abort();
	}

	if (ppp->username) {
		if (!list_empty(&lpd->msgs)) {
			log_emerg("log:BUG: lpd->msgs is not empty\n");
			abort();
		}
		list_for_each_entry(t, &targets, entry)
			if (t->session_stop)
				t->session_stop(ppp);
	}

	while (!list_empty(&lpd->msgs)) {
		msg = list_entry(lpd->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);

		list_for_each_entry(t, &targets, entry) {
			if (!t->log)
				continue;
			m = clone_msg(msg);
			if (!m)
				break;
			t->log(m);
		}

		_log_free_msg(msg);
	}

	list_del(&lpd->pd.entry);
	free(lpd);
}

static void ev_ppp_authorized(struct ppp_t *ppp)
{
	struct log_pd_t *lpd = find_pd(ppp);
	struct _log_msg_t *msg;
	struct log_msg_t *m;
	struct log_target_t *t;
	
	list_for_each_entry(t, &targets, entry)
		if (t->session_start)
			t->session_start(ppp);

	while(!list_empty(&lpd->msgs)) {
		msg = list_entry(lpd->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);

		list_for_each_entry(t, &targets, entry) {
			if (!t->session_log)
				continue;
			m = clone_msg(msg);
			if (!m)
				break;
			t->session_log(lpd->ppp, m);
		}

		_log_free_msg(msg);
	}
}

void __export log_switch(struct triton_context_t *ctx, void *arg)
{
	cur_ppp = (struct ppp_t *)arg;
}

void __export log_register_target(struct log_target_t *t)
{
	list_add_tail(&t->entry, &targets);
}

static void __init log_init(void)
{
	char *opt;

	opt = conf_get_opt("log", "log-emerg");
	if (opt) {
		emerg_file = fopen(opt, "a");
		if (!emerg_file)
			fprintf(stderr, "log:open: %s\n", strerror(errno));
	}

	opt = conf_get_opt("log", "copy");
	if (opt && atoi(opt) > 0)
		conf_copy = 1;

	msg_pool = mempool_create(sizeof(struct log_msg_t));
	_msg_pool = mempool_create(sizeof(struct _log_msg_t));
	chunk_pool = mempool_create(sizeof(struct log_chunk_t) + LOG_CHUNK_SIZE + 1);

	triton_event_register_handler(EV_CTRL_STARTING, (triton_event_func)ev_ctrl_starting);
	triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
	triton_event_register_handler(EV_PPP_AUTHORIZED, (triton_event_func)ev_ppp_authorized);
}
