#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>

#include <rte_malloc.h>

#include "init.h"
#include "common.h"
#include "conf_file.h"

#include "log.h"

#define LOG_MSG   0
#define LOG_ERROR 1
#define LOG_WARN  2
#define LOG_INFO1 3
#define LOG_INFO2 4
#define LOG_DEBUG 5

struct _log_msg {
	struct list_head entry;
	int level;
	struct timeval timestamp;
	struct list_head chunks;
	unsigned int refs;
};

static int log_level;

static LIST_HEAD(targets);

static pthread_key_t pth_key;
static __thread struct _log_msg *cur_msg;
static __thread char *stat_buf;

static FILE *emerg_file;
static FILE *debug_file;

static void _log_free_msg(struct _log_msg *msg);
static struct log_msg *clone_msg(struct _log_msg *msg);
static int add_msg(struct _log_msg *msg, const char *buf, int len);
static void write_msg(FILE *f, struct _log_msg *msg);

static void stat_buf_free(void *ptr)
{
	rte_free(ptr);
}

void log_append(const char *str, int len)
{
	struct log_target *t;
	struct log_msg *m;

	if (!cur_msg)
		return;

	if (add_msg(cur_msg, str, len))
		goto out;

	if (str[len - 1] != '\n')
		return;

	if (debug_file)
		write_msg(debug_file, cur_msg);

	list_for_each_entry(t, &targets, entry) {
		m = clone_msg(cur_msg);
		if (!m)
			break;
		t->log(m);
	}

out:
	_log_free_msg(cur_msg);
	cur_msg = NULL;
}

static void do_log(int level, const char *fmt, va_list ap)
{
	if (!cur_msg) {
		cur_msg = rte_malloc(NULL, sizeof(*cur_msg), 0);
		if (!cur_msg)
			return;
		INIT_LIST_HEAD(&cur_msg->chunks);
		cur_msg->refs = 1;
		cur_msg->level = level;
		gettimeofday(&cur_msg->timestamp, NULL);
	}

	if (!stat_buf) {
		stat_buf = rte_malloc(NULL, LOG_MAX_SIZE + 1, 0);
		pthread_setspecific(pth_key, stat_buf);
	}

	vsnprintf(stat_buf, LOG_MAX_SIZE, fmt, ap);
	log_append(stat_buf, strlen(stat_buf));
}

void log_error(const char *fmt,...)
{
	if (log_level >= LOG_ERROR) {
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_ERROR, fmt, ap);
		va_end(ap);
	}
}

void log_warn(const char *fmt,...)
{
	if (log_level >= LOG_WARN) {
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_WARN, fmt, ap);
		va_end(ap);
	}
}

void log_info1(const char *fmt,...)
{
	if (log_level >= LOG_INFO1) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO1, fmt, ap);
		va_end(ap);
	}
}

void log_info2(const char *fmt,...)
{
	if (log_level >= LOG_INFO2) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_INFO2, fmt, ap);
		va_end(ap);
	}
}

void log_debug(const char *fmt,...)
{
	if (log_level >= LOG_DEBUG) {
		va_list ap;
		va_start(ap, fmt);
		do_log(LOG_DEBUG, fmt, ap);
		va_end(ap);
	}
}

void log_debug2(const char *fmt,...)
{
	va_list ap;
	if (!debug_file)
		return;
	va_start(ap, fmt);
	vfprintf(debug_file, fmt, ap);
	va_end(ap);
	fflush(debug_file);
}
void log_msg(const char *fmt,...)
{
	va_list ap;
	va_start(ap, fmt);
	do_log(LOG_MSG, fmt, ap);
	va_end(ap);
}

void log_emerg(const char *fmt, ...)
{
	if (emerg_file) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(emerg_file, fmt, ap);
		va_end(ap);
		fflush(emerg_file);
	}
}

void log_free_msg(struct log_msg *m)
{
	struct _log_msg *msg = (struct _log_msg *)m->lpd;

	//printf("free msg %p\n", m);

	rte_free(m->hdr);
	_log_free_msg(msg);

	rte_free(m);
}


static void _log_free_msg(struct _log_msg *msg)
{
	struct log_chunk *chunk;

	if (__sync_sub_and_fetch(&msg->refs, 1))
		return;

	while(!list_empty(&msg->chunks)) {
		chunk = list_entry(msg->chunks.next, typeof(*chunk), entry);
		list_del(&chunk->entry);
		rte_free(chunk);
	}

	rte_free(msg);
}

static struct log_msg *clone_msg(struct _log_msg *msg)
{
	struct log_msg *m = rte_malloc(NULL, sizeof(*m), 0);
	if (!m) {
		log_emerg("log: out of memory\n");
		return NULL;
	}

	m->hdr = rte_malloc(NULL, sizeof(*m->hdr), 0);
	if (!m->hdr) {
		log_emerg("log: out of memory\n");
		rte_free(m);
		return NULL;
	}

	m->hdr->len = 0;
	m->lpd = msg;
	m->chunks = &msg->chunks;
	m->timestamp = msg->timestamp;
	m->level = msg->level;

	__sync_add_and_fetch(&msg->refs, 1);

	//printf("clone msg %p\n", m);
	return m;
}

static int add_msg(struct _log_msg *msg, const char *buf, int len)
{
	struct log_chunk *chunk;
	int i, chunk_cnt, n;

	if (!list_empty(&msg->chunks)) {
		chunk = list_entry(msg->chunks.prev, typeof(*chunk), entry);
		if (chunk->len != LOG_CHUNK_SIZE) {
			n = LOG_CHUNK_SIZE - chunk->len;
			if (n > len)
				n = len;
			memcpy(chunk->msg + chunk->len, buf, n);
			chunk->len += n;
			chunk->msg[chunk->len] = 0;
			buf += n;
			len -= n;
			if (len == 0)
				return 0;
		}
	}

	chunk_cnt = (len - 1)/LOG_CHUNK_SIZE + 1;

	for (i = 0; i < chunk_cnt; i++) {
		chunk = rte_malloc(NULL, sizeof(*chunk), 0);
		if (!chunk)
			return -1;

		chunk->len = i == chunk_cnt -1 ? len - i * LOG_CHUNK_SIZE : LOG_CHUNK_SIZE;
		memcpy(chunk->msg, buf + i * LOG_CHUNK_SIZE, chunk->len);
		chunk->msg[chunk->len] = 0;

		list_add_tail(&chunk->entry, &msg->chunks);
	}

	return 0;
}

static void write_msg(FILE *f, struct _log_msg *msg)
{
	struct log_chunk *chunk;

	fprintf(f, "[%u.%03u] ", (unsigned)msg->timestamp.tv_sec, (unsigned)msg->timestamp.tv_usec/1000);

	list_for_each_entry(chunk, &msg->chunks, entry)
		fwrite(chunk->msg, chunk->len, 1, f);

	fflush(f);
}

void log_register_target(struct log_target *t)
{
	list_add_tail(&t->entry, &targets);
}

static void sighup(int n)
{
	struct log_target *t;

	list_for_each_entry(t, &targets, entry)
		if (t->reopen)
			t->reopen();
}

static void config_load(void)
{
	const char *opt;

	opt = conf_get_opt("log", "level");
	if (opt && atoi(opt) >= 0)
		log_level = atoi(opt);

	opt = conf_get_opt("log", "log-emerg");
	if (opt) {
		if (emerg_file)
			emerg_file = freopen(opt, "a", emerg_file);
		else
			emerg_file = fopen(opt, "a");
		if (!emerg_file)
			fprintf(stderr, "log:open: %s\n", strerror(errno));
	} else if (emerg_file) {
		fclose(emerg_file);
		emerg_file = NULL;
	}

	opt = conf_get_opt("log", "log-debug");
	if (opt) {
		if (debug_file)
			debug_file = freopen(opt, "a", debug_file);
		else
			debug_file = fopen(opt, "a");
		if (!debug_file)
			fprintf(stderr, "log:open: %s\n", strerror(errno));
	} else if (debug_file) {
		fclose(debug_file);
		debug_file = NULL;
	}
}

static void log_init(void)
{
	pthread_key_create(&pth_key, stat_buf_free);

	config_load();

	signal(SIGHUP, sighup);
}

DEFINE_INIT(0, log_init);

