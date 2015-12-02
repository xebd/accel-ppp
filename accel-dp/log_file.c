#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <aio.h>
#include <signal.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include "init.h"
#include "common.h"
#include "conf_file.h"

#include "log.h"

//static const char* level_name[]={"  msg", "error", " warn", " info", " info", "debug"};
static int log_fd = -1;
static int conf_buf_size;

#define THREADED_LOG_FILE

#ifdef THREADED_LOG_FILE
static LIST_HEAD(log_queue);
static LIST_HEAD(log_buf);
static int buf_size;
static int buf_cnt;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond;
static pthread_t thr;
static int need_reopen;
#endif

static void make_hdr(struct log_msg *msg)
{
	struct tm tm;

	tm = *localtime(&msg->timestamp.tv_sec);

	msg->hdr->len = sprintf(msg->hdr->msg, "[%i-%02i-%02i %02i:%02i:%02i]: ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec/*, (int)msg->timestamp.tv_usec/100000*/);
}

/*static void __log(struct log_msg *msg)
{
	struct log_chunk *chunk;
	struct iovec iov[IOV_MAX];
	int iov_cnt;
	struct list_head *pos = msg->chunks->next;

	make_hdr(msg);

	iov[0].iov_base = msg->hdr->msg;
	iov[0].iov_len = msg->hdr->len;
	iov_cnt = 1;

	while (pos != msg->chunks) {
		chunk = list_entry(pos, typeof(*chunk), entry);
		iov[iov_cnt].iov_base = chunk->msg;
		iov[iov_cnt].iov_len = chunk->len;
		iov_cnt++;
		pos = pos->next;

		if (iov_cnt == IOV_MAX || pos == msg->chunks) {
			writev(log_fd, iov, iov_cnt);
			iov_cnt = 0;
		}
	}

	log_free_msg(msg);
}*/

static void write_buf()
{
	struct log_msg *msg;
	struct log_chunk *chunk;
	struct iovec iov[IOV_MAX];
	int n = 0;

	list_for_each_entry(msg, &log_buf, entry) {
		iov[n].iov_base = msg->hdr->msg;
		iov[n].iov_len = msg->hdr->len;
		n++;

		list_for_each_entry(chunk, msg->chunks, entry) {
			iov[n].iov_base = chunk->msg;
			iov[n].iov_len = chunk->len;
			n++;

			if (n >= IOV_MAX - 2) {
				writev(log_fd, iov, n);
				n = 0;
			}
		}
	}

	if (n)
		writev(log_fd, iov, n);

	while (!list_empty(&log_buf)) {
		msg = list_entry(log_buf.next, typeof(*msg), entry);
		list_del(&msg->entry);
		log_free_msg(msg);
	}

	buf_size = 0;
	buf_cnt = 0;
}

static void do_log(struct log_msg *msg)
{
#ifndef THREADED_LOG_FILE
	struct log_chunk *chunk;
#endif

	if (log_fd < 0 || msg->level == 5) {
		log_free_msg(msg);
		return;
	}

	make_hdr(msg);

#ifdef THREADED_LOG_FILE
	pthread_mutex_lock(&lock);
	list_add_tail(&msg->entry, &log_queue);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
#else
	buf_cnt++;
	buf_size += msg->hdr->len;

	list_for_each_entry(chunk, msg->chunks, entry) {
		buf_size += chunk->len;
		buf_cnt++;
	}

	if (buf_cnt > IOV_MAX - 16 || buf_size >= conf_buf_size)
		write_buf();
#endif
}

static void __reopen(void)
{
	const char *fname = conf_get_opt("log", "log-file");

	if (log_fd >= 0) {
		close(log_fd);
		log_fd = -1;
	}

	if (!fname)
		return;

	log_fd = open(fname, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (log_fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return;
	}

	fcntl(log_fd, F_SETFD, FD_CLOEXEC);
}

static void reopen(void)
{
#ifdef THREADED_LOG_FILE
	pthread_mutex_lock(&lock);
	need_reopen = 1;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
#else
	__reopen();
#endif
}

#ifdef THREADED_LOG_FILE
static void *log_thread(void *ignored)
{
	struct log_msg *msg;
	struct log_chunk *chunk;

	pthread_mutex_lock(&lock);
	while (1) {
		if (need_reopen) {
			need_reopen = 0;
			__reopen();
		}
		while (!list_empty(&log_queue)) {
			msg = list_entry(log_queue.next, typeof(*msg), entry);
			list_move_tail(&msg->entry, &log_buf);

			buf_cnt++;
			buf_size += msg->hdr->len;

			list_for_each_entry(chunk, msg->chunks, entry) {
				buf_size += chunk->len;
				buf_cnt++;
			}

			if (buf_cnt > IOV_MAX - 16 || buf_size >= conf_buf_size) {
				pthread_mutex_unlock(&lock);
				write_buf();
				pthread_mutex_lock(&lock);
			}
		}
		pthread_cond_wait(&cond, &lock);
	}
	pthread_mutex_unlock(&lock);

	return NULL;
}
#endif

static struct log_target target = {
	.log = do_log,
	.reopen = reopen,
};

static void load_config()
{
	const char *opt = conf_get_opt("log", "buffer");
	if (opt)
		conf_buf_size = atoi(opt);
	else
		conf_buf_size = 0;
}

static void init(void)
{
	if (!conf_get_opt("log", "log-file"))
		return;

	load_config();

	log_register_target(&target);
	reopen();

#ifdef THREADED_LOG_FILE
	pthread_cond_init(&cond, NULL);
	pthread_create(&thr, NULL, log_thread, NULL);
#endif
}

DEFINE_INIT(2, init);
