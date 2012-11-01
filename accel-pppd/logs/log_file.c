#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <aio.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "log.h"
#include "events.h"
#include "ppp.h"
#include "spinlock.h"
#include "mempool.h"

#include "memdebug.h"

#define LOG_BUF_SIZE 16*1024

#define RED_COLOR     "\033[1;31m"
#define GREEN_COLOR   "\033[1;32m"
#define YELLOW_COLOR  "\033[1;33m"
#define BLUE_COLOR  	"\033[1;34m"
#define NORMAL_COLOR  "\033[0;39m"

struct log_file_t
{
	struct list_head entry;
	struct list_head msgs;
	spinlock_t lock;
	int need_free:1;
	int queued:1;
	struct log_file_pd_t *lpd;

	int fd;
	int new_fd;
	off_t offset;
	unsigned long magic;
};

struct log_file_pd_t
{
	struct ppp_pd_t pd;
	struct log_file_t lf;
	unsigned long tmp;
};

struct fail_log_pd_t
{
	struct ppp_pd_t pd;
	struct list_head msgs;
};


static int conf_color;
static int conf_per_session;
static char *conf_per_user_dir;
static char *conf_per_session_dir;
static int conf_copy;
static int conf_fail_log;

static const char* level_name[]={"  msg", "error", " warn", " info", " info", "debug"};
static const char* level_color[]={NORMAL_COLOR, RED_COLOR, YELLOW_COLOR, GREEN_COLOR, GREEN_COLOR, BLUE_COLOR};

static void *pd_key1;
static void *pd_key2;
static void *pd_key3;

static struct log_file_t *log_file;
static struct log_file_t *fail_log_file;

static mempool_t lpd_pool;
static mempool_t fpd_pool;
static char *log_buf;

static struct aiocb aiocb = {
	.aio_lio_opcode = LIO_WRITE,
	.aio_sigevent.sigev_notify = SIGEV_SIGNAL,
	.aio_sigevent.sigev_signo = SIGIO,
};

static LIST_HEAD(lf_queue);
static spinlock_t lf_queue_lock = SPINLOCK_INITIALIZER;
static int lf_queue_sleeping = 1;

static unsigned long temp_seq;

static void send_next_chunk();


static void log_file_init(struct log_file_t *lf)
{
	spinlock_init(&lf->lock);
	INIT_LIST_HEAD(&lf->msgs);
	lf->fd = -1;
	lf->new_fd = -1;
}

static int log_file_open(struct log_file_t *lf, const char *fname)
{
	lf->fd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (lf->fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return -1;
	} 
	
	fcntl(lf->fd, F_SETFD, fcntl(lf->fd, F_GETFD) | FD_CLOEXEC);
	
	lf->offset = lseek(lf->fd, 0, SEEK_END);
	
	return 0;
}

static void sigio(int num, siginfo_t *si, void *uc)
{
	struct log_file_t *lf;
	int n;

	if (si->si_signo != SIGIO)
		return;

	if (si->si_code != SI_ASYNCIO) {
		if (aio_write(&aiocb))
			log_emerg("log_file: aio_write: %s\n", strerror(errno));
		return;
	}

	lf = (struct log_file_t *)si->si_ptr;

	n = aio_return(&aiocb);
	if (n < 0)
		log_emerg("log_file: %s\n", strerror(aio_error(&aiocb)));
	else if (n != aiocb.aio_nbytes)
		log_emerg("log_file: short write %p %i %lu\n", lf, n, aiocb.aio_nbytes);

	spin_lock(&lf->lock);
	lf->offset += n;
	if (list_empty(&lf->msgs)) {
		if (lf->need_free) {
			spin_unlock(&lf->lock);
			close(lf->fd);
			mempool_free(lf->lpd);
		} else {
			lf->queued = 0;
			spin_unlock(&lf->lock);
		}
	} else {
		spin_unlock(&lf->lock);

		spin_lock(&lf_queue_lock);
		list_add_tail(&lf->entry, &lf_queue);
		spin_unlock(&lf_queue_lock);
	}
	
	send_next_chunk();
}

static int dequeue_log(struct log_file_t *lf)
{
	int n, pos = 0;
	struct log_msg_t *msg;
	struct log_chunk_t *chunk;

	while (1) {
		spin_lock(&lf->lock);
		if (list_empty(&lf->msgs)) {
			spin_unlock(&lf->lock);
			return pos;
		}
		msg = list_entry(lf->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);
		spin_unlock(&lf->lock);

		if (pos + msg->hdr->len > LOG_BUF_SIZE)
			goto overrun;
		memcpy(log_buf + pos, msg->hdr->msg, msg->hdr->len);
		n = msg->hdr->len;

		list_for_each_entry(chunk, msg->chunks, entry) {
			if (pos + n + chunk->len > LOG_BUF_SIZE)
				goto overrun;
			memcpy(log_buf + pos + n, chunk->msg, chunk->len);
			n += chunk->len;
		}

		log_free_msg(msg);
		pos += n;
	}

overrun:
	spin_lock(&lf->lock);
	list_add(&msg->entry, &lf->msgs);
	spin_unlock(&lf->lock);

	return pos;
}

static void send_next_chunk(void)
{
	struct log_file_t *lf;

	spin_lock(&lf_queue_lock);
	if (list_empty(&lf_queue)) {
		lf_queue_sleeping = 1;
		spin_unlock(&lf_queue_lock);
		return;
	}
	lf = list_entry(lf_queue.next, typeof(*lf), entry);
	
	list_del(&lf->entry);

	spin_unlock(&lf_queue_lock);

	if (lf->new_fd != -1) {
		close(lf->fd);
		lf->fd = lf->new_fd;
		lf->new_fd = -1;
		lf->offset = 0;
	}

	aiocb.aio_fildes = lf->fd;
	aiocb.aio_offset = lf->offset;
	aiocb.aio_sigevent.sigev_value.sival_ptr = lf;
	aiocb.aio_nbytes = dequeue_log(lf);

	if (aio_write(&aiocb))
		log_emerg("log_file: aio_write: %s\n", strerror(errno));
}

static void queue_lf(struct log_file_t *lf)
{
	int r;

	spin_lock(&lf_queue_lock);
	list_add_tail(&lf->entry, &lf_queue);
	r = lf_queue_sleeping;
	lf_queue_sleeping = 0;
	spin_unlock(&lf_queue_lock);

	if (r)
		send_next_chunk();
}

static void queue_log(struct log_file_t *lf, struct log_msg_t *msg)
{
	int r;

	spin_lock(&lf->lock);
	list_add_tail(&msg->entry, &lf->msgs);
	if (lf->fd != -1) {
		r = lf->queued;
		lf->queued = 1;
	} else
		r = 1;
	spin_unlock(&lf->lock);

	if (!r)
		queue_lf(lf);
}

static void queue_log_list(struct log_file_t *lf, struct list_head *l)
{
	int r;
	struct log_msg_t *msg;

	spin_lock(&lf->lock);
	while (!list_empty(l)) {
		msg = list_entry(l->next, typeof(*msg), entry);
		list_del(&msg->entry);
		list_add_tail(&msg->entry, &lf->msgs);
	}
	if (lf->fd != -1) {
		r = lf->queued;
		lf->queued = 1;
	} else
		r = 1;
	spin_unlock(&lf->lock);

	if (!r)
		queue_lf(lf);
}


static void set_hdr(struct log_msg_t *msg, struct ppp_t *ppp)
{
	struct tm tm;
	char timestamp[32];

	localtime_r(&msg->timestamp.tv_sec, &tm);

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);
	sprintf(msg->hdr->msg, "%s[%s]: %s: %s%s%s", conf_color ? level_color[msg->level] : "", 
		timestamp, level_name[msg->level],
		ppp ? ppp->ifname : "",
		ppp ? ": " : "",
		conf_color ? NORMAL_COLOR : "");
	msg->hdr->len = strlen(msg->hdr->msg);
}

static void general_log(struct log_target_t *t, struct log_msg_t *msg, struct ppp_t *ppp)
{
	if (ppp && !conf_copy) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ppp);
	queue_log(log_file, msg);
}

static struct ppp_pd_t *find_pd(struct ppp_t *ppp, void *pd_key)
{
	struct ppp_pd_t *pd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == pd_key) {
			return pd;
		}
	}

	return NULL;
}

static struct log_file_pd_t *find_lpd(struct ppp_t *ppp, void *pd_key)
{
	struct ppp_pd_t *pd = find_pd(ppp, pd_key);

	if (!pd)
		return NULL;

	return container_of(pd, struct log_file_pd_t, pd);
}

static struct fail_log_pd_t *find_fpd(struct ppp_t *ppp, void *pd_key)
{
	struct ppp_pd_t *pd = find_pd(ppp, pd_key);

	if (!pd)
		return NULL;

	return container_of(pd, struct fail_log_pd_t, pd);
}


static void per_user_log(struct log_target_t *t, struct log_msg_t *msg, struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;

	if (!ppp) {
		log_free_msg(msg);
		return;
	}

	lpd = find_lpd(ppp, &pd_key1);

	if (!lpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ppp);
	queue_log(&lpd->lf, msg);
}

static void per_session_log(struct log_target_t *t, struct log_msg_t *msg, struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;
	
	if (!ppp) {
		log_free_msg(msg);
		return;
	}

	lpd = find_lpd(ppp, &pd_key2);

	if (!lpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ppp);
	queue_log(&lpd->lf, msg);
}

static void fail_log(struct log_target_t *t, struct log_msg_t *msg, struct ppp_t *ppp)
{
	struct fail_log_pd_t *fpd;
	
	if (!ppp || !conf_fail_log) {
		log_free_msg(msg);
		return;
	}

	fpd = find_fpd(ppp, &pd_key3);

	if (!fpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ppp);
	list_add_tail(&msg->entry, &fpd->msgs);
}

static void fail_reopen(void)
{
	char *fname = conf_get_opt("log", "log-fail-file");
 	int fd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return;
	}
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
	fail_log_file->new_fd = fd;
}


static void general_reopen(void)
{
	char *fname = conf_get_opt("log", "log-file");
 	int fd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return;
	}
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
	log_file->new_fd = fd;
}

static void free_lpd(struct log_file_pd_t *lpd)
{
	struct log_msg_t *msg;

	spin_lock(&lpd->lf.lock);
	list_del(&lpd->pd.entry);
	lpd->lf.need_free = 1;
	if (lpd->lf.queued)
		spin_unlock(&lpd->lf.lock);
	else {
		while (!list_empty(&lpd->lf.msgs)) {
			msg = list_entry(lpd->lf.msgs.next, typeof(*msg), entry);
			list_del(&msg->entry);
			log_free_msg(msg);
		}
		if (lpd->lf.fd != -1)
			close(lpd->lf.fd);
		spin_unlock(&lpd->lf.lock);
		mempool_free(lpd);
	}
}

static void ev_ppp_authorized2(struct ppp_t *ppp)
{
	struct fail_log_pd_t *fpd;
	struct log_msg_t *msg;

	fpd = find_fpd(ppp, &pd_key3);
	if (!fpd)
		return;
	
	while (!list_empty(&fpd->msgs)) {
		msg = list_entry(fpd->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);
		log_free_msg(msg);
	}

	list_del(&fpd->pd.entry);
	mempool_free(fpd);
}

static void ev_ppp_authorized1(struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;
	char *fname;

	lpd = find_lpd(ppp, &pd_key1);
	if (!lpd)
		return;
	
	fname = _malloc(PATH_MAX);
	if (!fname) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	strcpy(fname, conf_per_user_dir);
	strcat(fname, "/");
	strcat(fname, ppp->username);
	if (conf_per_session) {
		if (mkdir(fname, S_IRWXU) && errno != EEXIST) {
			log_emerg("log_file: mkdir '%s': %s'\n", fname, strerror(errno));
			goto out_err;
		}
		strcat(fname, "/");
		strcat(fname, ppp->sessionid);
	}
	strcat(fname, ".log");

	if (log_file_open(&lpd->lf, fname))
		goto out_err;

	_free(fname);

	if (!list_empty(&lpd->lf.msgs)) {
		lpd->lf.queued = 1;
		queue_lf(&lpd->lf);
	}

	return;

out_err:
	_free(fname);
	free_lpd(lpd);
}

static void ev_ctrl_started(struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;
	struct fail_log_pd_t *fpd;
	char *fname;

	if (conf_per_user_dir) {
		lpd = mempool_alloc(lpd_pool);
		if (!lpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(lpd, 0, sizeof(*lpd));
		lpd->pd.key = &pd_key1;
		log_file_init(&lpd->lf);
		lpd->lf.lpd = lpd;
		list_add_tail(&lpd->pd.entry, &ppp->pd_list);
	}

	if (conf_per_session_dir) {
		lpd = mempool_alloc(lpd_pool);
		if (!lpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(lpd, 0, sizeof(*lpd));
		lpd->pd.key = &pd_key2;
		log_file_init(&lpd->lf);
		lpd->lf.lpd = lpd;

		fname = _malloc(PATH_MAX);
		if (!fname) {
			mempool_free(lpd);
			log_emerg("log_file: out of memory\n");
			return;
		}

		lpd->tmp = temp_seq++;
		strcpy(fname, conf_per_session_dir);
		strcat(fname, "/tmp");
		sprintf(fname + strlen(fname), "%lu", lpd->tmp);

		if (log_file_open(&lpd->lf, fname)) {
			mempool_free(lpd);
			_free(fname);
			return;
		}

		_free(fname);

		list_add_tail(&lpd->pd.entry, &ppp->pd_list);
	}

	if (conf_fail_log) {
		fpd = mempool_alloc(fpd_pool);
		if (!fpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(fpd, 0, sizeof(*fpd));
		fpd->pd.key = &pd_key3;
		list_add_tail(&fpd->pd.entry, &ppp->pd_list);
		INIT_LIST_HEAD(&fpd->msgs);
	}
}

static void ev_ctrl_finished(struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;
	struct fail_log_pd_t *fpd;
	char *fname;

	fpd = find_fpd(ppp, &pd_key3);
	if (fpd) {
		queue_log_list(fail_log_file, &fpd->msgs);
		list_del(&fpd->pd.entry);
		mempool_free(fpd);
	}

	lpd = find_lpd(ppp, &pd_key1);
	if (lpd)
		free_lpd(lpd);

	lpd = find_lpd(ppp, &pd_key2);
	if (lpd) {
		if (lpd->tmp) {
			fname = _malloc(PATH_MAX);
			if (fname) {
				strcpy(fname, conf_per_session_dir);
				strcat(fname, "/tmp");
				sprintf(fname + strlen(fname), "%lu", lpd->tmp);
				if (unlink(fname))
					log_emerg("log_file: unlink '%s': %s\n", fname, strerror(errno));
				_free(fname);
			} else
				log_emerg("log_file: out of memory\n");
		}
		free_lpd(lpd);
	}
}

static void ev_ppp_starting(struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;
	char *fname1, *fname2;

	lpd = find_lpd(ppp, &pd_key2);
	if (!lpd)
		return;
	
	fname1 = _malloc(PATH_MAX);
	if (!fname1) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	fname2 = _malloc(PATH_MAX);
	if (!fname2) {
		log_emerg("log_file: out of memory\n");
		_free(fname1);
		return;
	}

	strcpy(fname1, conf_per_session_dir);
	strcat(fname1, "/tmp");
	sprintf(fname1 + strlen(fname1), "%lu", lpd->tmp);

	strcpy(fname2, conf_per_session_dir);
	strcat(fname2, "/");
	strcat(fname2, ppp->sessionid);
	strcat(fname2, ".log");

	if (rename(fname1, fname2))
		log_emerg("log_file: rename '%s' to '%s': %s\n", fname1, fname2, strerror(errno));

	lpd->tmp = 0;

	_free(fname1);
	_free(fname2);
}

static struct log_target_t general_target = 
{
	.log = general_log,
	.reopen = general_reopen,
};

static struct log_target_t per_user_target = 
{
	.log = per_user_log,
};

static struct log_target_t per_session_target = 
{
	.log = per_session_log,
};

static struct log_target_t fail_log_target = 
{
	.log = fail_log,
	.reopen = fail_reopen,
};


static void init(void)
{
	char *opt;
	
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGIO);

	struct sigaction sa = {
		.sa_sigaction = sigio,
		.sa_flags = SA_SIGINFO,
		.sa_mask = set,
	};

	lpd_pool = mempool_create(sizeof(struct log_file_pd_t));
	fpd_pool = mempool_create(sizeof(struct fail_log_pd_t));
	log_buf = malloc(LOG_BUF_SIZE);
	aiocb.aio_buf = log_buf;

	if (sigaction(SIGIO, &sa, NULL)) {
		log_emerg("log_file: sigaction: %s\n", strerror(errno));
		return;
	}

	opt = conf_get_opt("log", "log-file");
	if (opt) {
		log_file = malloc(sizeof(*log_file));
		memset(log_file, 0, sizeof(*log_file));
		log_file_init(log_file);
		if (log_file_open(log_file, opt)) {
			free(log_file);
			_exit(EXIT_FAILURE);
		}
	}
	
	opt = conf_get_opt("log", "log-fail-file");
	if (opt) {
		fail_log_file = malloc(sizeof(*fail_log_file));
		memset(fail_log_file, 0, sizeof(*fail_log_file));
		log_file_init(fail_log_file);
		if (log_file_open(fail_log_file, opt)) {
			free(fail_log_file);
			_exit(EXIT_FAILURE);
		}
		conf_fail_log = 1;
	}
	
	opt = conf_get_opt("log","color");
	if (opt && atoi(opt) > 0)
		conf_color = 1;
	
	opt = conf_get_opt("log", "per-user-dir");
	if (opt)
		conf_per_user_dir = _strdup(opt);

	opt = conf_get_opt("log", "per-session-dir");
	if (opt)
		conf_per_session_dir = _strdup(opt);

	opt = conf_get_opt("log", "per-session");
	if (opt && atoi(opt) > 0)
		conf_per_session = 1;
	
	opt = conf_get_opt("log", "copy");
	if (opt && atoi(opt) > 0)
		conf_copy = 1;

	log_register_target(&general_target);
	
	if (conf_per_user_dir) {
		log_register_target(&per_user_target);
		triton_event_register_handler(EV_PPP_AUTHORIZED, (triton_event_func)ev_ppp_authorized1);
	}
	
	if (conf_per_session_dir) {
		log_register_target(&per_session_target);
		triton_event_register_handler(EV_PPP_STARTING, (triton_event_func)ev_ppp_starting);
	}
	
	if (conf_fail_log) {
		log_register_target(&fail_log_target);
		triton_event_register_handler(EV_PPP_AUTHORIZED, (triton_event_func)ev_ppp_authorized2);
	}

	triton_event_register_handler(EV_CTRL_STARTED, (triton_event_func)ev_ctrl_started);
	triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
}

DEFINE_INIT(1, init);
