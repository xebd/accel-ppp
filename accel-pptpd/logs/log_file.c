#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#include "log.h"
#include "ppp.h"
#include "spinlock.h"

#define RED_COLOR     "\033[1;31m"
#define GREEN_COLOR   "\033[1;32m"
#define YELLOW_COLOR  "\033[1;33m"
#define BLUE_COLOR  	"\033[1;34m"
#define NORMAL_COLOR  "\033[0;39m"

struct log_file_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	struct list_head msgs;
	struct log_msg_t *cur_msg;
	struct log_chunk_t *cur_chunk;
	int cur_pos;
	spinlock_t lock;
	int sleeping:1;
	int need_free:1;
	struct log_file_pd_t *lpd;
};

struct log_file_pd_t
{
	struct ppp_pd_t pd;
	struct log_file_t lf;
};

static int conf_color;
static int conf_per_session;
static char *conf_per_user_dir;
static char *conf_per_session_dir;

static const char* level_name[]={"  msg", "error", " warn", " info", "debug"};
static const char* level_color[]={NORMAL_COLOR, RED_COLOR, YELLOW_COLOR, GREEN_COLOR, BLUE_COLOR};

static void *pd_key1;
static void *pd_key2;
static struct log_file_t *log_file;

static int log_write(struct triton_md_handler_t *h);

static int log_file_init(struct log_file_t *lf, const char *fname)
{
	spinlock_init(&lf->lock);
	lf->sleeping = 1;
	INIT_LIST_HEAD(&lf->msgs);
	lf->hnd.write = log_write;

	lf->hnd.fd = open(fname, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (lf->hnd.fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return -1;
	} 
	
	lseek(lf->hnd.fd, 0, SEEK_END);
	
	if (fcntl(lf->hnd.fd, F_SETFL, O_NONBLOCK)) {
			log_emerg("log_file: cann't to set nonblocking mode: %s\n", strerror(errno));
			goto out_err;
	}
	
	if (triton_context_register(&lf->ctx, NULL))
		goto out_err;
	triton_md_register_handler(&lf->ctx, &lf->hnd);
	return 0;

out_err:
	close(lf->hnd.fd);
	return -1;
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
static int write_chunk(int fd, struct log_chunk_t *chunk, int pos)
{
	int n;

	while (1) {
		n = write(fd, chunk->msg + pos, chunk->len - pos);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return pos;
			log_emerg("log_file: write: %s\n", strerror(errno));
			break;
		}
		pos += n;
		if (pos == chunk->len)
			return 0;
	}
	return -1;
}
static int write_msg(struct log_file_t *lf)
{
	if (!lf->cur_chunk)
		lf->cur_chunk = lf->cur_msg->hdr;
	
	if (lf->cur_chunk == lf->cur_msg->hdr) {
		lf->cur_pos = write_chunk(lf->hnd.fd, lf->cur_chunk, lf->cur_pos);
		if (lf->cur_pos < 0)
			goto out;
		if (lf->cur_pos)
			return -1;
		lf->cur_chunk = list_entry(lf->cur_msg->chunks->next, typeof(*lf->cur_chunk), entry);
	}

	while(&lf->cur_chunk->entry != lf->cur_msg->chunks) {
		lf->cur_pos = write_chunk(lf->hnd.fd, lf->cur_chunk, lf->cur_pos);
		if (lf->cur_pos < 0)
			break;
		if (lf->cur_pos)
			return -1;
		lf->cur_chunk = list_entry(lf->cur_chunk->entry.next, typeof(*lf->cur_chunk), entry);
	}

out:
	log_free_msg(lf->cur_msg);
	lf->cur_chunk = NULL;
	lf->cur_msg = NULL;
	lf->cur_pos = 0;
	return 0;
}

static int log_write(struct triton_md_handler_t *h)
{
	struct log_file_t *lf = container_of(h, typeof(*lf), hnd);

	if (lf->cur_msg)
		if (write_msg(lf))
			return 0;

	while (1) {
		spin_lock(&lf->lock);
		if (!list_empty(&lf->msgs)) {
			lf->cur_msg = list_entry(lf->msgs.next, typeof(*lf->cur_msg), entry);
			list_del(&lf->cur_msg->entry);
			spin_unlock(&lf->lock);

			if (write_msg(lf))
				return 0;
			
			continue;
		}
		if (lf->need_free) {
			spin_unlock(&lf->lock);
			triton_md_unregister_handler(&lf->hnd);
			close(lf->hnd.fd);
			triton_context_unregister(&lf->ctx);
			free(lf->lpd);
			return 1;
		}
		lf->sleeping = 1;
		spin_unlock(&lf->lock);
		triton_md_disable_handler(&lf->hnd, MD_MODE_WRITE);
		return 0;
	}
}

static void log_wakeup(struct log_file_t *lf)
{
	if (log_write(&lf->hnd))
		return ;

	if (!lf->sleeping)
		triton_md_enable_handler(&lf->hnd, MD_MODE_WRITE);
}

static void log_queue(struct log_file_t *lf, struct log_msg_t *msg)
{
	int r;
	spin_lock(&lf->lock);
	list_add_tail(&msg->entry, &lf->msgs);
	r = lf->sleeping;
	lf->sleeping = 0;
	spin_unlock(&lf->lock);

	if (r)
		triton_context_call(&lf->ctx, (void (*)(void *))log_wakeup, lf);
}

static void general_log(struct log_msg_t *msg)
{
	if (!log_file)
		return;
	set_hdr(msg, NULL);
	log_queue(log_file, msg);
}

static void general_session_log(struct ppp_t *ppp, struct log_msg_t *msg)
{
	if (!log_file)
		return;
	set_hdr(msg, ppp);
	log_queue(log_file, msg);
}

static struct log_file_pd_t *find_pd(struct ppp_t *ppp, void *pd_key)
{
	struct ppp_pd_t *pd;
	struct log_file_pd_t *lpd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == pd_key) {
			lpd = container_of(pd, typeof(*lpd), pd);
			return lpd;
		}
	}
	//log_emerg("log:BUG: pd not found\n");
	//abort();
	return NULL;
}

static void session_log(struct ppp_t *ppp, struct log_msg_t *msg, void *pd_key)
{
	struct log_file_pd_t *lpd  = find_pd(ppp, pd_key);

	if (!lpd)
		return;

	set_hdr(msg, ppp);
	log_queue(&lpd->lf, msg);
}

static void per_user_session_log(struct ppp_t *ppp, struct log_msg_t *msg)
{
	session_log(ppp, msg, &pd_key1);
}

static void per_session_log(struct ppp_t *ppp, struct log_msg_t *msg)
{
	session_log(ppp, msg, &pd_key2);
}

static void per_user_session_start(struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;
	char *fname;
	
	fname = malloc(PATH_MAX + 32);
	if (!fname) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	lpd = malloc(sizeof(*lpd));
	if (!lpd) {
		log_emerg("log_file: out of memory\n");
		goto out_err;
	}
	
	memset(lpd, 0, sizeof(*lpd));
	lpd->pd.key = &pd_key1;
	lpd->lf.hnd.fd = -1;
	lpd->lf.lpd = lpd;

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

	if (log_file_init(&lpd->lf, fname))
		goto out_err;
	

	list_add_tail(&lpd->pd.entry, &ppp->pd_list);
	free(fname);
	return;

out_err:
	free(fname);
	if (lpd)
		free(lpd);
}
static void per_session_start(struct ppp_t *ppp)
{
	struct log_file_pd_t *lpd;
	char *fname;
	
	fname = malloc(PATH_MAX + 32);
	if (!fname) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	lpd = malloc(sizeof(*lpd));
	if (!lpd) {
		log_emerg("log_file: out of memory\n");
		goto out_err;
	}
	
	memset(lpd, 0, sizeof(*lpd));
	lpd->pd.key = &pd_key2;
	lpd->lf.hnd.fd = -1;
	lpd->lf.lpd = lpd;

	strcpy(fname, conf_per_session_dir);
	strcat(fname, "/");
	strcat(fname, ppp->sessionid);
	strcat(fname, ".log");


	if (log_file_init(&lpd->lf, fname))
		goto out_err;
	
	list_add_tail(&lpd->pd.entry, &ppp->pd_list);
	free(fname);
	return;

out_err:
	free(fname);
	if (lpd)
		free(lpd);
}

static void session_stop(struct ppp_t *ppp, void *pd_key)
{
	struct log_file_pd_t *lpd = find_pd(ppp, pd_key);
	int r;

	spin_lock(&lpd->lf.lock);
	r = lpd->lf.sleeping;
	lpd->lf.sleeping = 0;
	lpd->lf.need_free = 1;
	spin_unlock(&lpd->lf.lock);

	if (r)
		triton_context_call(&lpd->lf.ctx, (void (*)(void *))log_wakeup, &lpd->lf);
}

static void per_user_session_stop(struct ppp_t *ppp)
{
	session_stop(ppp, &pd_key1);
}

static void per_session_stop(struct ppp_t *ppp)
{
	session_stop(ppp, &pd_key2);
}

static struct log_target_t target = 
{
	.log = general_log,
};

static struct log_target_t per_user_target = 
{
	.session_log = per_user_session_log,
	.session_start = per_user_session_start,
	.session_stop = per_user_session_stop,
};

static struct log_target_t per_session_target = 
{
	.session_log = per_session_log,
	.session_start = per_session_start,
	.session_stop = per_session_stop,
};


static void __init init(void)
{
	char *opt;
	
	opt = conf_get_opt("log","color");
	if (opt && atoi(opt) > 0)
		conf_color = 1;
	
	opt = conf_get_opt("log", "log-file");
	if (opt) {
		log_file = malloc(sizeof(*log_file));
		memset(log_file, 0, sizeof(*log_file));
		if (log_file_init(log_file, opt)) {
			free(log_file);
			log_file = NULL;
		}
	}
	
	opt = conf_get_opt("log", "per-user-dir");
	if (opt)
		conf_per_user_dir = opt;

	opt = conf_get_opt("log", "per-session-dir");
	if (opt)
		conf_per_session_dir = opt;

	opt = conf_get_opt("log", "per-session");
	if (opt && atoi(opt) > 0)
		conf_per_session = 1;

	if (conf_per_user_dir)
		log_register_target(&per_user_target);
	
	if (conf_per_session_dir)
		log_register_target(&per_session_target);
	
	if (log_file) {
		if (!conf_per_user_dir && !conf_per_session_dir)
			target.session_log = general_session_log;
		log_register_target(&target);
	}
}

