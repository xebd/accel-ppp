#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <features.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "triton.h"
#include "log.h"
#include "events.h"
#include "ap_session.h"
#include "backup.h"
#include "iputils.h"
#include "spinlock.h"
#include "mempool.h"
#include "memdebug.h"

#define SID_SOURCE_SEQ 0
#define SID_SOURCE_URANDOM 1

static int conf_sid_ucase;
static int conf_single_session = -1;
static int conf_sid_source;

pthread_rwlock_t __export ses_lock = PTHREAD_RWLOCK_INITIALIZER;
__export LIST_HEAD(ses_list);

#if __WORDSIZE == 32
static spinlock_t seq_lock;
#endif

int __export sock_fd;
int __export sock6_fd;
int __export urandom_fd;
int __export ap_shutdown;

static long long unsigned seq;

struct ap_session_stat __export ap_session_stat;

static void (*shutdown_cb)(void);

static void generate_sessionid(struct ap_session *ses);

void __export ap_session_init(struct ap_session *ses)
{
	memset(ses, 0, sizeof(*ses));
	INIT_LIST_HEAD(&ses->pd_list);
	ses->ifindex = -1;
}

void __export ap_session_set_ifindex(struct ap_session *ses)
{
	struct rtnl_link_stats stats;

	if (iplink_get_stats(ses->ifindex, &stats))
		log_ppp_warn("failed to get interface statistics\n");
	else {
		ses->acct_rx_packets_i = stats.rx_packets;
		ses->acct_tx_packets_i = stats.tx_packets;
		ses->acct_rx_bytes_i = stats.rx_bytes;
		ses->acct_tx_bytes_i = stats.tx_bytes;
	}
}

int __export ap_session_starting(struct ap_session *ses)
{
	struct ifreq ifr;

	if (ap_shutdown)
		return -1;

	if (ses->ifindex == -1 && ses->ifname[0]) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, ses->ifname);

		if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
			log_ppp_error("ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
			return -1;
		}
		ses->ifindex = ifr.ifr_ifindex;
	}
	
	if (ses->ifindex != -1)
		ap_session_set_ifindex(ses);

	if (ses->state != AP_STATE_RESTORE) {
		ses->start_time = time(NULL);
		ses->idle_time = ses->start_time;
		generate_sessionid(ses);

		ses->state = AP_STATE_STARTING;
	}
	
	__sync_add_and_fetch(&ap_session_stat.starting, 1);

	pthread_rwlock_wrlock(&ses_lock);
	list_add_tail(&ses->entry, &ses_list);
	pthread_rwlock_unlock(&ses_lock);
	
	triton_event_fire(EV_SES_STARTING, ses);

	return 0;
}

void __export ap_session_activate(struct ap_session *ses)
{
	if (ap_shutdown)
		return;

	ap_session_ifup(ses);

	ses->state = AP_STATE_ACTIVE;
	__sync_sub_and_fetch(&ap_session_stat.starting, 1);
	__sync_add_and_fetch(&ap_session_stat.active, 1);

#ifdef USE_BACKUP
	if (!ses->backup)
		backup_save_session(ses);
#endif
}

void __export ap_session_finished(struct ap_session *ses)
{
	ses->terminated = 1;

	ap_session_read_stats(ses, NULL);
	
	triton_event_fire(EV_SES_PRE_FINISHED, ses);

	pthread_rwlock_wrlock(&ses_lock);
	list_del(&ses->entry);
	pthread_rwlock_unlock(&ses_lock);

	switch (ses->state) {
		case AP_STATE_ACTIVE:
			__sync_sub_and_fetch(&ap_session_stat.active, 1);
			break;
		case AP_STATE_RESTORE:
		case AP_STATE_STARTING:
			__sync_sub_and_fetch(&ap_session_stat.starting, 1);
			break;
		case AP_STATE_FINISHING:
			__sync_sub_and_fetch(&ap_session_stat.finishing, 1);
			break;
	}

	triton_event_fire(EV_SES_FINISHED, ses);
	ses->ctrl->finished(ses);

	if (ses->username) {
		_free(ses->username);
		ses->username = NULL;
	}

	if (ses->ipv4_pool_name) {
		_free(ses->ipv4_pool_name);
		ses->ipv4_pool_name = NULL;
	}
	
	if (ses->ipv6_pool_name) {
		_free(ses->ipv6_pool_name);
		ses->ipv6_pool_name = NULL;
	}

#ifdef USE_BACKUP
	if (ses->backup)
		ses->backup->storage->free(ses->backup);
#endif
	
	if (ap_shutdown && !ap_session_stat.starting && !ap_session_stat.active && !ap_session_stat.finishing) {
		if (shutdown_cb)
			shutdown_cb();
		else
			kill(getpid(), SIGTERM);
	}
}

void __export ap_session_terminate(struct ap_session *ses, int cause, int hard)
{
	if (ses->terminated)
		return;

	if (!ses->stop_time)
		time(&ses->stop_time);

	if (!ses->terminate_cause)
		ses->terminate_cause = cause;

	if (ses->terminating) {
		if (hard)
			ses->ctrl->terminate(ses, hard);
		return;
	}
	
	if (ses->state == AP_STATE_ACTIVE)
		__sync_sub_and_fetch(&ap_session_stat.active, 1);
	else
		__sync_sub_and_fetch(&ap_session_stat.starting, 1);

	__sync_add_and_fetch(&ap_session_stat.finishing, 1);
	ses->terminating = 1;
	ses->state = AP_STATE_FINISHING;

	log_ppp_debug("terminate\n");

	ap_session_ifdown(ses);
	ap_session_read_stats(ses, NULL);

	triton_event_fire(EV_SES_FINISHING, ses);
			
	ses->ctrl->terminate(ses, hard);
}

void ap_shutdown_soft(void (*cb)(void))
{
	ap_shutdown = 1;
	shutdown_cb = cb;

	if (!ap_session_stat.starting && !ap_session_stat.active && !ap_session_stat.finishing) {
		if (shutdown_cb)
			shutdown_cb();
		else
			kill(getpid(), SIGTERM);
	}
}

static void generate_sessionid(struct ap_session *ses)
{
	if (conf_sid_source == SID_SOURCE_SEQ) {
		unsigned long long sid;
#if __WORDSIZE == 32
		spin_lock(&seq_lock);
		sid = ++seq;
		spin_unlock(&seq_lock);
#else
		sid = __sync_add_and_fetch(&seq, 1);
#endif

		if (conf_sid_ucase)
			sprintf(ses->sessionid, "%016llX", sid);
		else
			sprintf(ses->sessionid, "%016llx", sid);
	} else {
		uint8_t sid[AP_SESSIONID_LEN/2];
		int i;
		read(urandom_fd, sid, AP_SESSIONID_LEN/2);
		for (i = 0; i < AP_SESSIONID_LEN/2; i++) {
			if (conf_sid_ucase)
				sprintf(ses->sessionid + i*2, "%02X", sid[i]);
			else
				sprintf(ses->sessionid + i*2, "%02x", sid[i]);
		}
	}
}

int __export ap_session_read_stats(struct ap_session *ses, struct rtnl_link_stats *stats)
{
	struct rtnl_link_stats lstats;
	time_t t;

	if (!stats)
		stats = &lstats;

	time(&t);

	if (iplink_get_stats(ses->ifindex, stats)) {
		log_ppp_warn("failed to get interface statistics\n");
		return -1;
	}
	
	stats->rx_packets -= ses->acct_rx_packets_i;
	stats->tx_packets -= ses->acct_tx_packets_i;
	stats->rx_bytes -= ses->acct_rx_bytes_i;
	stats->tx_bytes -= ses->acct_tx_bytes_i;

	if (stats->rx_bytes != ses->acct_rx_bytes || stats->tx_bytes != ses->acct_tx_bytes)
		time(&ses->idle_time);

	if (stats->rx_bytes < ses->acct_rx_bytes)
		ses->acct_input_gigawords++;
	ses->acct_rx_bytes = stats->rx_bytes;

	if (stats->tx_bytes < ses->acct_tx_bytes)
		ses->acct_output_gigawords++;
	ses->acct_tx_bytes = stats->tx_bytes;

	return 0;
}

static void __terminate_sec(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REQUEST, 0);
}

int __export ap_session_check_single(const char *username)
{
	struct ap_session *ses;

	if (conf_single_session >= 0) {
		pthread_rwlock_rdlock(&ses_lock);
		list_for_each_entry(ses, &ses_list, entry) {
			if (ses->username && !strcmp(ses->username, username)) {
				if (conf_single_session == 0) {
					pthread_rwlock_unlock(&ses_lock);
					log_ppp_info1("%s: second session denied\n", username);
					return -1;
				} else {
					if (conf_single_session == 1) {
						ap_session_ifdown(ses);
						triton_context_call(ses->ctrl->ctx, (triton_event_func)__terminate_sec, ses);
					}
				}
			}
		}
		pthread_rwlock_unlock(&ses_lock);
	}

	return 0;
}

static void save_seq(void)
{
	FILE *f;
	char *opt = conf_get_opt("common", "seq-file");
	if (!opt)
		opt = "/var/run/accel-ppp/seq";

	f = fopen(opt, "w");
	if (f) {
		fprintf(f, "%llu", seq);
		fclose(f);
	}
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("common", "sid-case");
	if (opt) {
		if (!strcmp(opt, "upper"))
			conf_sid_ucase = 1;
		else if (strcmp(opt, "lower"))
			log_emerg("sid-case: invalid format\n");
	}
	
	opt = conf_get_opt("common", "single-session");
	if (opt) {
		if (!strcmp(opt, "deny"))
			conf_single_session = 0;
		else if (!strcmp(opt, "replace"))
			conf_single_session = 1;
	} else 
		conf_single_session = -1;
	
	opt = conf_get_opt("common", "sid-source");
	if (opt) {
		if (strcmp(opt, "seq") == 0)
			conf_sid_source = SID_SOURCE_SEQ;
		else if (strcmp(opt, "urandom") == 0)
			conf_sid_source = SID_SOURCE_URANDOM;
		else
			log_error("unknown sid-source\n");
	} else
		conf_sid_source = SID_SOURCE_SEQ;
}

static void init(void)
{
	const char *opt;
	FILE *f;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		perror("socket");
		_exit(EXIT_FAILURE);
	}
	
	fcntl(sock_fd, F_SETFD, fcntl(sock_fd, F_GETFD) | FD_CLOEXEC);

	sock6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock6_fd < 0)
		log_warn("ppp: kernel doesn't support ipv6\n");
	else
		fcntl(sock6_fd, F_SETFD, fcntl(sock6_fd, F_GETFD) | FD_CLOEXEC);

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		log_emerg("failed to open /dev/urandom: %s\n", strerror(errno));
		return;
	}
	
	fcntl(urandom_fd, F_SETFD, fcntl(urandom_fd, F_GETFD) | FD_CLOEXEC);

	opt = conf_get_opt("common", "seq-file");
	if (!opt)
		opt = "/var/run/accel-ppp/seq";
	
	f = fopen(opt, "r");
	if (f) {
		fscanf(f, "%llu", &seq);
		fclose(f);
	} else
		seq = (unsigned long long)random() * (unsigned long long)random();

	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	atexit(save_seq);
}

DEFINE_INIT(2, init);

