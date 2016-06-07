#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "linux_ppp.h"

#include "triton.h"

#include "events.h"
#include "ppp.h"
#include "ipdb.h"
#include "log.h"
#include "utils.h"
#include "sigchld.h"
#include "iputils.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

#define ENV_MEM 1024
#define ENV_MAX 16

static char *conf_ip_up = "/etc/ppp/ip-up";
static char *conf_ip_pre_up = "/etc/ppp/ip-pre-up";
static char *conf_ip_down = "/etc/ppp/ip-down";
static char *conf_ip_change = "/etc/ppp/ip-change";
static char *conf_radattr_prefix = "/var/run/radattr";
static int conf_verbose = 0;

static void *pd_key;

struct pppd_compat_pd
{
	struct ap_private pd;
	struct ap_session *ses;
	struct sigchld_handler_t ip_pre_up_hnd;
	struct sigchld_handler_t ip_up_hnd;
	struct sigchld_handler_t ip_change_hnd;
	struct sigchld_handler_t ip_down_hnd;
#ifdef RADIUS
	char *tmp_fname;
	int radattr_saved:1;
#endif
	int started:1;
	int res;
	in_addr_t ipv4_addr;
	in_addr_t ipv4_peer_addr;
};

static struct pppd_compat_pd *find_pd(struct ap_session *ses);
static void fill_argv(char **argv, struct pppd_compat_pd *pd, char *path);
static void fill_env(char **env, char *mem, struct pppd_compat_pd *pd);
#ifdef RADIUS
static void remove_radattr(struct pppd_compat_pd *);
static void write_radattr(struct pppd_compat_pd *, struct rad_packet_t *pack);
#endif

static void ip_pre_up_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), ip_pre_up_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ses);
		log_ppp_info2("pppd_compat: ip-pre-up finished (%i)\n", status);
	}
	sched_yield();
	pd->res = status;
	triton_context_wakeup(pd->ses->ctrl->ctx);
}

static void ip_up_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), ip_up_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ses);
		log_ppp_info2("pppd_compat: ip-up finished (%i)\n", status);
	}
}

static void ip_down_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), ip_down_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ses);
		log_ppp_info2("pppd_compat: ip-down finished (%i)\n", status);
	}
	sched_yield();
	triton_context_wakeup(pd->ses->ctrl->ctx);
}

static void ip_change_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd *pd = container_of(h, typeof(*pd), ip_change_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ses);
		log_ppp_info2("pppd_compat: ip-change finished (%i)\n", status);
	}
	sched_yield();
	pd->res = status;
	triton_context_wakeup(pd->ses->ctrl->ctx);
}

static void ev_ses_starting(struct ap_session *ses)
{
	struct pppd_compat_pd *pd;

	pd = _malloc(sizeof(*pd));
	if (!pd) {
		log_emerg("pppd_compat: out of memory\n");
		return;
	}

	memset(pd, 0, sizeof(*pd));
	pd->pd.key = &pd_key;
	pd->ses = ses;
	pd->ip_pre_up_hnd.handler = ip_pre_up_handler;
	pd->ip_up_hnd.handler = ip_up_handler;
	pd->ip_down_hnd.handler = ip_down_handler;
	pd->ip_change_hnd.handler = ip_change_handler;
	list_add_tail(&pd->pd.entry, &ses->pd_list);
}

static void ev_ses_pre_up(struct ap_session *ses)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd = find_pd(ses);

	if (!pd)
		return;

#ifdef RADIUS
	if (pd->tmp_fname) {
		char *fname = _malloc(PATH_MAX);

		if (!fname) {
			log_emerg("pppd_compat: out of memory\n");
			return;
		}

		sprintf(fname, "%s.%s", conf_radattr_prefix, ses->ifname);
		rename(pd->tmp_fname, fname);

		_free(fname);
		_free(pd->tmp_fname);
		pd->tmp_fname = NULL;
	}
#endif

	if (ses->ipv4) {
		pd->ipv4_addr = ses->ipv4->addr;
		pd->ipv4_peer_addr = ses->ipv4->peer_addr;
	}

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, pd, conf_ip_up);

	fill_env(env, env_mem, pd);

	if (conf_ip_pre_up && !access(conf_ip_pre_up, R_OK | X_OK)) {
		sigchld_lock();
		pid = fork();
		if (pid > 0) {
			pd->ip_pre_up_hnd.pid = pid;
			sigchld_register_handler(&pd->ip_pre_up_hnd);
			if (conf_verbose)
				log_ppp_info2("pppd_compat: ip-pre-up started (pid %i)\n", pid);
			sigchld_unlock();
			triton_context_schedule();
			pthread_mutex_lock(&pd->ip_pre_up_hnd.lock);
			pthread_mutex_unlock(&pd->ip_pre_up_hnd.lock);
			if (pd->res != 0) {
				ap_session_terminate(ses, pd->res > 127 ? TERM_NAS_ERROR : TERM_ADMIN_RESET, 0);
				return;
			}
		} else if (pid == 0) {
			sigset_t set;
			sigfillset(&set);
			pthread_sigmask(SIG_UNBLOCK, &set, NULL);

			execve(conf_ip_pre_up, argv, env);
			log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_pre_up, strerror(errno));
			_exit(EXIT_FAILURE);
		} else
			log_error("pppd_compat: fork: %s\n", strerror(errno));
	}
}

static void ev_ses_started(struct ap_session *ses)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd = find_pd(ses);

	if (!pd)
		return;

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, pd, conf_ip_up);

	fill_env(env, env_mem, pd);

	if (conf_ip_up && !access(conf_ip_up, R_OK | X_OK)) {
		sigchld_lock();
		pid = fork();
		if (pid > 0) {
			pd->ip_up_hnd.pid = pid;
			sigchld_register_handler(&pd->ip_up_hnd);
			if (conf_verbose)
				log_ppp_info2("pppd_compat: ip-up started (pid %i)\n", pid);
			sigchld_unlock();
		} else if (pid == 0) {
			sigset_t set;
			sigfillset(&set);
			pthread_sigmask(SIG_UNBLOCK, &set, NULL);

			execve(conf_ip_up, argv, env);
			log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_up, strerror(errno));
			_exit(EXIT_FAILURE);
		} else
			log_error("pppd_compat: fork: %s\n", strerror(errno));
	}

	pd->started = 1;
}

static void ev_ses_finished(struct ap_session *ses)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd = find_pd(ses);

	if (!pd)
		return;

	if (!pd->started)
		goto skip;

	pthread_mutex_lock(&pd->ip_up_hnd.lock);
	if (pd->ip_up_hnd.pid) {
		log_ppp_warn("pppd_compat: ip-up is not yet finished, terminating it ...\n");
		kill(pd->ip_up_hnd.pid, SIGTERM);
	}
	pthread_mutex_unlock(&pd->ip_up_hnd.lock);

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, pd, conf_ip_down);

	fill_env(env, env_mem, pd);

	if (conf_ip_down && !access(conf_ip_down, R_OK | X_OK)) {
		sigchld_lock();
		pid = fork();
		if (pid > 0) {
			pd->ip_down_hnd.pid = pid;
			sigchld_register_handler(&pd->ip_down_hnd);
			if (conf_verbose)
				log_ppp_info2("pppd_compat: ip-down started (pid %i)\n", pid);
			sigchld_unlock();
			triton_context_schedule();
			pthread_mutex_lock(&pd->ip_down_hnd.lock);
			pthread_mutex_unlock(&pd->ip_down_hnd.lock);
			sigchld_unregister_handler(&pd->ip_down_hnd);
		} else if (pid == 0) {
			sigset_t set;
			sigfillset(&set);
			pthread_sigmask(SIG_UNBLOCK, &set, NULL);

			execve(conf_ip_down, argv, env);
			log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_down, strerror(errno));
			_exit(EXIT_FAILURE);
		} else
			log_error("pppd_compat: fork: %s\n", strerror(errno));
	}

	pthread_mutex_lock(&pd->ip_up_hnd.lock);
	if (pd->ip_up_hnd.pid) {
		log_ppp_warn("pppd_compat: ip-up is not yet finished, killing it ...\n");
		kill(pd->ip_up_hnd.pid, SIGKILL);
		pthread_mutex_unlock(&pd->ip_up_hnd.lock);
		sigchld_unregister_handler(&pd->ip_up_hnd);
	} else
		pthread_mutex_unlock(&pd->ip_up_hnd.lock);

skip:
#ifdef RADIUS
	if (pd->radattr_saved)
		remove_radattr(pd);
#endif

	list_del(&pd->pd.entry);
	_free(pd);
}

#ifdef RADIUS
static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct pppd_compat_pd *pd = find_pd(ev->ses);

	if (!pd)
		return;

	write_radattr(pd, ev->reply);

	pd->radattr_saved = 1;
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	pid_t pid;
	char *argv[8];
	char *env[ENV_MAX];
	char env_mem[ENV_MEM];
	char ipaddr[17];
	char peer_ipaddr[17];
	struct pppd_compat_pd *pd = find_pd(ev->ses);

	if (!pd)
		return;

	write_radattr(pd, ev->request);

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, pd, conf_ip_change);

	fill_env(env, env_mem, pd);
	if (!access(conf_ip_change, R_OK | X_OK)) {
	    sigchld_lock();
	    pid = fork();
	    if (pid > 0) {
		pd->ip_change_hnd.pid = pid;
		sigchld_register_handler(&pd->ip_change_hnd);
		sigchld_unlock();
		if (conf_verbose)
			log_ppp_info2("pppd_compat: ip-change started (pid %i)\n", pid);
		triton_context_schedule();
		if (!ev->res)
			ev->res = pd->res;
	    } else if (pid == 0) {
		execve(conf_ip_change, argv, env);
		log_emerg("pppd_compat: exec '%s': %s\n", conf_ip_change, strerror(errno));
		_exit(EXIT_FAILURE);
	    } else
		log_error("pppd_compat: fork: %s\n", strerror(errno));
	}
}

static void remove_radattr(struct pppd_compat_pd *pd)
{
	char *fname;

	if (pd->tmp_fname) {
		unlink(pd->tmp_fname);
		_free(pd->tmp_fname);
	} else {
		fname = _malloc(PATH_MAX);
		if (!fname) {
			log_emerg("pppd_compat: out of memory\n");
			return;
		}

		sprintf(fname, "%s.%s", conf_radattr_prefix, pd->ses->ifname);

		if (unlink(fname)) {
			log_ppp_warn("pppd_compat: failed to remove '%s': %s\n", fname, strerror(errno));
		}
		sprintf(fname, "%s_old.%s", conf_radattr_prefix, pd->ses->ifname);
		unlink(fname);

		_free(fname);
	}
}

static void write_radattr(struct pppd_compat_pd *pd, struct rad_packet_t *pack)
{
	struct ap_session *ses = pd->ses;
	struct rad_attr_t *attr;
	struct rad_dict_value_t *val;
	FILE *f = NULL;
	char *fname1, *fname2 = NULL;
	int i;
	in_addr_t addr;

	fname1 = _malloc(PATH_MAX);
	if (!fname1) {
		log_emerg("pppd_compat: out of memory\n");
		return;
	}

	if (ses->state == AP_STATE_ACTIVE) {
		fname2 = _malloc(PATH_MAX);
		if (!fname2) {
			log_emerg("pppd_compat: out of memory\n");
			_free(fname1);
			return;
		}
	}

	if (ses->state == AP_STATE_ACTIVE) {
		sprintf(fname1, "%s.%s", conf_radattr_prefix, ses->ifname);
		sprintf(fname2, "%s_old.%s", conf_radattr_prefix, ses->ifname);
		if (rename(fname1, fname2))
			log_ppp_warn("pppd_compat: rename: %s\n", strerror(errno));

		f = fopen(fname1, "w");
	} else {
		int fd;

		sprintf(fname1, "%s.XXXXXX", conf_radattr_prefix);

		fd = mkstemp(fname1);
		if (fd < 0)
			log_ppp_warn("pppd_compat: mkstemp: %s\n", strerror(errno));
		else {
			fchmod(fd, 0644);
			f = fdopen(fd, "w");
		}
	}

	if (f) {
		list_for_each_entry(attr, &pack->attrs, entry) {
			fprintf(f, "%s ", attr->attr->name);
			switch (attr->attr->type) {
				case ATTR_TYPE_INTEGER:
					val = rad_dict_find_val(attr->attr, attr->val);
					if (val)
						fprintf(f, "%s\n", val->name);
					else
						fprintf(f, "%i\n", attr->val.integer);
					break;
				case ATTR_TYPE_STRING:
					fprintf(f, "%s\n", attr->val.string);
					break;
				case ATTR_TYPE_OCTETS:
					for (i = 0; i < attr->len; i++)
						fprintf(f, "%02X", attr->val.octets[i]);
					fprintf(f, "\n");
					break;
				case ATTR_TYPE_IPADDR:
					addr = ntohl(attr->val.ipaddr);
					fprintf(f, "%i.%i.%i.%i\n", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
					break;
				case ATTR_TYPE_DATE:
					fprintf(f, "%lu\n", (unsigned long) attr->val.date);
					break;
			}
		}
		fclose(f);
	} else
		log_ppp_warn("pppd_compat: failed to create '%s': %s\n", fname1, strerror(errno));

	if (ses->state == AP_STATE_ACTIVE) {
		_free(fname1);
		_free(fname2);
	} else
		pd->tmp_fname = fname1;
}
#endif

static struct pppd_compat_pd *find_pd(struct ap_session *ses)
{
	struct ap_private *pd;
	struct pppd_compat_pd *cpd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key) {
			cpd = container_of(pd, typeof(*cpd), pd);
			return cpd;
		}
	}

	//log_ppp_warn("pppd_compat: pd not found\n");
	return NULL;
}

static void fill_argv(char **argv, struct pppd_compat_pd *pd, char *path)
{
	argv[0] = path;
	argv[1] = pd->ses->ifname;
	argv[2] = "none";
	argv[3] = "0";
	u_inet_ntoa(pd->ipv4_addr, argv[4]);
	u_inet_ntoa(pd->ipv4_peer_addr, argv[5]);
	argv[6] = pd->ses->ctrl->calling_station_id;
	argv[7] = NULL;
}

static void build_addr(struct ipv6db_addr_t *a, uint64_t intf_id, struct in6_addr *addr)
{
	memcpy(addr, &a->addr, sizeof(*addr));

	if (a->prefix_len <= 64)
		*(uint64_t *)(addr->s6_addr + 8) = intf_id;
	else
		*(uint64_t *)(addr->s6_addr + 8) |= intf_id & ((1 << (128 - a->prefix_len)) - 1);
}

static void fill_env(char **env, char *mem, struct pppd_compat_pd *pd)
{
	struct ap_session *ses = pd->ses;
	uint64_t tx_bytes, rx_bytes;
	int n = 0;

	tx_bytes = (uint64_t)ses->acct_tx_bytes + 4294967296llu*ses->acct_output_gigawords;
	rx_bytes = (uint64_t)ses->acct_rx_bytes + 4294967296llu*ses->acct_input_gigawords;

	env[n++] = mem;
	mem += sprintf(mem, "PEERNAME=%s", pd->ses->username) + 1;
	env[n++] = mem;
	mem += sprintf(mem, "CALLING_SID=%s", pd->ses->ctrl->calling_station_id) + 1;
	env[n++] = mem;
	mem += sprintf(mem, "CALLED_SID=%s", pd->ses->ctrl->called_station_id) + 1;

	if (ses->ipv6) {
		///FIXME only first address is passed to env
		struct ipv6db_addr_t *a = list_first_entry(&ses->ipv6->addr_list, typeof(*a), entry);
		struct in6_addr addr;
		build_addr(a, ses->ipv6->peer_intf_id, &addr);
		env[n++] = mem;
		strcpy(mem, "IPV6_PREFIX="); mem += 12;
		inet_ntop(AF_INET6, &addr, mem, ENV_MEM); mem = strchr(mem, 0);
		mem += sprintf(mem, "/%i", a->prefix_len) + 1;
	}

	if (ses->ipv6_dp) {
		///FIXME only first prefix is passed to env
		struct ipv6db_addr_t *a = list_first_entry(&ses->ipv6_dp->prefix_list, typeof(*a), entry);
		env[n++] = mem;
		strcpy(mem, "IPV6_DELEGATED_PREFIX="); mem += 22;
		inet_ntop(AF_INET6, &a->addr, mem, ENV_MEM); mem = strchr(mem, 0);
		mem += sprintf(mem, "/%i", a->prefix_len) + 1;
	}

	if (pd->ses->stop_time) {
		env[n++] = mem;
		mem += sprintf(mem, "CONNECT_TIME=%lu", (unsigned long)(pd->ses->stop_time - pd->ses->start_time)) + 1;
		env[n++] = mem;
		mem += sprintf(mem, "BYTES_SENT=%" PRIu64, tx_bytes) + 1;
		env[n++] = mem;
		mem += sprintf(mem, "BYTES_RCVD=%" PRIu64, rx_bytes) + 1;
	}

	env[n++] = NULL;
}

static void init(void)
{
	char *opt;

	opt = conf_get_opt("pppd-compat", "ip-pre-up");
	if (opt)
		conf_ip_pre_up = _strdup(opt);

	opt = conf_get_opt("pppd-compat", "ip-up");
	if (opt)
		conf_ip_up = _strdup(opt);

	opt = conf_get_opt("pppd-compat", "ip-down");
	if (opt)
		conf_ip_down = _strdup(opt);

	opt = conf_get_opt("pppd-compat", "ip-change");
	if (opt)
		conf_ip_change = _strdup(opt);

	opt = conf_get_opt("pppd-compat", "radattr-prefix");
	if (opt)
		conf_radattr_prefix = _strdup(opt);

	opt = conf_get_opt("pppd-compat", "verbose");
	if (opt && atoi(opt) > 0)
		conf_verbose = 1;

	triton_event_register_handler(EV_SES_STARTING, (triton_event_func)ev_ses_starting);
	triton_event_register_handler(EV_SES_PRE_UP, (triton_event_func)ev_ses_pre_up);
	triton_event_register_handler(EV_SES_STARTED, (triton_event_func)ev_ses_started);
	triton_event_register_handler(EV_SES_PRE_FINISHED, (triton_event_func)ev_ses_finished);
#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif
}

DEFINE_INIT(100, init);
