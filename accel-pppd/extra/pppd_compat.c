#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "linux_ppp.h"

#include "triton.h"

#include "events.h"
#include "ppp.h"
#include "log.h"
#include "utils.h"
#include "sigchld.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

static char *conf_ip_up = "/etc/ppp/ip-up";
static char *conf_ip_pre_up;
static char *conf_ip_down = "/etc/ppp/ip-down";
static char *conf_ip_change;
static char *conf_radattr_prefix = "/var/run/radattr.";
static int conf_verbose = 0;

static void *pd_key;

struct pppd_compat_pd_t
{
	struct ppp_pd_t pd;
	struct ppp_t *ppp;
	struct sigchld_handler_t ip_pre_up_hnd;
	struct sigchld_handler_t ip_up_hnd;
	struct sigchld_handler_t ip_change_hnd;
	struct sigchld_handler_t ip_down_hnd;
#ifdef RADIUS
	int radattr_saved:1;
#endif
	int started:1;
	int res;
	int bytes_sent;
	int bytes_rcvd;
};

static struct pppd_compat_pd_t *find_pd(struct ppp_t *ppp);
static void fill_argv(char **argv, struct ppp_t *ppp, char *path);
static void fill_env(char **env, struct pppd_compat_pd_t *pd);
#ifdef RADIUS
static void remove_radattr(struct ppp_t *ppp);
static void write_radattr(struct ppp_t *ppp, struct rad_packet_t *pack, int save_old);
#endif

static void ip_pre_up_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd_t *pd = container_of(h, typeof(*pd), ip_pre_up_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ppp);
		log_ppp_info2("pppd_compat: ip-pre-up finished (%i)\n", status);
		pd->res = status;
	}
	sched_yield();
	triton_context_wakeup(pd->ppp->ctrl->ctx);
}

static void ip_up_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd_t *pd = container_of(h, typeof(*pd), ip_up_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ppp);
		log_ppp_info2("pppd_compat: ip-up finished (%i)\n", status);
	}
}

static void ip_down_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd_t *pd = container_of(h, typeof(*pd), ip_down_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ppp);
		log_ppp_info2("pppd_compat: ip-down finished (%i)\n", status);
	}
	sched_yield();
	triton_context_wakeup(pd->ppp->ctrl->ctx);
}

static void ip_change_handler(struct sigchld_handler_t *h, int status)
{
	struct pppd_compat_pd_t *pd = container_of(h, typeof(*pd), ip_change_hnd);
	if (conf_verbose) {
		log_switch(NULL, pd->ppp);
		log_ppp_info2("pppd_compat: ip-change finished (%i)\n", status);
	}
	sched_yield();
	pd->res = status;
	triton_context_wakeup(pd->ppp->ctrl->ctx);
}

static void ev_ppp_starting(struct ppp_t *ppp)
{
	struct pppd_compat_pd_t *pd = _malloc(sizeof(*pd));

	if (!pd) {
		log_emerg("pppd_compat: out of memory\n");
		return;
	}

	memset(pd, 0, sizeof(*pd));
	pd->pd.key = &pd_key;
	pd->ppp = ppp;
	pd->ip_pre_up_hnd.handler = ip_pre_up_handler;
	pd->ip_up_hnd.handler = ip_up_handler;
	pd->ip_down_hnd.handler = ip_down_handler;
	pd->ip_change_hnd.handler = ip_change_handler;
	list_add_tail(&pd->pd.entry, &ppp->pd_list);
}

static void ev_ppp_pre_up(struct ppp_t *ppp)
{
	pid_t pid;
	char *argv[8];
	char *env[2];
	char ipaddr[17];
	char peer_ipaddr[17];
	char peername[64];
	struct pppd_compat_pd_t *pd = find_pd(ppp);
	
	if (!pd)
		return;

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, ppp, conf_ip_up);
	
	env[0] = peername;
	env[1] = NULL;
	fill_env(env, pd);

	if (conf_ip_pre_up) {
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
				ppp_terminate(ppp, 0, pd->res < 0 ? TERM_NAS_ERROR : TERM_ADMIN_RESET);
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

static void ev_ppp_started(struct ppp_t *ppp)
{
	pid_t pid;
	char *argv[8];
	char *env[2];
	char ipaddr[17];
	char peer_ipaddr[17];
	char peername[64];
	struct pppd_compat_pd_t *pd = find_pd(ppp);
	
	if (!pd)
		return;

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, ppp, conf_ip_up);
	
	env[0] = peername;
	env[1] = NULL;
	fill_env(env, pd);

	if (conf_ip_up) {
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

static void ev_ppp_finishing(struct ppp_t *ppp)
{
	struct ifpppstatsreq ifreq;
	struct pppd_compat_pd_t *pd = find_pd(ppp);
	
	if (!pd)
		return;
	
	memset(&ifreq, 0, sizeof(ifreq));
	ifreq.stats_ptr = (void *)&ifreq.stats;
	strcpy(ifreq.ifr__name, ppp->ifname);

	if (ioctl(sock_fd, SIOCGPPPSTATS, &ifreq)) {
		log_ppp_error("pppd_compat: failed to get ppp statistics: %s\n", strerror(errno));
		return;
	}

	pd->bytes_sent = ifreq.stats.p.ppp_obytes;
	pd->bytes_rcvd = ifreq.stats.p.ppp_ibytes;
}

static void ev_ppp_finished(struct ppp_t *ppp)
{
	pid_t pid;
	char *argv[8];
	char *env[5];
	char ipaddr[17];
	char peer_ipaddr[17];
	char peername[64];
	char connect_time[24];
	char bytes_sent[24];
	char bytes_rcvd[24];
	struct pppd_compat_pd_t *pd = find_pd(ppp);
	
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
	fill_argv(argv, pd->ppp, conf_ip_down);

	env[0] = peername;
	env[1] = connect_time;
	env[2] = bytes_sent;
	env[3] = bytes_rcvd;
	env[4] = NULL;
	fill_env(env, pd);

	if (conf_ip_down) {
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
		remove_radattr(ppp);
#endif
	
	list_del(&pd->pd.entry);
	_free(pd);
}

#ifdef RADIUS
static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct pppd_compat_pd_t *pd = find_pd(ev->ppp);

	write_radattr(ev->ppp, ev->reply, 0);

	pd->radattr_saved = 1;
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	pid_t pid;
	char *argv[8];
	char *env[2];
	char ipaddr[17];
	char peer_ipaddr[17];
	char peername[64];
	struct pppd_compat_pd_t *pd = find_pd(ev->ppp);
	
	if (!pd)
		return;

	write_radattr(ev->ppp, ev->request, 1);

	argv[4] = ipaddr;
	argv[5] = peer_ipaddr;
	fill_argv(argv, pd->ppp, conf_ip_change);

	env[0] = peername;
	env[1] = NULL;
	fill_env(env, pd);

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

static void remove_radattr(struct ppp_t *ppp)
{
	char *fname;

	fname = _malloc(PATH_MAX);
	if (!fname) {
		log_emerg("pppd_compat: out of memory\n");
		return;
	}

	sprintf(fname, "%s.%s", conf_radattr_prefix, ppp->ifname);
	if (unlink(fname)) {
		log_ppp_warn("pppd_compat: failed to remove '%s': %s\n", fname, strerror(errno));
	}
	sprintf(fname, "%s_old.%s", conf_radattr_prefix, ppp->ifname);
	unlink(fname);

	_free(fname);
}

static void write_radattr(struct ppp_t *ppp, struct rad_packet_t *pack, int save_old)
{
	struct rad_attr_t *attr;
	struct rad_dict_value_t *val;
	FILE *f;
	char *fname1, *fname2 = NULL;
	int i;

	fname1 = _malloc(PATH_MAX);
	if (!fname1) {
		log_emerg("pppd_compat: out of memory\n");
		return;
	}

	if (save_old) {
		fname2 = _malloc(PATH_MAX);
		if (!fname2) {
			log_emerg("pppd_compat: out of memory\n");
			_free(fname1);
			return;
		}
	}

	sprintf(fname1, "%s.%s", conf_radattr_prefix, ppp->ifname);
	if (save_old) {
		sprintf(fname2, "%s_old.%s", conf_radattr_prefix, ppp->ifname);
		if (rename(fname1, fname2)) {
			log_ppp_warn("pppd_compat: rename: %s\n", strerror(errno));
		}
	}

	f = fopen(fname1, "w");
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
					fprintf(f, "%i.%i.%i.%i\n", attr->val.ipaddr & 0xff, (attr->val.ipaddr >> 8) & 0xff, (attr->val.ipaddr >> 16) & 0xff, (attr->val.ipaddr >> 24) & 0xff);
					break;
				case ATTR_TYPE_DATE:
					fprintf(f, "%lu\n", attr->val.date);
					break;
			}
		}
		fclose(f);
	} else
		log_ppp_warn("pppd_compat: failed to create '%s': %s\n", fname1, strerror(errno));
	
	_free(fname1);
	if (save_old)
		_free(fname2);
}
#endif

static struct pppd_compat_pd_t *find_pd(struct ppp_t *ppp)
{
	struct ppp_pd_t *pd;
	struct pppd_compat_pd_t *cpd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &pd_key) {
			cpd = container_of(pd, typeof(*cpd), pd);
			return cpd;
		}
	}
	
	log_ppp_warn("pppd_compat: pd not found\n");
	return NULL;
}

static void fill_argv(char **argv, struct ppp_t *ppp, char *path)
{
	argv[0] = path;
	argv[1] = ppp->ifname;
	argv[2] = "none";
	argv[3] = "0";
	u_inet_ntoa(ppp->ipaddr, argv[4]);
	u_inet_ntoa(ppp->peer_ipaddr, argv[5]);
	argv[6] = ppp->ctrl->calling_station_id;
	argv[7] = NULL;
}

static void fill_env(char **env, struct pppd_compat_pd_t *pd)
{
	snprintf(env[0], 64, "PEERNAME=%s", pd->ppp->username);
	
	if (pd->ppp->stop_time && env[1]) {
		snprintf(env[1], 24, "CONNECT_TIME=%lu", pd->ppp->stop_time - pd->ppp->start_time);
		snprintf(env[2], 24, "BYTES_SENT=%u", pd->bytes_sent);
		snprintf(env[3], 24, "BYTES_RCVD=%u", pd->bytes_rcvd);
	}
}

static void __init init(void)
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

	triton_event_register_handler(EV_PPP_STARTING, (triton_event_func)ev_ppp_starting);
	triton_event_register_handler(EV_PPP_PRE_UP, (triton_event_func)ev_ppp_pre_up);
	triton_event_register_handler(EV_PPP_STARTED, (triton_event_func)ev_ppp_started);
	triton_event_register_handler(EV_PPP_FINISHING, (triton_event_func)ev_ppp_finishing);
	triton_event_register_handler(EV_PPP_FINISHED, (triton_event_func)ev_ppp_finished);
#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif
}
