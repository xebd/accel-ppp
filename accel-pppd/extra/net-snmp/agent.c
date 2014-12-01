#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <string.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "log.h"
#include "triton.h"

#include "statCore.h"
#include "statPPP.h"
#include "statPPTP.h"
#include "statL2TP.h"
#include "statPPPOE.h"
#include "statIPOE.h"
#include "terminate.h"
#include "shutdown.h"
#include "sessionTable.h"
#include "exec_cli.h"

static const char *conf_agent_name = "accel-ppp";
static int conf_master = 0;
/*static const char *conf_oid_prefix = "1.3.6.1.4.1.8072.100";

static oid* oid_prefix;
static size_t oid_prefix_size;*/

static pthread_t snmp_thr;
static int snmp_term = 0;

/*int accel_ppp_alloc_oid(oid tail, size_t size, oid **oid)
{
	*oid = malloc(sizeof(oid) * (oid_prefix_size + size));

	memcpy(*oid, oid_prefix, oid_prefix_size);
	memcpy((*oid) + oid_prefix_size, tail, size);

	return oid_prefix_size + size;
}*/

static int agent_log(int major, int minor, void *serv_arg, void *cl_arg)
{
	struct snmp_log_message *m = serv_arg;

	switch (m->priority) {
		case LOG_EMERG:
			log_emerg("net-snmp: %s", m->msg);
			break;
		case LOG_ALERT:
		case LOG_CRIT:
		case LOG_ERR:
			log_error("net-snmp: %s", m->msg);
			break;
		case LOG_WARNING:
			log_warn("net-snmp: %s", m->msg);
			break;
		case LOG_NOTICE:
			log_info1("net-snmp: %s", m->msg);
			break;
		case LOG_INFO:
			log_info2("net-snmp: %s", m->msg);
			break;
		case LOG_DEBUG:
			log_debug("net-snmp: %s", m->msg);
			break;
		default:
			log_msg("net-snmp: %s", m->msg);
	}
	return 0;
}

static void *snmp_thread(void *a)
{
	sigset_t set;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	sigdelset(&set, 32);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	if (unshare(CLONE_FILES) < 0) {
		log_error("net-snmp: impossible to start SNMP thread:"
			  " unshare(CLONE_FILES) failed (%s)\n",
			  strerror(errno));

		return NULL;
	}

	snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING, agent_log, NULL);
  snmp_disable_log();
	snmp_enable_calllog();
	//snmp_set_do_debugging(1);
	//netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1);

	if (!conf_master)
		netsnmp_enable_subagent();

	init_agent(conf_agent_name);

	init_statCore();
	init_statPPP();
	init_statPPTP();
	init_statL2TP();
	init_statPPPOE();
	init_statIPOE();
	init_terminate();
	init_shutdown();
	init_sessionTable();
	init_cli();

	init_snmp(conf_agent_name);

	if (conf_master)
		init_master_agent();

	while (!snmp_term) {
    agent_check_and_process(1);
	}

	snmp_shutdown(conf_agent_name);

  SOCK_CLEANUP;

	return NULL;
}

static void snmp_ctx_close(struct triton_context_t *ctx)
{
	snmp_term = 1;
	pthread_cancel(snmp_thr);
	pthread_join(snmp_thr, NULL);
	triton_context_unregister(ctx);
}

static struct triton_context_t ctx = {
	.close = snmp_ctx_close,
};

static void init(void)
{
	const char *opt;

	opt = conf_get_opt("snmp", "master");
	if (opt)
		conf_master = atoi(opt);

	opt = conf_get_opt("snmp", "agent-name");
	if (opt)
		conf_agent_name = opt;

	/*opt = conf_get_opt("snmp", "oid-prefix")
	if (opt)
		conf_oid_prefix = opt;*/

	pthread_create(&snmp_thr, NULL, snmp_thread, NULL);
	triton_context_register(&ctx, NULL);
	triton_context_wakeup(&ctx);
	triton_collect_cpu_usage();
}

DEFINE_INIT(100, init);

