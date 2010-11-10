#include <stdio.h>
#include <time.h>
#include <string.h>

#include "triton.h"
#include "ppp.h"
#include "cli.h"
#include "utils.h"

int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	char buf[128];

	if (cli_send(client, "core:\r\n"))
		return CLI_CMD_FAILED;
	
	sprintf(buf, "  mempool_allocated: %u\r\n", triton_stat.mempool_allocated);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  mempool_available: %u\r\n", triton_stat.mempool_available);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  thread_count: %u\r\n", triton_stat.thread_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  thread_active: %u\r\n", triton_stat.thread_active);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  context_count: %u\r\n", triton_stat.context_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  context_sleeping: %u\r\n", triton_stat.context_sleeping);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  context_pending: %u\r\n", triton_stat.context_pending);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  md_handler_count: %u\r\n", triton_stat.md_handler_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  md_handler_pending: %u\r\n", triton_stat.md_handler_pending);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  timer_count: %u\r\n", triton_stat.timer_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  timer_pending: %u\r\n", triton_stat.timer_pending);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

//===========
	if (cli_send(client, "ppp:\r\n"))
		return CLI_CMD_FAILED;

	sprintf(buf, "  staring: %u\r\n", ppp_stat.starting);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  active: %u\r\n", ppp_stat.active);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "  finishing: %u\r\n", ppp_stat.finishing);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	return CLI_CMD_OK;
}

int show_stat_help(char * const *fields, int fields_cnt, void *client)
{
	if (cli_send(client, "show stat - shows various statistics information\r\n"))
		return -1;
	
	return 0;
}

const char *show_stat_hdr[] = {"show","stat"};
static struct cli_simple_cmd_t show_stat_cmd = {
	.hdr_len = 2,
	.hdr = show_stat_hdr,
	.exec = show_stat_exec,
	.help = show_stat_help,
};

//=============================

int exit_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	return CLI_CMD_EXIT;
}

int exit_help(char * const *fields, int fields_cnt, void *client)
{
	if (cli_send(client, "exit - exit cli\r\n"))
		return -1;
	
	return 0;
}

const char *exit_hdr[] = {"exit"};
static struct cli_simple_cmd_t exit_cmd = {
	.hdr_len = 1,
	.hdr = exit_hdr,
	.exec = exit_exec,
	.help = exit_help,
};

//=============================

int show_ses_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	char buf[128];
	char ip_str[17];
	char *state_str;
	char time_str[12];
	time_t uptime;
	int day,hour,min,sec;
	struct ppp_t *ppp;

	if (cli_send(client, "interface:        username:          address:  type: state:     uptime:\r\n"))
		return CLI_CMD_FAILED;

	if (cli_send(client, "------------------------------------------------------------------------\r\n"))
		return CLI_CMD_FAILED;

	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		u_inet_ntoa(ppp->peer_ipaddr, ip_str);
		
		switch (ppp->state) {
			case PPP_STATE_STARTING:
				state_str = "start";
				break;
			case PPP_STATE_ACTIVE:
				state_str = "active";
				break;
			case PPP_STATE_FINISHING:
				state_str = "finish";
				break;
			default:
				state_str = "unk";
		}

		if (ppp->stop_time)
			uptime = ppp->stop_time - ppp->start_time;
		else {
			time(&uptime);
			uptime -= ppp->start_time;
		}
		day = uptime/ (24*60*60); uptime %= (24*60*60);
		hour = uptime / (60*60); uptime %= (60*60);
		min = uptime / 60;
		sec = uptime % 60;
		if (day)
			sprintf(time_str, "%i.%02i:%02i:%02i", day, hour, min, sec);
		else
			sprintf(time_str, "%02i:%02i:%02i", hour, min, sec);

		sprintf(buf, "%9s  %15s  %16s %6s %6s  %10s\r\n", ppp->ifname, ppp->username ? ppp->username : "", ip_str, ppp->ctrl->name, state_str, time_str);
		if (cli_send(client, buf)) {
			pthread_rwlock_unlock(&ppp_lock);
			return CLI_CMD_FAILED;
		}
	}
	pthread_rwlock_unlock(&ppp_lock);
	
	return CLI_CMD_OK;
}

int show_ses_help(char * const *fields, int fields_cnt, void *client)
{
	if (cli_send(client, "show sessions - shows all sessions\r\n"))
		return -1;
	
	return 0;
}

const char *show_ses_hdr[] = {"show", "sessions"};
static struct cli_simple_cmd_t show_ses_cmd = {
	.hdr_len = 2,
	.hdr = show_ses_hdr,
	.exec = show_ses_exec,
	.help = show_ses_help,
};

//=============================

static void ppp_terminate_soft(struct ppp_t *ppp)
{
	ppp_terminate(ppp, 0, TERM_ADMIN_RESET);
}

static void ppp_terminate_hard(struct ppp_t *ppp)
{
	ppp_terminate(ppp, 1, TERM_ADMIN_RESET);
}

int terminate_help(char * const *fields, int fields_cnt, void *client);
int terminate_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct ppp_t *ppp;
	int hard = 0;

	if (fields_cnt == 1)
		return terminate_help(NULL, 0, client);
	
	if (fields_cnt == 3) {
		if (!strcmp(fields[2], "hard"))
			hard = 1;
		else if (strcmp(fields[2], "soft"))
			return terminate_help(NULL, 0, client);
	}
	
	pthread_rwlock_rdlock(&ppp_lock);
	if (strcmp(fields[1], "all")) {
		list_for_each_entry(ppp, &ppp_list, entry) {
			if (strcmp(ppp->ifname, fields[1]))
				continue;
			if (hard)
				triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_hard, ppp);
			else
				triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_soft, ppp);
			break;
		}
	} else {
		list_for_each_entry(ppp, &ppp_list, entry) {
			if (hard)
				triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_hard, ppp);
			else
				triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_soft, ppp);
		}
	}
	pthread_rwlock_unlock(&ppp_lock);

	return CLI_CMD_OK;
}

int terminate_help(char * const *fields, int fields_cnt, void *client)
{
	if (cli_send(client, "terminate <interface> [soft|hard]- terminate session\r\n"))
		return -1;
	
	if (cli_send(client, "terminate all [soft|hard]- terminate all session\r\n"))
		return -1;
	
	return 0;
}

const char *terminate_hdr[] = {"terminate"};
static struct cli_simple_cmd_t terminate_cmd = {
	.hdr_len = 1,
	.hdr = terminate_hdr,
	.exec = terminate_exec,
	.help = terminate_help,
};

static void __init init(void)
{
	cli_register_simple_cmd(&show_stat_cmd);
	cli_register_simple_cmd(&show_ses_cmd);
	cli_register_simple_cmd(&terminate_cmd);
	cli_register_simple_cmd(&exit_cmd);
}
