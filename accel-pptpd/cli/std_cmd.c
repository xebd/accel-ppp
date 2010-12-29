#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>

#include "triton.h"
#include "events.h"
#include "ppp.h"
#include "cli.h"
#include "utils.h"
#include "log.h"
#include "memdebug.h"

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	time_t dt;
	int day,hour;
	char statm_fname[128];
	FILE *f;
	unsigned long vmsize = 0, vmrss = 0;
	unsigned long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024;

	sprintf(statm_fname, "/proc/%i/statm", getpid());
	f = fopen(statm_fname, "r");
	if (f) {
		fscanf(f, "%lu %lu", &vmsize, &vmrss);
		fclose(f);
	}

	time(&dt);
	dt -= triton_stat.start_time;
	day = dt / (60 * 60 * 24);
	dt %= 60 * 60 * 24;
	hour = dt / (60 * 60);
	dt %= 60 * 60;

	cli_sendv(client, "uptime: %i.%02i:%02i:%02i\r\n", day, hour, dt / 60, dt % 60);
	cli_sendv(client, "cpu: %i%%\r\n", triton_stat.cpu);
	cli_sendv(client, "mem(rss/virt): %lu/%lu kB\r\n", vmrss * page_size_kb, vmsize * page_size_kb);
	cli_send(client, "core:\r\n");
	cli_sendv(client, "  mempool_allocated: %u\r\n", triton_stat.mempool_allocated);
	cli_sendv(client, "  mempool_available: %u\r\n", triton_stat.mempool_available);
	cli_sendv(client, "  thread_count: %u\r\n", triton_stat.thread_count);
	cli_sendv(client, "  thread_active: %u\r\n", triton_stat.thread_active);
	cli_sendv(client, "  context_count: %u\r\n", triton_stat.context_count);
	cli_sendv(client, "  context_sleeping: %u\r\n", triton_stat.context_sleeping);
	cli_sendv(client, "  context_pending: %u\r\n", triton_stat.context_pending);
	cli_sendv(client, "  md_handler_count: %u\r\n", triton_stat.md_handler_count);
	cli_sendv(client, "  md_handler_pending: %u\r\n", triton_stat.md_handler_pending);
	cli_sendv(client, "  timer_count: %u\r\n", triton_stat.timer_count);
	cli_sendv(client, "  timer_pending: %u\r\n", triton_stat.timer_pending);

//===========
	cli_send(client, "ppp:\r\n");
	cli_sendv(client, "  staring: %u\r\n", ppp_stat.starting);
	cli_sendv(client, "  active: %u\r\n", ppp_stat.active);
	cli_sendv(client, "  finishing: %u\r\n", ppp_stat.finishing);

	return CLI_CMD_OK;
}

static void show_stat_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "show stat - shows various statistics information\r\n");
}
//=============================

static int exit_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	return CLI_CMD_EXIT;
}

static void exit_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "exit - exit cli\r\n");
}

//=============================

static int show_ses_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct row_t
	{
		struct list_head entry;
		char buf[128];
		char *match_key;
		char *order_key;
	};
	char ip_str[17];
	char *state_str;
	char time_str[12];
	time_t uptime;
	int day,hour,min,sec;
	struct ppp_t *ppp;
	int i;
	enum order_type {ORDER_NONE, ORDER_USERNAME};
	enum match_type {MATCH_NONE, MATCH_USERNAME};
	int order = ORDER_NONE;
	int match = MATCH_NONE;
	struct row_t *row, *row2, *row3;
	pcre *re = NULL;
	const char *pcre_err;
	int pcre_offset;
	LIST_HEAD(rows);
	LIST_HEAD(temp_rows);

	for (i = 2; i < fields_cnt; i++) {
		if (!strcmp(fields[i], "order")) {
			if (i == fields_cnt - 1)
				return CLI_CMD_SYNTAX;
			i++;
			if (!strcmp(fields[i], "username"))
				order = ORDER_USERNAME;
			else {
				cli_send(client, "only order by username is supported yet\r\n");
				return CLI_CMD_OK;
			}
		} else if (!strcmp(fields[i], "match")) {
			if (i == fields_cnt - 2)
				return CLI_CMD_SYNTAX;
			i++;
			if (!strcmp(fields[i], "username"))
				match = MATCH_USERNAME;
			else {
				cli_send(client, "only match by username is supported yet\r\n");
				return CLI_CMD_OK;
			}
			i++;
			re = pcre_compile2(fields[i], 0, NULL, &pcre_err, &pcre_offset, NULL);
			if (!re) {
				cli_sendv(client, "match: %s at %i\r\n", pcre_err, pcre_offset);
				return CLI_CMD_OK;
			}
		} else
			return CLI_CMD_SYNTAX;
	}


	cli_send(client, "interface:        username:          address:  type: state:     uptime:\r\n");
	cli_send(client, "------------------------------------------------------------------------\r\n");

	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		row = _malloc(sizeof(*row));
		if (!row) {
			log_emerg("out of memory\n");
			cli_send(client, "out of memory\r\n");
			break;
		}
		
		if (order == ORDER_USERNAME)
			row->order_key = ppp->username ? _strdup(ppp->username) : _strdup("");

		if (match == MATCH_USERNAME)
			row->match_key = ppp->username ? _strdup(ppp->username) : _strdup("");

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
			snprintf(time_str, 12, "%i.%02i:%02i:%02i", day, hour, min, sec);
		else
			snprintf(time_str, 12, "%02i:%02i:%02i", hour, min, sec);

		snprintf(row->buf, 128, "%9s  %15s  %16s %6s %6s  %10s\r\n", ppp->ifname, ppp->username ? ppp->username : "", ip_str, ppp->ctrl->name, state_str, time_str);
		if (order || match)
			list_add_tail(&row->entry, &temp_rows);
		else
			list_add_tail(&row->entry, &rows);
		//cli_send(client, buf);
	}
	pthread_rwlock_unlock(&ppp_lock);

	if (match || order) {
		while (!list_empty(&temp_rows)) {
			row = list_entry(temp_rows.next, typeof(*row), entry);
			list_del(&row->entry);
			if (match == MATCH_USERNAME) {
				if (pcre_exec(re, NULL, row->match_key, strlen(row->match_key), 0, 0, NULL, 0) < 0) {
					_free(row->match_key);
					if (order)
						_free(row->order_key);
					_free(row);
					continue;
				}
			}
			if (order == ORDER_USERNAME) {
				row3 = NULL;
				list_for_each_entry(row2, &rows, entry) {
					if (strcmp(row->order_key, row2->order_key) <= 0) {
						row3 = row2;
						break;
					}
				}
				if (row3)
					list_add_tail(&row->entry, &row3->entry);
				else
					list_add_tail(&row->entry, &rows);
			} else
				list_add_tail(&row->entry, &rows);
		}
	}

	while (!list_empty(&rows)) {
		row = list_entry(rows.next, typeof(*row), entry);
		list_del(&row->entry);
		cli_send(client, row->buf);
		if (match == MATCH_USERNAME)
			_free(row->match_key);
		if (order == ORDER_USERNAME)
			_free(row->order_key);
		_free(row);
	}

	if (match == MATCH_USERNAME)
		pcre_free(re);
	
	return CLI_CMD_OK;
}

static void show_ses_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "show sessions [order username] [match username <regexp>] - shows all sessions\r\n");
}

//=============================

static void ppp_terminate_soft(struct ppp_t *ppp)
{
	ppp_terminate(ppp, TERM_NAS_REQUEST, 0);
}

static void ppp_terminate_hard(struct ppp_t *ppp)
{
	ppp_terminate(ppp, TERM_NAS_REQUEST, 1);
}

static int terminate_exec1(char * const *f, int f_cnt, void *cli)
{
	struct ppp_t *ppp;
	int hard = 0;
	pcre *re;
	const char *pcre_err;
	int pcre_offset;
	
	if (f_cnt == 5) {
		if (!strcmp(f[4], "hard"))
			hard = 1;
		else if (strcmp(f[4], "soft"))
			return CLI_CMD_SYNTAX;
	} else if (f_cnt != 4)
		return CLI_CMD_SYNTAX;
			
	re = pcre_compile2(f[3], 0, NULL, &pcre_err, &pcre_offset, NULL);
	if (!re) {
		cli_sendv(cli, "match: %s at %i\r\n", pcre_err, pcre_offset);
		return CLI_CMD_OK;
	}

	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		if (pcre_exec(re, NULL, ppp->username, strlen(ppp->username), 0, 0, NULL, 0) < 0)
			continue;
		if (hard)
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_hard, ppp);
		else
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_soft, ppp);
	}
	pthread_rwlock_unlock(&ppp_lock);
	
	pcre_free(re);
	
	return CLI_CMD_OK;
}

static int terminate_exec2(int key, char * const *f, int f_cnt, void *cli)
{
	struct ppp_t *ppp;
	int hard = 0;
	in_addr_t ipaddr = 0;
	
	if (f_cnt == 4) {
		if (!strcmp(f[3], "hard"))
			hard = 1;
		else if (strcmp(f[3], "soft"))
			return CLI_CMD_SYNTAX;
	} else if (f_cnt != 3)
		return CLI_CMD_SYNTAX;
	
	if (key == 1)
		ipaddr = inet_addr(f[2]);
			
	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		switch (key) {
			case 0:
				if (strcmp(ppp->username, f[2]))
					continue;
				break;
			case 1:
				if (ppp->peer_ipaddr != ipaddr)
					continue;
				break;
			case 2:
				if (strcmp(ppp->ctrl->calling_station_id, f[2]))
					continue;
				break;
			case 3:
				if (strcmp(ppp->sessionid, f[2]))
					continue;
				break;
			case 4:
				if (strcmp(ppp->ifname, f[2]))
					continue;
				break;
		}
		if (hard)
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_hard, ppp);
		else
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_soft, ppp);
		break;
	}
	pthread_rwlock_unlock(&ppp_lock);

	return CLI_CMD_OK;
}

static int terminate_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct ppp_t *ppp;
	int hard = 0;

	if (fields_cnt == 1)
		return CLI_CMD_SYNTAX;
	
	if (!strcmp(fields[1], "match") && fields_cnt > 3 && !strcmp(fields[2], "username"))
		return terminate_exec1(fields, fields_cnt, client);
	else if (!strcmp(fields[1], "username"))
		return terminate_exec2(0, fields, fields_cnt, client);
	else if (!strcmp(fields[1], "ip"))
		return terminate_exec2(1, fields, fields_cnt, client);
	else if (!strcmp(fields[1], "csid"))
		return terminate_exec2(2, fields, fields_cnt, client);
	else if (!strcmp(fields[1], "sid"))
		return terminate_exec2(3, fields, fields_cnt, client);
	else if (!strcmp(fields[1], "if"))
		return terminate_exec2(4, fields, fields_cnt, client);
	else if (strcmp(fields[1], "all"))
		return CLI_CMD_SYNTAX;
	
	if (fields_cnt == 3) {
		if (!strcmp(fields[2], "hard"))
			hard = 1;
		else if (strcmp(fields[2], "soft"))
			return CLI_CMD_SYNTAX;
	} else if (fields_cnt != 2)
		return CLI_CMD_SYNTAX;
	
	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		if (hard)
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_hard, ppp);
		else
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_soft, ppp);
	}
	pthread_rwlock_unlock(&ppp_lock);

	return CLI_CMD_OK;
}

static void terminate_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "terminate if <interface> [soft|hard]- terminate session by interface name\r\n");
	cli_send(client, "\t[match] username <username> [soft|hard]- terminate session by username\r\n");
	cli_send(client, "\tip <addresss> [soft|hard]- terminate session by ip address\r\n");
	cli_send(client, "\tcsid <id> [soft|hard]- terminate session by calling station id\r\n");
	cli_send(client, "\tsid <id> [soft|hard]- terminate session by session id\r\n");
	cli_send(client, "\tall [soft|hard]- terminate all sessions\r\n");
}

//=============================

static void shutdown_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "shutdown [soft|hard|cancel]- shutdown daemon\r\n");
	cli_send(client, "\t\tdefault action - send termination signals to all clients and wait everybody disconnects\r\n");
	cli_send(client, "\t\tsoft - wait until all clients disconnects, don't accept new connections\r\n");
	cli_send(client, "\t\thard - shutdown now, don't wait anything\r\n");
	cli_send(client, "\t\tcancel - cancel 'shutdown soft' and return to normal operation\r\n");
}

static void ppp_terminate_soft2(struct ppp_t *ppp)
{
	ppp_terminate(ppp, TERM_NAS_REBOOT, 0);
}

static void ppp_terminate_hard2(struct ppp_t *ppp)
{
	ppp_terminate(ppp, TERM_NAS_REBOOT, 1);
}

static int shutdown_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	int hard = 0;
	struct ppp_t *ppp;

	if (f_cnt == 2) {
		if (!strcmp(f[1], "soft")) {
			ppp_shutdown_soft();
			return CLI_CMD_OK;
		} else if (!strcmp(f[1], "hard"))
			hard = 1;
		else if (!strcmp(f[1], "cancel")) {
			ppp_shutdown = 0;
			return CLI_CMD_OK;
		} else
			return CLI_CMD_SYNTAX;
	}

	ppp_shutdown_soft();

	pthread_rwlock_rdlock(&ppp_lock);
	list_for_each_entry(ppp, &ppp_list, entry) {
		if (hard)
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_hard2, ppp);
		else
			triton_context_call(ppp->ctrl->ctx, (triton_event_func)ppp_terminate_soft2, ppp);
	}
	pthread_rwlock_unlock(&ppp_lock);

	return CLI_CMD_OK;
}

//==========================
static int conf_reload_res;
static struct triton_context_t *conf_reload_ctx;
static void conf_reload_notify(int r)
{
	if (!r)
		triton_event_fire(EV_CONFIG_RELOAD, NULL);
	conf_reload_res = r;
	triton_context_wakeup(conf_reload_ctx);
}
static int reload_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt == 1) {
		conf_reload_ctx = triton_context_self();
		triton_conf_reload(conf_reload_notify);
		triton_context_schedule();
		if (conf_reload_res)
			cli_send(cli, "failed\r\n");
		return CLI_CMD_OK;
	} else
		return CLI_CMD_SYNTAX;
}

static void reload_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "reload - reload config file\r\n");
}

static void __init init(void)
{
	cli_register_simple_cmd2(show_stat_exec, show_stat_help, 2, "show", "stat");
	cli_register_simple_cmd2(show_ses_exec, show_ses_help, 2, "show", "sessions_old");
	cli_register_simple_cmd2(terminate_exec, terminate_help, 1, "terminate");
	cli_register_simple_cmd2(reload_exec, reload_help, 1, "reload");
	cli_register_simple_cmd2(shutdown_exec, shutdown_help, 1, "shutdown");
	cli_register_simple_cmd2(exit_exec, exit_help, 1, "exit");
}

