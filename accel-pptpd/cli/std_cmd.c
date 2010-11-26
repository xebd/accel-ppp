#include <stdio.h>
#include <time.h>
#include <string.h>

#include "triton.h"
#include "ppp.h"
#include "cli.h"
#include "utils.h"
#include "log.h"
#include "memdebug.h"

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
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
	pcre *re;
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
			row->order_key = _strdup(ppp->username);

		if (match == MATCH_USERNAME)
			row->match_key = _strdup(ppp->username);

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

		sprintf(row->buf, "%9s  %15s  %16s %6s %6s  %10s\r\n", ppp->ifname, ppp->username ? ppp->username : "", ip_str, ppp->ctrl->name, state_str, time_str);
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
	ppp_terminate(ppp, TERM_ADMIN_RESET, 0);
}

static void ppp_terminate_hard(struct ppp_t *ppp)
{
	ppp_terminate(ppp, TERM_ADMIN_RESET, 1);
}

static void terminate_help(char * const *fields, int fields_cnt, void *client);
static int terminate_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct ppp_t *ppp;
	int hard = 0;

	if (fields_cnt == 1)
		goto help;
	
	if (fields_cnt == 3) {
		if (!strcmp(fields[2], "hard"))
			hard = 1;
		else if (strcmp(fields[2], "soft"))
			goto help;
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
help:
	terminate_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

static void terminate_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "terminate <interface> [soft|hard]- terminate session\r\n");
	cli_send(client, "terminate all [soft|hard]- terminate all session\r\n");
}

static void __init init(void)
{
	cli_register_simple_cmd2(show_stat_exec, show_stat_help, 2, "show", "stat");
	cli_register_simple_cmd2(show_ses_exec, show_ses_help, 2, "show", "sessions");
	cli_register_simple_cmd2(terminate_exec, terminate_help, 1, "terminate");
	cli_register_simple_cmd2(exit_exec, exit_help, 1, "exit");
}

