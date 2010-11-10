#include <stdio.h>

#include "triton.h"
#include "cli.h"

int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	char buf[128];

	if (cli_send(client, "core:\r\n"))
		return CLI_CMD_FAILED;
	
	sprintf(buf, "\tmempool_allocated: %u\r\n", triton_stat.mempool_allocated);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tmempool_available: %u\r\n", triton_stat.mempool_available);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tthread_count: %u\r\n", triton_stat.thread_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tthread_active: %u\r\n", triton_stat.thread_active);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tcontext_count: %u\r\n", triton_stat.context_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tcontext_sleeping: %u\r\n", triton_stat.context_sleeping);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tcontext_pending: %u\r\n", triton_stat.context_pending);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tmd_handler_count: %u\r\n", triton_stat.md_handler_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\tmd_handler_pending: %u\r\n", triton_stat.md_handler_pending);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\ttimer_count: %u\r\n", triton_stat.timer_count);
	if (cli_send(client, buf))
		return CLI_CMD_FAILED;

	sprintf(buf, "\ttimer_pending: %u\r\n", triton_stat.timer_pending);
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

const char *show_stat_hdr[] = {"show","stat"};
static struct cli_simple_cmd_t show_stat_cmd = {
	.hdr_len = 2,
	.hdr = show_stat_hdr,
	.exec = show_stat_exec,
	.help = show_stat_help,
};

const char *exit_hdr[] = {"exit"};
static struct cli_simple_cmd_t exit_cmd = {
	.hdr_len = 1,
	.hdr = exit_hdr,
	.exec = exit_exec,
	.help = exit_help,
};


static void __init init(void)
{
	cli_register_simple_cmd(&show_stat_cmd);
	cli_register_simple_cmd(&exit_cmd);
}
