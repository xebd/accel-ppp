#include <string.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "triton.h"
#include "cli.h"
#include "ppp.h"

#include "pppoe.h"

static void show_interfaces(void *cli)
{
	struct pppoe_serv_t *serv;

	cli_send(cli, "interface:   connections:    state:\r\n");
	cli_send(cli, "-----------------------------------\r\n");

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		cli_sendv(cli, "%9s    %11u    %6s\r\n", serv->ifname, serv->conn_cnt, serv->stopping ? "stop" : "active");
	}
	pthread_rwlock_unlock(&serv_lock);
}

static void intf_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe interface add <name> - start pppoe server on specified interface\r\n");
	cli_send(client, "pppoe interface del <name> - stop pppoe server on specified interface and drop his connections\r\n");
	cli_send(client, "pppoe interface show - show interfaces on which pppoe server started\r\n");
}

static int intf_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt == 2)
		goto help;

	if (fields_cnt == 3) {
		if (!strcmp(fields[2], "show"))
			show_interfaces(client);
		else
			goto help;

		return CLI_CMD_OK;
	}

	if (fields_cnt != 4)
		goto help;

	if (!strcmp(fields[2], "add"))
		pppoe_server_start(fields[3], client);
	else if (!strcmp(fields[2], "del"))
		pppoe_server_stop(fields[3]);
	else
		goto help;
	
	return CLI_CMD_OK;
help:
	intf_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

//===================================

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe:\r\n");
	cli_sendv(client, "  active: %u\r\n", stat_active);
	cli_sendv(client, "  delayed PADO: %u\r\n", stat_delayed_pado);

	return CLI_CMD_OK;
}

static void __init init(void)
{
	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");
	cli_register_simple_cmd2(intf_exec, intf_help, 2, "pppoe", "interface");
}

