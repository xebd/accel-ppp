#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "list.h"
#include "cli.h"
#include "triton.h"
#include "log.h"
#include "memdebug.h"

#include "pppoe.h"

struct mac_t
{
	struct list_head entry;
	uint8_t addr[ETH_ALEN];
};

static LIST_HEAD(mac_list);
static int type; // -1 - disabled, 1 - allow, 0 - denied
static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static const char *conf_mac_filter;

int mac_filter_check(const uint8_t *addr)
{
	struct mac_t *mac;
	int res = type;

	if (type == -1)
		return 0;

	pthread_rwlock_rdlock(&lock);
	list_for_each_entry(mac, &mac_list, entry) {
		if (memcmp(mac->addr, addr, ETH_ALEN))
			continue;
		res = !type;
		break;
	}
	pthread_rwlock_unlock(&lock);

	return res;
}

static int mac_filter_load(const char *opt)
{
	struct mac_t *mac;
	FILE *f;
	char *c;
	char *name = _strdup(opt);
	char *buf = _malloc(1024);
	int n[ETH_ALEN];
	int i, line = 0;

	c = strstr(name, ",");
	if (!c)
		goto err_inval;

	*c = 0;

	if (!strcmp(c + 1, "allow"))
		type = 1;
	else if (!strcmp(c + 1, "deny"))
		type = 0;
	else
		goto err_inval;

	f = fopen(name, "r");
	if (!f) {
		log_emerg("pppoe: open '%s': %s\n", name, strerror(errno));
		goto err;
	}
	
	conf_mac_filter = opt;

	pthread_rwlock_wrlock(&lock);
	while (!list_empty(&mac_list)) {
		mac = list_entry(mac_list.next, typeof(*mac), entry);
		list_del(&mac->entry);
		_free(mac);
	}

	while (fgets(buf, 1024, f)) {
		line++;
		if (buf[0] == '#' || buf[0] == ';' || buf[0] == '\n')
			continue;
		if (sscanf(buf, "%x:%x:%x:%x:%x:%x",
			n + 0, n + 1, n + 2, n + 3, n + 4, n + 5) != 6) {
			log_warn("pppoe: mac-filter:%s:%i: address is invalid\n", name, line);
			continue;
		}
		mac = _malloc(sizeof(*mac));
		for (i = 0; i < ETH_ALEN; i++) {
			if (n[i] > 255) {
				log_warn("pppoe: mac-filter:%s:%i: address is invalid\n", name, line);
				_free(mac);
				continue;
			}
			mac->addr[i] = n[i];
		}
		list_add_tail(&mac->entry, &mac_list);
	}
	pthread_rwlock_unlock(&lock);

	fclose(f);

	_free(name);
	_free(buf);

	return 0;

err_inval:
	log_emerg("pppoe: mac-filter format is invalid\n");
err:
	_free(name);
	_free(buf);
	return -1;
}

static int mac_filter_add(const char *addr, void *client)
{
	int n[ETH_ALEN];
	struct mac_t *mac;
	int i;

	if (sscanf(addr, "%x:%x:%x:%x:%x:%x",
		n + 0, n + 1, n + 2, n + 3, n + 4, n + 5) != 6) {
		return cli_send(client, "invalid format\r\n");
	}

	mac = _malloc(sizeof(*mac));
	for (i = 0; i < ETH_ALEN; i++) {
		if (n[i] > 255) {
			_free(mac);
			return cli_send(client, "invalid format\r\n");
		}
		mac->addr[i] = n[i];
	}

	pthread_rwlock_wrlock(&lock);
	list_add_tail(&mac->entry, &mac_list);
	pthread_rwlock_unlock(&lock);

	return 0;
}

static int mac_filter_del(const char *addr, void *client)
{
	int n[ETH_ALEN];
	uint8_t a[ETH_ALEN];
	struct mac_t *mac;
	int i;
	int found = 0;

	if (sscanf(addr, "%x:%x:%x:%x:%x:%x",
		n + 0, n + 1, n + 2, n + 3, n + 4, n + 5) != 6) {
		return cli_send(client, "invalid format\r\n");
	}

	for (i = 0; i < ETH_ALEN; i++) {
		if (n[i] > 255) {
			return cli_send(client, "invalid format\r\n");
		}
		a[i] = n[i];
	}

	pthread_rwlock_wrlock(&lock);
	list_for_each_entry(mac, &mac_list, entry) {
		if (memcmp(a, mac->addr, ETH_ALEN))
			continue;
		list_del(&mac->entry);
		_free(mac);
		found = 1;
		break;
	}
	pthread_rwlock_unlock(&lock);

	if (!found)
		return cli_send(client, "not found\r\n");

	return 0;
}

static int mac_filter_show(void *client)
{
	struct mac_t *mac;
	const char *filter_type;
	char buf[64];

	if (type == 0)
		filter_type = "deny";
	else if (type == 1)
		filter_type = "allow";
	else
		filter_type = "disabled";

	sprintf(buf, "filter type: %s\r\n", filter_type);

	if (cli_send(client, buf))
		return -1;

	pthread_rwlock_rdlock(&lock);
	list_for_each_entry(mac, &mac_list, entry) {
		sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x\r\n",
			mac->addr[0], mac->addr[1], mac->addr[2],
			mac->addr[3],	mac->addr[4], mac->addr[5]);
		if (cli_send(client, buf)) {
			pthread_rwlock_unlock(&lock);
			return -1;
		}
	}
	pthread_rwlock_unlock(&lock);

	return 0;
}

static int cmd_help(char * const *fields, int fields_cnt, void *client);
int cmd_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt == 2)
		return cmd_help(fields, fields_cnt, client);
	
	if (!strcmp(fields[2], "reload")) {
		if (!conf_mac_filter) {
			if (cli_send(client, "error: mac-filter was not specified in the config\r\n"))
				return CLI_CMD_FAILED;
		} else if (mac_filter_load(conf_mac_filter)) {
			if (cli_send(client, "error: check logs\r\n"))
				return CLI_CMD_FAILED;
		}
	} else if (!strcmp(fields[2], "add")) {
		if (fields_cnt != 4)
			return cmd_help(fields, fields_cnt, client);
		if (mac_filter_add(fields[3], client))
			return CLI_CMD_FAILED;
	} else if (!strcmp(fields[2], "del")) {
		if (fields_cnt != 4)
			return cmd_help(fields, fields_cnt, client);
		if (mac_filter_del(fields[3], client))
			return CLI_CMD_FAILED;
	} else if (!strcmp(fields[2], "show")) {
		if (mac_filter_show(client))
			return CLI_CMD_FAILED;
	}
	return CLI_CMD_OK;
}

static int cmd_help(char * const *fields, int fields_cnt, void *client)
{
	if (cli_send(client, "pppoe mac-filter reload - reload mac-filter file\r\n"))
		return -1;
	
	if (cli_send(client, "pppoe mac-filter add <address> - add address to mac-filter list\r\n"))
		return -1;
	
	if (cli_send(client, "pppoe mac-filter del <address> - delete address from mac-filter list\r\n"))
		return -1;
	
	if (cli_send(client, "pppoe mac-filter show - show current mac-filter list\r\n"))
		return -1;

	return 0;
}

const char *cmd_hdr[] = {"pppoe", "mac-filter"};
static struct cli_simple_cmd_t cmd = {
	.hdr_len = 2,
	.hdr = cmd_hdr,
	.exec = cmd_exec,
	.help = cmd_help,
};

static void __init init(void)
{
	const char *opt = conf_get_opt("pppoe", "mac-filter");
	if (!opt || mac_filter_load(opt))
		type = -1;
	
	cli_register_simple_cmd(&cmd);
}

