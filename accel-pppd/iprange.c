#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "triton.h"
#include "list.h"
#include "log.h"
#include "utils.h"

#include "iprange.h"

#include "memdebug.h"

struct iprange_t
{
	struct list_head entry;
	uint32_t begin;
	uint32_t end;
};

static int conf_disable = 0;

static LIST_HEAD(client_ranges);

/* Maximum IPv4 address length with CIDR notation but no extra 0,
 * e.g. "0xff.0xff.0xff.0xff/32".
 */
#define CIDR_MAXLEN 22


static void free_ranges(struct list_head *head)
{
	struct iprange_t *range;

	while (!list_empty(head)) {
		range = list_first_entry(head, typeof(*range), entry);
		list_del(&range->entry);
		_free(range);
	}
}

static int parse_iprange(const char *str, struct iprange_t **range)
{
	char ipstr[CIDR_MAXLEN + 1] = { 0 };
	struct iprange_t *_range;
	struct in_addr addr;
	const char *errmsg;
	char *suffix_str;
	uint32_t ipmin;
	uint32_t ipmax;
	bool is_cidr;

	/* Extra spaces and comments must have already been removed */
	if (strpbrk(str, " \t#")) {
		log_error("iprange: impossible to parse range \"%s\":"
			  " invalid space or comment character found\n",
			  str);
		return -1;
	}

	if (!strcmp(str, "disable"))
		goto disable;

	strncpy(ipstr, str, CIDR_MAXLEN + 1);
	if (ipstr[CIDR_MAXLEN] != '\0') {
		log_error("iprange: impossible to parse range \"%s\":"
			  " line too long\n",
			  str);
		return -1;
	}

	suffix_str = strpbrk(ipstr, "-/");
	if (!suffix_str) {
		log_error("iprange: impossible to parse range \"%s\":"
			  " unrecognised range format\n",
			  str);
		return -1;
	}

	is_cidr = *suffix_str == '/';
	*suffix_str = '\0';
	++suffix_str;

	if (u_parse_ip4addr(ipstr, &addr, &errmsg)) {
		log_error("iprange: impossible to parse range \"%s\":"
			  " invalid IPv4 address \"%s\"\n",
			  str, ipstr);
		return -1;
	}
	ipmin = ntohl(addr.s_addr);


	/* If is_cidr is set, range is given with CIDR notation,
	 * e.g. "192.0.2.0/24".
	 * If unset, range is an IP address where the last octet is replaced by
	 * an octet range, e.g. "192.0.2.0-255".
	 */
	if (is_cidr) {
		long int prefix_len;
		uint32_t mask;

		if (u_readlong(&prefix_len, suffix_str, 0, 32)) {
			log_error("iprange: impossible to parse range \"%s\":"
				  " invalid CIDR prefix length \"/%s\"\n",
				  str, suffix_str);
			return -1;
		}

		/* Interpret /0 as disable request */
		if (prefix_len == 0)
			goto disable;

		mask = UINT32_MAX << (32 - prefix_len);

		if (ipmin != (ipmin & mask)) {
			char buf[INET_ADDRSTRLEN] = { 0 };

			ipmin &= mask;
			addr.s_addr = htonl(ipmin);
			log_warn("iprange: first IP of range %s will be %s\n",
				 str, inet_ntop(AF_INET, &addr, buf,
						sizeof(buf)));
		}

		ipmax = ipmin | ~mask;
	} else {
		long int max;

		if (u_readlong(&max, suffix_str, ipmin & 0xff, 255)) {
			log_error("iprange: impossible to parse range \"%s\":"
				  " invalid upper bound \"-%s\"\n",
				  str, suffix_str);
			return -1;
		}

		ipmax = (ipmin & 0xffffff00) | max;
	}

	_range = _malloc(sizeof(*_range));
	if (!_range) {
		log_error("iprange: impossible to allocate range \"%s\":"
			  " memory allocation failed\n", str);
		return -1;
	}

	_range->begin = ipmin;
	_range->end = ipmax;
	*range = _range;

	return 0;

disable:
	*range = NULL;

	return 0;
}

static void load_ranges(struct list_head *list, const char *conf_sect)
{
	struct conf_sect_t *s =	conf_get_section(conf_sect);
	struct conf_option_t *opt;
	struct iprange_t *r;

	if (!s) {
		log_emerg("iprange: section '%s' not found in config file, pptp and l2tp probably will not work...\n", conf_sect);
		return;
	}

	list_for_each_entry(opt, &s->items, entry) {
		/* Ignore parsing errors, parse_iprange() already logs suitable
		 * error message.
		 */
		if (parse_iprange(opt->name, &r) < 0)
			continue;

		if (!r) {
			log_warn("iprange: iprange module disabled, improper IP address assignment may cause kernel soft lockup!\n");
			free_ranges(list);
			conf_disable = 1;

			return;
		}

		list_add_tail(&r->entry, list);
	}
}

static int check_range(struct list_head *list, in_addr_t ipaddr)
{
	struct iprange_t *r;
	uint32_t a = ntohl(ipaddr);

	list_for_each_entry(r, list, entry) {
		if (a >= r->begin && a <= r->end)
			return 0;
	}

	return -1;
}

int __export iprange_client_check(in_addr_t ipaddr)
{
	if (conf_disable)
		return 0;

	return check_range(&client_ranges, ipaddr);
}
int __export iprange_tunnel_check(in_addr_t ipaddr)
{
	if (conf_disable)
		return 0;

	return !check_range(&client_ranges, ipaddr);
}

static void iprange_init(void)
{
	load_ranges(&client_ranges, "client-ip-range");
}

DEFINE_INIT(10, iprange_init);
