#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "triton.h"
#include "list.h"
#include "log.h"

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
//static LIST_HEAD(tunnel_ranges);

//parses ranges like x.x.x.x/mask
static struct iprange_t *parse1(const char *str)
{
	int n,f1,f2,f3,f4,m;
	struct iprange_t *r;
	int mask;

	n = sscanf(str, "%u.%u.%u.%u/%u",&f1, &f2, &f3, &f4, &m);
	if (n != 5)
		return NULL;
	if (f1 > 255)
		return NULL;
	if (f2 > 255)
		return NULL;
	if (f3 > 255)
		return NULL;
	if (f4 > 255)
		return NULL;
	if (m > 32)
		return NULL;

	r = _malloc(sizeof(*r));
	r->begin = (f4 << 24) | (f3 << 16) | (f2 << 8) | f1;

	mask = htonl(~((1 << (32 - m)) - 1));
	r->end = ntohl(r->begin | ~mask);
	r->begin = ntohl(r->begin);

	return r;
}

//parses ranges like x.x.x.x-y
static struct iprange_t *parse2(const char *str)
{
	int n,f1,f2,f3,f4,m;
	struct iprange_t *r;

	n = sscanf(str, "%u.%u.%u.%u-%u",&f1, &f2, &f3, &f4, &m);
	if (n != 5)
		return NULL;
	if (f1 > 255)
		return NULL;
	if (f2 > 255)
		return NULL;
	if (f3 > 255)
		return NULL;
	if (f4 > 255)
		return NULL;
	if (m < f4 || m > 255)
		return NULL;

	r = _malloc(sizeof(*r));
	r->begin = ntohl((f4 << 24) | (f3 << 16) | (f2 << 8) | f1);
	r->end = ntohl((m << 24) | (f3 << 16) | (f2 << 8) | f1);

	return r;
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
		if (!strcmp(opt->name, "disable"))
			goto disable;
		r = parse1(opt->name);
		if (!r)
			r = parse2(opt->name);
		if (!r) {
			log_emerg("iprange: cann't parse '%s' in '%s'\n", opt->name, conf_sect);
			_exit(EXIT_FAILURE);
		}
		if (r->begin == r->end)
			goto disable;
		list_add_tail(&r->entry, list);
	}

	return;
disable:
	conf_disable = 1;
	log_emerg("iprange: iprange module disabled so improper ip address assigning may cause kernel soft lockup!\n");
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
	//load_ranges(&tunnel_ranges, "tunnel-ip-range");
}

DEFINE_INIT(10, iprange_init);
