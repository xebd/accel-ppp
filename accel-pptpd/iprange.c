#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "triton.h"
#include "list.h"

#include "iprange.h"

struct iprange_t
{
	struct list_head entry;
	uint32_t prefix;
	uint32_t mask;
	uint32_t end;
};

static LIST_HEAD(client_ranges);
//static LIST_HEAD(tunnel_ranges);

//parses ranges like x.x.x.x/mask
static struct iprange_t *parse1(const char *str)
{
	int n,f1,f2,f3,f4,m;
	struct iprange_t *r;
	
	n = sscanf(str, "%u.%u.%u.%u/%u",&f1, &f2, &f3, &f4, &m);
	if (n != 5)
		return NULL;
	if (f1 > 255)
		return NULL;
	if (f1 > 255)
		return NULL;
	if (f1 > 255)
		return NULL;
	if (f1 > 255)
		return NULL;
	if (m == 0 || m > 32)
		return NULL;
	
	r = malloc(sizeof(*r));
	r->prefix = (f4 << 24) | (f3 << 16) | (f2 << 8) | f1;
	r->mask = 0;

	for (n = 0; n < m ; n++)
		r->mask |= 1 <<  n;
	
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
	
	r = malloc(sizeof(*r));
	r->prefix = (f4 << 24) | (f3 << 16) | (f2 << 8) | f1;
	r->end = (m << 24) | (f3 << 16) | (f2 << 8) | f1;
	r->mask = 0;

	return r;
}

static void load_ranges(struct list_head *list, const char *conf_sect)
{
	struct conf_sect_t *s =	conf_get_section(conf_sect);
	struct conf_option_t *opt;
	struct iprange_t *r;

	if (!s) {
		fprintf(stderr, "iprange: section '%s' not found in config file, pptp and l2tp probably will not work...\n", conf_sect);
		return;
	}

	list_for_each_entry(opt, &s->items, entry) {
		r = parse1(opt->name);
		if (!r)
			r = parse2(opt->name);
		if (!r) {
			fprintf(stderr, "iprange: cann't parse '%s' in '%s'\n", opt->name, conf_sect);
			_exit(EXIT_FAILURE);
		}
		list_add_tail(&r->entry, list);
	}
}

static int check_range(struct list_head *list, in_addr_t ipaddr)
{
	struct iprange_t *r;
	
	list_for_each_entry(r, list, entry) {
		if (r->mask) {
			if ((r->prefix & r->mask) == (ipaddr & r->mask))
				return 0;
		} else {
			if (ipaddr >= r->prefix && ipaddr <= r->end)
				return 0;
		}
	}

	return -1;
}

int __export iprange_client_check(in_addr_t ipaddr)
{
	return check_range(&client_ranges, ipaddr);
}
/*int __export iprange_tunnel_check(in_addr_t ipaddr)
{
	return check_range(&tunnel_ranges, ipaddr);
}*/

static void __init iprange_init(void)
{
	load_ranges(&client_ranges, "client-ip-range");
	//load_ranges(&tunnel_ranges, "tunnel-ip-range");
}

