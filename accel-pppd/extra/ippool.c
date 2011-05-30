#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "ipdb.h"
#include "list.h"
#include "spinlock.h"

#include "memdebug.h"

struct ippool_item_t
{
	struct list_head entry;
	struct ipdb_item_t it;
};

struct ipaddr_t
{
	struct list_head entry;
	in_addr_t addr;
};

static LIST_HEAD(gw_list);
static LIST_HEAD(tunnel_list);
static LIST_HEAD(ippool);
static spinlock_t pool_lock = SPINLOCK_INITIALIZER;
static struct ipdb_t ipdb;

static in_addr_t conf_gw_ip_address;
static int cnt;

static void parse_gw_ip_address(const char *val)
{
	if (!val)
		return;
	
	conf_gw_ip_address = inet_addr(val);
}

//parses ranges like x.x.x.x/mask
static int parse1(const char *str, uint32_t *begin, uint32_t *end)
{
	int n, f1, f2, f3, f4, m, mask = 0;
	
	n = sscanf(str, "%u.%u.%u.%u/%u",&f1, &f2, &f3, &f4, &m);
	if (n != 5)
		return -1;
	if (f1 > 255)
		return -1;
	if (f2 > 255)
		return -1;
	if (f3 > 255)
		return -1;
	if (f4 > 255)
		return -1;
	if (m == 0 || m > 32)
		return -1;
	
	*begin = (f4 << 24) | (f3 << 16) | (f2 << 8) | f1;

	mask = htonl(~((1 << (32 - m)) - 1));
	*end = ntohl(*begin | ~mask);
	*begin = ntohl(*begin);

	return 0;
}

//parses ranges like x.x.x.x-y
static int parse2(const char *str, uint32_t *begin, uint32_t *end)
{
	int n, f1, f2, f3, f4, m;

	n = sscanf(str, "%u.%u.%u.%u-%u",&f1, &f2, &f3, &f4, &m);
	if (n != 5)
		return -1;
	if (f1 > 255)
		return -1;
	if (f2 > 255)
		return -1;
	if (f3 > 255)
		return -1;
	if (f4 > 255)
		return -1;
	if (m < f4 || m > 255)
		return -1;
	
	*begin = ntohl((f4 << 24) | (f3 << 16) | (f2 << 8) | f1);
	*end = ntohl((m << 24) | (f3 << 16) | (f2 << 8) | f1);

	return 0;
}

static void add_range(struct list_head *list, const char *name)
{
	uint32_t i,startip, endip;
	struct ipaddr_t *ip;

	if (parse1(name, &startip, &endip))
		if (parse2(name, &startip, &endip)) {
			fprintf(stderr, "ippool: cann't parse '%s'\n", name);
			_exit(EXIT_FAILURE);
		}

	for (i = startip; i <= endip; i++) {
		ip = malloc(sizeof(*ip));
		ip->addr = htonl(i);
		list_add_tail(&ip->entry, list);
		cnt++;
	}
}

static void generate_pool(void)
{
	struct ippool_item_t *it;
	struct ipaddr_t *addr = NULL;
	struct ipaddr_t *peer_addr;

	while (1) {
		if (list_empty(&tunnel_list))
			break;
		else {
			peer_addr = list_entry(tunnel_list.next, typeof(*peer_addr), entry);
			list_del(&peer_addr->entry);
		}

		if (!conf_gw_ip_address) {
			if (list_empty(&gw_list))
				break;
			else {
				addr = list_entry(gw_list.next, typeof(*addr), entry);
				list_del(&addr->entry);
			}
		}

		it = malloc(sizeof(*it));
		if (!it) {
			fprintf(stderr, "ippool: out of memory\n");
			break;
		}

		it->it.owner = &ipdb;
		if (conf_gw_ip_address)
			it->it.addr = conf_gw_ip_address;
		else
			it->it.addr = addr->addr;

		it->it.peer_addr = peer_addr->addr;

		list_add_tail(&it->entry, &ippool);
	}
}

static struct ipdb_item_t *get_ip(struct ppp_t *ppp)
{
	struct ippool_item_t *it;

	spin_lock(&pool_lock);
	if (!list_empty(&ippool)) {
		it = list_entry(ippool.next, typeof(*it), entry);
		list_del(&it->entry);
	} else
		it = NULL;
	spin_unlock(&pool_lock);

	return it ? &it->it : NULL;
}

static void put_ip(struct ppp_t *ppp, struct ipdb_item_t *it)
{
	struct ippool_item_t *pit = container_of(it, typeof(*pit), it);

	spin_lock(&pool_lock);
	list_add_tail(&pit->entry, &ippool);
	spin_unlock(&pool_lock);
}

static struct ipdb_t ipdb = {
	.get = get_ip,
	.put = put_ip,
};

static void ippool_init(void)
{
	struct conf_sect_t *s = conf_get_section("ip-pool");
	struct conf_option_t *opt;
	
	if (!s)
		return;
	
	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "gw-ip-address"))
			parse_gw_ip_address(opt->val);
		else if (!strcmp(opt->name, "gw"))
			add_range(&gw_list, opt->val);
		else if (!strcmp(opt->name, "tunnel"))
			add_range(&tunnel_list, opt->val);
		else if (!opt->val)
			add_range(&tunnel_list, opt->name);
	}

	generate_pool();

	ipdb_register(&ipdb);
}

DEFINE_INIT(100, ippool_init);

