#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "events.h"
#include "ipdb.h"
#include "log.h"
#include "list.h"
#include "utils.h"
#include "spinlock.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

struct ippool_t
{
	struct list_head entry;
	char *name;
	struct list_head gw_list;
	struct list_head tunnel_list;
	struct list_head items;
	spinlock_t lock;
};

struct ippool_item_t
{
	struct list_head entry;
	struct ippool_t *pool;
	char *username;
	struct ipv4db_item_t it;
};

struct ipaddr_t
{
	struct list_head entry;
	in_addr_t addr;
};

static struct ipdb_t ipdb;

static in_addr_t conf_gw_ip_address;
static int conf_vendor = 0;
static int conf_attr = 88; // Framed-Pool

static int cnt;
static LIST_HEAD(pool_list);
static struct ippool_t *def_pool;

static struct ippool_t *persist_pool;
static FILE *persist_file;
static pthread_mutex_t persist_file_lock = PTHREAD_MUTEX_INITIALIZER;

struct ippool_t *create_pool(const char *name)
{
	struct ippool_t *p = malloc(sizeof(*p));

	memset(p, 0, sizeof(*p));
	if (name)
		p->name = strdup(name);
	INIT_LIST_HEAD(&p->gw_list);
	INIT_LIST_HEAD(&p->tunnel_list);
	INIT_LIST_HEAD(&p->items);
	spinlock_init(&p->lock);

	if (name)
		list_add_tail(&p->entry, &pool_list);

	return p;
}

struct ippool_t *find_pool(const char *name, int create)
{
	struct ippool_t *p;

	list_for_each_entry(p, &pool_list, entry) {
		if (!strcmp(p->name, name))
			return p;
	}

	if (create)
		return create_pool(name);
	
	return NULL;
}

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

	if (parse1(name, &startip, &endip)) {
		if (parse2(name, &startip, &endip)) {
			fprintf(stderr, "ippool: cann't parse '%s'\n", name);
			_exit(EXIT_FAILURE);
		}
	}

	for (i = startip; i <= endip; i++) {
		ip = malloc(sizeof(*ip));
		ip->addr = htonl(i);
		list_add_tail(&ip->entry, list);
		cnt++;
	}
}

static struct ippool_item_t *find_persist_item(const char *username)
{
	struct ippool_item_t *it;
	
	spin_lock(&persist_pool->lock);
	list_for_each_entry(it, &persist_pool->items, entry) {
		if (strcmp(it->username, username) == 0) {
			spin_unlock(&persist_pool->lock);
			return it;
		}
	}
	spin_unlock(&persist_pool->lock);

	return NULL;
}

static struct ippool_item_t *find_persist_item2(in_addr_t peer_addr)
{
	struct ippool_item_t *it;
	
	list_for_each_entry(it, &persist_pool->items, entry) {
		if (it->it.peer_addr == peer_addr)
			return it;
	}

	return NULL;
}

static void generate_pool(struct ippool_t *p)
{
	struct ippool_item_t *it;
	struct ipaddr_t *addr = NULL;
	struct ipaddr_t *peer_addr;

	while (1) {
		if (list_empty(&p->tunnel_list))
			break;
		else {
			peer_addr = list_entry(p->tunnel_list.next, typeof(*peer_addr), entry);
			list_del(&peer_addr->entry);
		}

		if (!conf_gw_ip_address) {
			if (list_empty(&p->gw_list))
				break;
			else {
				addr = list_entry(p->gw_list.next, typeof(*addr), entry);
				list_del(&addr->entry);
			}
		}

		it = find_persist_item2(peer_addr->addr);
		if (!it) {
			it = malloc(sizeof(*it));
			if (!it) {
				fprintf(stderr, "ippool: out of memory\n");
				break;
			}

			it->it.owner = &ipdb;
			it->it.peer_addr = peer_addr->addr;

			list_add_tail(&it->entry, &p->items);
		}
			
		it->pool = p;
		if (conf_gw_ip_address)
			it->it.addr = conf_gw_ip_address;
		else
			it->it.addr = addr->addr;
	}
}

static struct ipv4db_item_t *get_ip(struct ppp_t *ppp)
{
	struct ippool_item_t *it;
	struct ippool_t *p;
	const char *pool_name = NULL;

	it = find_persist_item(ppp->username);
	if (it)
		return &it->it;

	if (ppp->ipv4_pool_name)
		pool_name = ppp->ipv4_pool_name;
	else if (ppp->ctrl->def_pool)
		pool_name = ppp->ctrl->def_pool;

	if (pool_name)
		p = find_pool(pool_name, 0);
	else
		p = def_pool;

	if (!p)
		return NULL;

	spin_lock(&p->lock);
	if (!list_empty(&p->items)) {
		it = list_entry(p->items.next, typeof(*it), entry);
		list_del(&it->entry);
	} else
		it = NULL;
	spin_unlock(&p->lock);

	if (it && persist_file) {
		char addr[17];
		u_inet_ntoa(it->it.peer_addr, addr);
		pthread_mutex_lock(&persist_file_lock);
		fprintf(persist_file, "%s %s\n", ppp->username, addr);
		fflush(persist_file);
		pthread_mutex_unlock(&persist_file_lock);
		it->username = strdup(ppp->username);
		
		spin_lock(&persist_pool->lock);
		list_add_tail(&it->entry, &persist_pool->items);
		spin_unlock(&persist_pool->lock);
	}

	return it ? &it->it : NULL;
}

static void put_ip(struct ppp_t *ppp, struct ipv4db_item_t *it)
{
	struct ippool_item_t *pit = container_of(it, typeof(*pit), it);

	if (!pit->username) {
		spin_lock(&pit->pool->lock);
		list_add_tail(&pit->entry, &pit->pool->items);
		spin_unlock(&pit->pool->lock);
	}
}

static struct ipdb_t ipdb = {
	.get_ipv4 = get_ip,
	.put_ipv4 = put_ip,
};

#ifdef RADIUS
static int parse_attr(struct ppp_t *ppp, struct rad_attr_t *attr)
{
	if (attr->len > sizeof("ip:addr-pool=") && memcmp(attr->val.string, "ip:addr-pool=", sizeof("ip:addr-pool=") - 1) == 0)
		ppp->ipv4_pool_name = _strdup(attr->val.string + sizeof("ip:addr-pool=") - 1);
	else if (!attr->vendor)
		ppp->ipv4_pool_name = _strdup(attr->val.string);
	else
		return -1;
	
	return 0;
}

static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct rad_attr_t *attr;

	list_for_each_entry(attr, &ev->reply->attrs, entry) {
		if (attr->attr->type != ATTR_TYPE_STRING)
			continue;
		if (attr->vendor && attr->vendor->id != conf_vendor)
			continue;
		if (!attr->vendor && conf_vendor)
			continue;
		if (attr->attr->id != conf_attr)
			continue;
		if (parse_attr(ev->ppp, attr))
			continue;
		break;
	}
}

static int parse_attr_opt(const char *opt)
{
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (conf_vendor)
		vendor = rad_dict_find_vendor_id(conf_vendor);
	else
		vendor = NULL;

	if (conf_vendor) {
		if (vendor)
			attr = rad_dict_find_vendor_attr(vendor, opt);
		else
			attr = NULL;
	}else
		attr = rad_dict_find_attr(opt);

	if (attr)
		return attr->id;

	return atoi(opt);
}

static int parse_vendor_opt(const char *opt)
{
	struct rad_dict_vendor_t *vendor;

	vendor = rad_dict_find_vendor_name(opt);
	if (vendor)
		return vendor->id;
	
	return atoi(opt);
}
#endif

static void load_persist_pool(void)
{
	const char *opt;
	FILE *f = NULL;;
	LIST_HEAD(tmp);
	char str[1024];
	char *ptr, *ptr1;
	struct ippool_item_t *it;

	list_splice_init(&persist_pool->items, &tmp);
	
	opt = conf_get_opt("ip-pool", "persist");
	if (opt)
		f = fopen(opt, "r");
	
	if (f) {
		while (fgets(str, 1024, f)) {
			if (*str == '#' || *str == '\n')
				continue;

			ptr1 = NULL;
			for (ptr = str; *ptr; ptr++) {
				if (*ptr == ' ') {
					*ptr = 0;
					ptr1 = ptr + 1;
				} else if (*ptr == '\n') {
					*ptr = 0;
					break;
				}
			}

			if (!ptr1)
				continue;

			list_for_each_entry(it, &tmp, entry) {
				if (strcmp(it->username, str) == 0) {
					list_move(&it->entry, &persist_pool->items);
					goto found;
				}
			}

			it = malloc(sizeof(*it));
			it->it.owner = &ipdb;
			it->it.addr = conf_gw_ip_address;
			it->it.peer_addr = inet_addr(ptr1);
			it->pool = NULL;
			it->username = strdup(str);
			list_add_tail(&it->entry, &persist_pool->items);
found:
			{}
		}

		fclose(f);
	}
		
	if (persist_file)
		fclose(persist_file);

	persist_file = fopen(opt, "a");
	if (!persist_file)
		log_error("ippool: open %s: %s\n", opt, strerror(errno));

	while (!list_empty(&tmp)) {
		it = list_entry(tmp.next, typeof(*it), entry);
		free(it->username);
		it->username = NULL;
		if (it->pool)
			list_move(&it->entry, &it->pool->items);
		else {
			list_del(&it->entry);
			free(it);
		}
	}
}

static void ippool_init1(void)
{
	ipdb_register(&ipdb);
}

static void ippool_init2(void)
{
	struct conf_sect_t *s = conf_get_section("ip-pool");
	struct conf_option_t *opt;
	struct ippool_t *p;
	char *pool_name;
	
	if (!s)
		return;

	def_pool = create_pool(NULL);
	persist_pool = create_pool(NULL);

	load_persist_pool();

	list_for_each_entry(opt, &s->items, entry) {
#ifdef RADIUS
		if (triton_module_loaded("radius")) {
			if (!strcmp(opt->name, "vendor")) {
				conf_vendor = parse_vendor_opt(opt->val);
				continue;
			}
			
			if (!strcmp(opt->name, "attr")) {
				conf_attr = parse_attr_opt(opt->val);
				continue;
			}
		}
#endif
		if (!strcmp(opt->name, "gw-ip-address"))
			parse_gw_ip_address(opt->val);
		else {
			if (opt->val)
				pool_name = strchr(opt->val, ',');
			else
				pool_name = strchr(opt->name, ',');

			p = pool_name ? find_pool(pool_name + 1, 1) : def_pool;

			if (!strcmp(opt->name, "gw"))
				add_range(&p->gw_list, opt->val);
			else if (!strcmp(opt->name, "tunnel"))
				add_range(&p->tunnel_list, opt->val);
			else if (!opt->val)
				add_range(&p->tunnel_list, opt->name);
		}
	}

	generate_pool(def_pool);

	list_for_each_entry(p, &pool_list, entry)
		generate_pool(p);

#ifdef RADIUS
	if (triton_module_loaded("radius"))
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
#endif
	
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_persist_pool);
}

DEFINE_INIT(51, ippool_init1);
DEFINE_INIT2(52, ippool_init2);

