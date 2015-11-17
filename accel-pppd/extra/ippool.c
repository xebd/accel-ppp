#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "events.h"
#include "log.h"
#include "list.h"
#include "spinlock.h"
#include "backup.h"
#include "ap_session_backup.h"

#include "ipdb.h"

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
	uint32_t startip;
	uint32_t endip;
	void (*generate)(struct ippool_t *);
	spinlock_t lock;
};

struct ippool_item_t
{
	struct list_head entry;
	struct ippool_t *pool;
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
static int conf_shuffle;

static int cnt;
static LIST_HEAD(pool_list);
static struct ippool_t *def_pool;

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

static void add_range(struct ippool_t *p, struct list_head *list, const char *name, void (*generate)(struct ippool_t *))
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

	p->startip = startip;
	p->endip = endip;
	p->generate = generate;
}

static uint8_t get_random()
{
	static uint8_t buf[128];
	static int pos = 0;
	int r;

	if (pos == 0)
		read(urandom_fd, buf, 128);

	r = buf[pos++];

	if (pos == 128)
		pos = 0;

	return r;
}

static void generate_pool_p2p(struct ippool_t *p)
{
	struct ippool_item_t *it;
	struct ipaddr_t *addr = NULL;
	struct ipaddr_t *peer_addr;
	struct list_head *pos, *pos1 = p->tunnel_list.next, *pos2 = p->tunnel_list.prev;
	uint8_t r, t = 0;

	while (1) {
		if (list_empty(&p->tunnel_list))
			break;
		else {
			if (conf_shuffle) {
				if (pos1 == &p->tunnel_list)
					pos1 = pos1->next;

				if (pos2 == &p->tunnel_list)
					pos2 = pos2->prev;

				if (t++ < 10)
					r = get_random();
				else
					r = get_random()%64;

				if (r < 32)
					pos = pos1;
				else if (r < 64)
					pos = pos2;

				pos1 = pos1->next;
				pos2 = pos2->prev;

				if (r >= 64)
					continue;

				peer_addr = list_entry(pos, typeof(*peer_addr), entry);
				if (pos == pos1)
					pos1 = pos1->next;

				if (pos == pos2)
					pos2 = pos2->prev;

				list_del(&peer_addr->entry);
				t = 0;
			} else {
				peer_addr = list_entry(p->tunnel_list.next, typeof(*peer_addr), entry);
				list_del(&peer_addr->entry);
			}
		}

		if (!conf_gw_ip_address) {
			if (list_empty(&p->gw_list))
				break;
			else {
				addr = list_entry(p->gw_list.next, typeof(*addr), entry);
				list_del(&addr->entry);
			}
		}

		it = malloc(sizeof(*it));
		if (!it) {
			fprintf(stderr, "ippool: out of memory\n");
			break;
		}

		it->pool = p;
		it->it.owner = &ipdb;
		if (conf_gw_ip_address)
			it->it.addr = conf_gw_ip_address;
		else
			it->it.addr = addr->addr;

		it->it.peer_addr = peer_addr->addr;

		list_add_tail(&it->entry, &p->items);
	}
}

static void generate_pool_net30(struct ippool_t *p)
{
	struct ippool_item_t *it;
	struct ipaddr_t *addr[4];
	int i;

	while (1) {
		memset(addr, 0, sizeof(addr));

		for (i = 0; i < 4; i++) {
			if (list_empty(&p->tunnel_list))
				break;

			addr[i] = list_entry(p->tunnel_list.next, typeof(*addr[i]), entry);
			list_del(&addr[i]->entry);
		}

		if (!addr[2])
			break;


		it = malloc(sizeof(*it));
		if (!it) {
			log_emerg("ippool: out of memory\n");
			break;
		}

		it->pool = p;
		it->it.owner = &ipdb;
		it->it.addr = addr[1]->addr;
		it->it.peer_addr = addr[2]->addr;

		list_add_tail(&it->entry, &p->items);

		for (i = 0; i < 4; i++) {
			if (addr[i])
				free(addr[i]);
		}
	}

	for (i = 0; i < 4; i++) {
		if (addr[i])
			free(addr[i]);
	}
}


static struct ipv4db_item_t *get_ip(struct ap_session *ses)
{
	struct ippool_item_t *it;
	struct ippool_t *p;

	if (ses->ipv4_pool_name)
		p = find_pool(ses->ipv4_pool_name, 0);
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

	if (it) {
		if (ses->ctrl->ppp)
			it->it.addr = conf_gw_ip_address;
		else
			it->it.addr = 0;
	}

	return it ? &it->it : NULL;
}

static void put_ip(struct ap_session *ses, struct ipv4db_item_t *it)
{
	struct ippool_item_t *pit = container_of(it, typeof(*pit), it);

	spin_lock(&pit->pool->lock);
	list_add_tail(&pit->entry, &pit->pool->items);
	spin_unlock(&pit->pool->lock);
}

static struct ipdb_t ipdb = {
	.get_ipv4 = get_ip,
	.put_ipv4 = put_ip,
};

#ifdef USE_BACKUP
static void put_ip_b(struct ap_session *ses, struct ipv4db_item_t *it)
{
	_free(it);
}

static struct ipdb_t ipdb_b = {
	.put_ipv4 = put_ip_b,
};

static int session_save(struct ap_session *ses, struct backup_mod *m)
{
	if (!ses->ipv4 || ses->ipv4->owner != &ipdb)
		return -2;

	return 0;
}

static int session_restore(struct ap_session *ses, struct backup_mod *m)
{
	struct backup_tag *tag;
	in_addr_t addr = 0, peer_addr;
	struct ippool_t *p;
	struct ippool_item_t *it, *it0 = NULL;

	m = backup_find_mod(m->data, MODID_COMMON);

	list_for_each_entry(tag, &m->tag_list, entry) {
		switch (tag->id) {
			case SES_TAG_IPV4_ADDR:
				addr = *(in_addr_t *)tag->data;
				break;
			case SES_TAG_IPV4_PEER_ADDR:
				peer_addr = *(in_addr_t *)tag->data;
				break;
		}
	}

	spin_lock(&def_pool->lock);
	list_for_each_entry(it, &def_pool->items, entry) {
		if (peer_addr == it->it.peer_addr && addr == it->it.addr) {
			list_del(&it->entry);
			it0 = it;
			break;
		}
	}
	spin_unlock(&def_pool->lock);

	if (!it0) {
		list_for_each_entry(p, &pool_list, entry) {
			spin_lock(&p->lock);
			list_for_each_entry(it, &p->items, entry) {
				if (peer_addr == it->it.peer_addr && addr == it->it.addr) {
					list_del(&it->entry);
					it0 = it;
					break;
				}
			}
			spin_unlock(&p->lock);
			if (it0)
				break;
		}
	}

	if (it0)
		ses->ipv4 = &it0->it;
	else {
		ses->ipv4 = _malloc(sizeof(*ses->ipv4));
		ses->ipv4->addr = addr;
		ses->ipv4->peer_addr = peer_addr;
		ses->ipv4->owner = &ipdb_b;
	}

	return 0;
}

static struct backup_module backup_mod = {
	.id = MODID_IPPOOL,
	.save = session_save,
	.restore = session_restore,
};
#endif

#ifdef RADIUS
static int parse_attr(struct ap_session *ses, struct rad_attr_t *attr)
{
	if (conf_vendor == 9) {
		if (attr->len > sizeof("ip:addr-pool=") && memcmp(attr->val.string, "ip:addr-pool=", sizeof("ip:addr-pool=") - 1) == 0) {
			if (ses->ipv4_pool_name)
				_free(ses->ipv4_pool_name);
			ses->ipv4_pool_name = _strdup(attr->val.string + sizeof("ip:addr-pool=") - 1);
		}
	} else {
		if (ses->ipv4_pool_name)
			_free(ses->ipv4_pool_name);

		ses->ipv4_pool_name = _strdup(attr->val.string);
	}

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
		parse_attr(ev->ses, attr);
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

static void parse_options(const char *opt, char **pool_name, char **allocator)
{
	char *ptr1, *ptr2;
	int len;

	ptr1 = strstr(opt, "name=");
	if (ptr1) {
		for (ptr2 = ptr1 + 5; *ptr2 && *ptr2 != ','; ptr2++);
		len = ptr2 - (ptr1 + 5);
		*pool_name = _malloc(len + 1);
		memcpy(*pool_name, ptr1 + 5, len);
		(*pool_name)[len] = 0;
	}

	ptr1 = strstr(opt, "allocator=");
	if (ptr1) {
		for (ptr2 = ptr1 + 10; *ptr2 && *ptr2 != ','; ptr2++);
		len = ptr2 - (ptr1 + 10);
		*allocator = _malloc(len + 1);
		memcpy(*allocator, ptr1 + 10, len);
		(*allocator)[len] = 0;
	}

	if (!*pool_name) {
		ptr1 = strchr(opt, ',');
		if (!ptr1)
			return;

		for (ptr2 = ptr1 + 1; *ptr2 && *ptr2 != '='; ptr2++);
		if (*ptr2 == '=')
			return;

		*pool_name = _strdup(ptr1 + 1);
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
	char *pool_name = NULL;
	char *allocator = NULL;
	void (*generate)(struct ippool_t *pool);

	if (!s)
		return;

	def_pool = create_pool(NULL);

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
		else if (!strcmp(opt->name, "shuffle"))
			conf_shuffle = atoi(opt->val);
		else {
			pool_name = NULL;
			allocator = NULL;

			parse_options(opt->raw, &pool_name, &allocator);

			if (allocator) {
				if (strcmp(allocator, "p2p") == 0)
					generate = generate_pool_p2p;
				else if (strcmp(allocator, "net30") == 0)
					generate = generate_pool_net30;
				else {
					log_error("ipool: '%s': unknown allocator\n", opt->raw);
				}
			} else
				generate = generate_pool_p2p;

			p = pool_name ? find_pool(pool_name, 1) : def_pool;

			if (!strcmp(opt->name, "gw"))
				add_range(p, &p->gw_list, opt->val, generate);
			else if (!strcmp(opt->name, "tunnel"))
				add_range(p, &p->tunnel_list, opt->val, generate);
			else if (!opt->val || strchr(opt->name, ','))
				add_range(p, &p->tunnel_list, opt->name, generate);

			if (pool_name)
				_free(pool_name);

			if (allocator)
				_free(allocator);
		}
	}

	if (def_pool->generate)
		def_pool->generate(def_pool);

	list_for_each_entry(p, &pool_list, entry)
		p->generate(p);

#ifdef USE_BACKUP
	backup_register_module(&backup_mod);
#endif

#ifdef RADIUS
	if (triton_module_loaded("radius"))
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
#endif
}

DEFINE_INIT(51, ippool_init1);
DEFINE_INIT2(52, ippool_init2);

