#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <endian.h>

#include "events.h"
#include "ipdb.h"
#include "list.h"
#include "log.h"
#include "spinlock.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

enum ippool_type
{
    IPPOOL_ADDRESS,
    IPPOOL_PREFIX
};

struct ippool_t
{
	struct list_head entry;
	char *name;
	struct list_head gw_list;
	struct list_head items;
	struct ippool_t *next;
	spinlock_t lock;
};

struct ippool_item_t
{
	struct list_head entry;
	struct ippool_t *pool;
	struct ipv6db_item_t it;
};

struct dppool_item_t
{
	struct list_head entry;
	struct ippool_t *pool;
	struct ipv6db_prefix_t it;
};

#ifdef RADIUS
static int conf_vendor = 0;
static int conf_dppool_attr = 171; // Delegated-IPv6-Prefix-Pool
static int conf_ippool_attr = 172; // Stateful-IPv6-Address-Pool
#endif

static LIST_HEAD(ippool_list);
static LIST_HEAD(dppool_list);
static struct ipdb_t ipdb;
static struct in6_addr conf_gw_addr;
static struct ippool_t *def_ippool;
static struct ippool_t *def_dppool;

static void in6_addr_add(struct in6_addr *res, const struct in6_addr *arg)
{
	uint16_t n = 0;
	int i;

	for (i = 15; i >= 0; i--) {
		n = (uint16_t)res->s6_addr[i] + arg->s6_addr[i] + (n >> 8);
		res->s6_addr[i] = n & 0xff;
	}
}

static int in6_addr_cmp(const struct in6_addr *n1, const struct in6_addr *n2)
{
	int i;

	for (i = 0; i < 16; i++) {
		if (n1->s6_addr[i] < n2->s6_addr[i])
			return -1;
		if (n1->s6_addr[i] > n2->s6_addr[i])
			return 1;
	}

	return 0;
}

static struct ippool_t *create_pool(enum ippool_type type, char *name)
{
	struct ippool_t *pool = malloc(sizeof(*pool));
	struct list_head *pool_list = (type == IPPOOL_PREFIX) ? &dppool_list : &ippool_list;

	memset(pool, 0, sizeof(*pool));
	pool->name = name;

	INIT_LIST_HEAD(&pool->items);
	spinlock_init(&pool->lock);

	if (name)
		list_add_tail(&pool->entry, pool_list);

	return pool;
}

static struct ippool_t *find_pool(enum ippool_type type, char *name, int create)
{
	struct ippool_t *pool;
	struct list_head *pool_list = (type == IPPOOL_PREFIX) ? &dppool_list : &ippool_list;

	list_for_each_entry(pool, pool_list, entry) {
		if (!strcmp(pool->name, name))
			return pool;
	}

	if (create)
		return create_pool(type, name);

	return NULL;
}

static void generate_ippool(struct ippool_t *pool, struct in6_addr *addr, int mask, int prefix_len)
{
	struct ippool_item_t *it;
	struct ipv6db_addr_t *a;
	struct in6_addr ip, end, step;

	memcpy(&ip, addr, sizeof(ip));

	memcpy(&end, addr, sizeof(end));
	if (mask > 64)
		*(uint64_t *)(end.s6_addr + 8) = htobe64(be64toh(*(uint64_t *)(end.s6_addr + 8)) | ((1llu << (128 - mask)) - 1));
	else {
		memset(end.s6_addr + 8, 0xff, 8);
		*(uint64_t *)end.s6_addr = htobe64(be64toh(*(uint64_t *)end.s6_addr) | ((1llu << (64 - mask)) - 1));
	}

	memset(&step, 0, sizeof(step));
	if (prefix_len > 64)
		*(uint64_t *)(step.s6_addr + 8) = htobe64(1llu << (128 - prefix_len));
	else
		*(uint64_t *)step.s6_addr = htobe64(1llu << (64 - prefix_len));

	while (in6_addr_cmp(&ip, &end) <= 0) {
		it = malloc(sizeof(*it));
		memset(it, 0, sizeof(*it));
		it->pool = pool;
		it->it.owner = &ipdb;
		INIT_LIST_HEAD(&it->it.addr_list);
		a = malloc(sizeof(*a));
		memset(a, 0, sizeof(*a));
		memcpy(&a->addr, &ip, sizeof(ip));
		a->prefix_len = prefix_len;
		list_add_tail(&a->entry, &it->it.addr_list);
		list_add_tail(&it->entry, &pool->items);
		in6_addr_add(&ip, &step);
	}
}

static void generate_dppool(struct ippool_t *pool, struct in6_addr *addr, int mask, int prefix_len)
{
	struct dppool_item_t *it;
	struct in6_addr ip, end, step;
	struct ipv6db_addr_t *a;

	memcpy(&ip, addr, sizeof(ip));

	memcpy(&end, addr, sizeof(end));
	if (mask > 64)
		*(uint64_t *)(end.s6_addr + 8) = htobe64(be64toh(*(uint64_t *)(end.s6_addr + 8)) | ((1llu << (128 - mask)) - 1));
	else {
		memset(end.s6_addr + 8, 0xff, 8);
		*(uint64_t *)end.s6_addr = htobe64(be64toh(*(uint64_t *)end.s6_addr) | ((1llu << (64 - mask)) - 1));
	}

	memset(&step, 0, sizeof(step));
	if (prefix_len > 64)
		*(uint64_t *)(step.s6_addr + 8) = htobe64(1llu << (128 - prefix_len));
	else
		*(uint64_t *)step.s6_addr = htobe64(1llu << (64 - prefix_len));

	while (in6_addr_cmp(&ip, &end) <= 0) {
		it = malloc(sizeof(*it));
		memset(it, 0, sizeof(*it));
		it->pool = pool;
		it->it.owner = &ipdb;
		INIT_LIST_HEAD(&it->it.prefix_list);
		a = malloc(sizeof(*a));
		memset(a, 0, sizeof(*a));
		memcpy(&a->addr, &ip, sizeof(ip));
		a->prefix_len = prefix_len;
		list_add_tail(&a->entry, &it->it.prefix_list);
		list_add_tail(&it->entry, &pool->items);
		in6_addr_add(&ip, &step);
	}
}

static void add_prefix(enum ippool_type type, struct ippool_t *pool, const char *_val)
{
	char *val = _strdup(_val);
	char *ptr1, *ptr2;
	struct in6_addr addr;
	int prefix_len;
	int mask;

	ptr1 = strchr(val, '/');
	if (!ptr1)
		goto err;

	*ptr1 = 0;

	ptr2 = strchr(ptr1 + 1, ',');
	if (!ptr2)
		goto err;

	*ptr2 = 0;

	if (inet_pton(AF_INET6, val, &addr) == 0)
		goto err;

	if (sscanf(ptr1 + 1, "%i", &mask) != 1)
		goto err;

	if (mask < 7 || mask > 127)
		goto err;

	if (sscanf(ptr2 + 1, "%i", &prefix_len) != 1)
		goto err;

	if (prefix_len > 128  || prefix_len < mask)
		goto err;

	if (type == IPPOOL_PREFIX)
		generate_dppool(pool, &addr, mask, prefix_len);
	else
		generate_ippool(pool, &addr, mask, prefix_len);

	_free(val);
	return;

err:
	log_error("ipv6_pool: failed to parse '%s'\n", _val);
	_free(val);
}

static struct ipv6db_item_t *get_ip(struct ap_session *ses)
{
	struct ippool_item_t *it;
	struct ipv6db_addr_t *a;
	struct ippool_t *pool, *start;

	if (ses->ipv6_pool_name)
		pool = find_pool(IPPOOL_ADDRESS, ses->ipv6_pool_name, 0);
	else
		pool = def_ippool;

	if (!pool)
		return NULL;

	start = pool;
	do {
		spin_lock(&pool->lock);
		if (!list_empty(&pool->items)) {
			it = list_entry(pool->items.next, typeof(*it), entry);
			list_del(&it->entry);
		} else
			it = NULL;
		spin_unlock(&pool->lock);

		if (it) {
			a = list_entry(it->it.addr_list.next, typeof(*a), entry);
			if (a->prefix_len == 128) {
				memcpy(&it->it.intf_id, conf_gw_addr.s6_addr + 8, 8);
				memcpy(&it->it.peer_intf_id, a->addr.s6_addr + 8, 8);
			} else {
				it->it.intf_id = 0;
				it->it.peer_intf_id = 0;
			}

			return &it->it;
		}

		pool = pool->next;
	} while (pool && pool != start);

	return NULL;
}

static void put_ip(struct ap_session *ses, struct ipv6db_item_t *it)
{
	struct ippool_item_t *pit = container_of(it, typeof(*pit), it);

	spin_lock(&pit->pool->lock);
	list_add_tail(&pit->entry, &pit->pool->items);
	spin_unlock(&pit->pool->lock);
}

static struct ipv6db_prefix_t *get_dp(struct ap_session *ses)
{
	struct dppool_item_t *it;
	struct ippool_t *pool, *start;

	if (ses->dpv6_pool_name)
		pool = find_pool(IPPOOL_PREFIX, ses->dpv6_pool_name, 0);
	else
		pool = def_dppool;

	start = pool;
	do {
		spin_lock(&pool->lock);
		if (!list_empty(&pool->items)) {
			it = list_entry(pool->items.next, typeof(*it), entry);
			list_del(&it->entry);
		} else
			it = NULL;
		spin_unlock(&pool->lock);

		if (it)
			return &it->it;

		pool = pool->next;
	} while (pool && pool != start);

	return NULL;
}

static void put_dp(struct ap_session *ses, struct ipv6db_prefix_t *it)
{
	struct dppool_item_t *pit = container_of(it, typeof(*pit), it);

	spin_lock(&pit->pool->lock);
	list_add_tail(&pit->entry, &pit->pool->items);
	spin_unlock(&pit->pool->lock);
}

static struct ipdb_t ipdb = {
	.get_ipv6 = get_ip,
	.put_ipv6 = put_ip,
	.get_ipv6_prefix = get_dp,
	.put_ipv6_prefix = put_dp,
};

#ifdef RADIUS
static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct rad_attr_t *attr;
	struct ap_session *ses = ev->ses;

	list_for_each_entry(attr, &ev->reply->attrs, entry) {
		if (attr->attr->type != ATTR_TYPE_STRING)
			continue;
		if (attr->vendor && attr->vendor->id != conf_vendor)
			continue;
		if (!attr->vendor && conf_vendor)
			continue;

		if (conf_dppool_attr && conf_dppool_attr == attr->attr->id) {
			if (ses->dpv6_pool_name)
				_free(ses->dpv6_pool_name);
			ses->dpv6_pool_name = _strdup(attr->val.string);
		} else
		if (conf_ippool_attr && conf_ippool_attr == attr->attr->id) {
			if (ses->ipv6_pool_name)
				_free(ses->ipv6_pool_name);
			ses->ipv6_pool_name = _strdup(attr->val.string);
		}
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
	} else
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

static int parse_options(enum ippool_type type, const char *opt, struct ippool_t **pool, struct ippool_t **next)
{
	char *name, *ptr;

	name = strstr(opt, ",name=");
	if (name) {
		name += sizeof(",name=") - 1;
		ptr = strchrnul(name, ',');
		name = _strndup(name, ptr - name);
		if (!name)
			return -1;
		*pool = find_pool(type, name, 1);
	} else if (type == IPPOOL_PREFIX)
		*pool = def_dppool;
	else
		*pool = def_ippool;

	name = strstr(opt, ",next=");
	if (name) {
		name += sizeof(",next=") - 1;
		ptr = strchrnul(name, ',');
		name = strncpy(alloca(ptr - name + 1), name, ptr - name + 1);
		*next = find_pool(type, name, 0);
		if (!*next) {
			name = _strdup(name);
			if (!name)
				return -1;
			*next = find_pool(type, name, 1);
		}
	} else
		*next = NULL;

	return 0;
}

static void ippool_init1(void)
{
	ipdb_register(&ipdb);
}

static void ippool_init2(void)
{
	struct conf_sect_t *s = conf_get_section("ipv6-pool");
	struct conf_option_t *opt;
	struct ippool_t *pool, *next;
	char *val;
	enum ippool_type type;
#ifdef RADIUS
	int dppool_attr = 0, ippool_attr = 0;
#endif

	if (!s)
		return;

	def_ippool = create_pool(IPPOOL_ADDRESS, NULL);
	def_dppool = create_pool(IPPOOL_PREFIX, NULL);

	list_for_each_entry(opt, &s->items, entry) {
#ifdef RADIUS
		if (triton_module_loaded("radius")) {
			if (!strcmp(opt->name, "vendor")) {
				conf_vendor = parse_vendor_opt(opt->val);
				continue;
			} else if (!strcmp(opt->name, "attr-prefix")) {
				dppool_attr = parse_attr_opt(opt->val);
				continue;
			} else if (!strcmp(opt->name, "attr-address")) {
				ippool_attr = parse_attr_opt(opt->val);
				continue;
			}
		}
#endif
		if (!strcmp(opt->name, "gw-ip6-address")) {
			if (inet_pton(AF_INET6, opt->val, &conf_gw_addr) == 0)
				log_error("ipv6_pool: failed to parse '%s'\n", opt->raw);
			continue;
		} else if (!strcmp(opt->name, "delegate")) {
			type = IPPOOL_PREFIX;
			val = opt->val;
		} else {
			type = IPPOOL_ADDRESS;
			val = opt->name;
		}

		if (parse_options(type, opt->raw, &pool, &next)) {
			log_error("ipv6_pool: failed to parse '%s'\n", opt->raw);
			continue;
		}

		add_prefix(type, pool, val);

		if (next)
			pool->next = next;
	}

	list_for_each_entry(pool, &ippool_list, entry) {
		if (list_empty(&pool->items))
			log_warn("ipv6_pool: pool '%s' is empty or not defined\n", pool->name);
	}
	list_for_each_entry(pool, &dppool_list, entry) {
		if (list_empty(&pool->items))
			log_warn("ipv6_pool: delegate pool '%s' is empty or not defined\n", pool->name);
	}

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		if (conf_vendor || dppool_attr)
			conf_dppool_attr = dppool_attr;
		if (conf_vendor || ippool_attr)
			conf_ippool_attr = ippool_attr;
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
	}
#endif
}

DEFINE_INIT(51, ippool_init1);
DEFINE_INIT2(52, ippool_init2);
