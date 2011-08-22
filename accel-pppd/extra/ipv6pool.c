#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <endian.h>

#include "ipdb.h"
#include "list.h"
#include "log.h"
#include "spinlock.h"

#include "memdebug.h"


#define INTF_ID_FIXED  0
#define INTF_ID_RANDOM 1
#define INTF_ID_CSID   2
#define INTF_ID_IPV4   3

static int conf_intf_id = INTF_ID_FIXED;
static uint64_t conf_intf_id_val = 2;

struct ippool_item_t
{
	struct list_head entry;
	struct ipv6db_item_t it;
};

static LIST_HEAD(ippool);
static spinlock_t pool_lock = SPINLOCK_INITIALIZER;
static struct ipdb_t ipdb;
static int urandom_fd;

static void generate_pool(struct in6_addr *addr, int mask, int prefix_len)
{
	struct ippool_item_t *it;
	uint64_t ip, endip, step;

	ip = be64toh(*(uint64_t *)addr->s6_addr);
	endip = ip | ((1llu << (64 - mask)) - 1);
	step = 1 << (64 - prefix_len);
	
	for (; ip <= endip; ip += step) {
		it = malloc(sizeof(*it));
		*(uint64_t *)it->it.addr.s6_addr = htobe64(ip);
		list_add_tail(&it->entry, &ippool);
	}
}

static void add_prefix(const char *_val)
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
	
	if (mask < 7 || mask > 64)
		goto err;
	
	if (sscanf(ptr2 + 1, "%i", &prefix_len) != 1)
		goto err;
	
	if (prefix_len > 64  || prefix_len < mask)
		goto err;
	
	generate_pool(&addr, mask, prefix_len);

	_free(val);
	return;
	
err:
	log_error("ipv6_pool: failed to parse '%s'\n", _val);
	_free(val);
}

static void generate_intf_id(struct ppp_t *ppp, struct in6_addr *addr)
{
	char str[4];
	int i, n;
	
	switch (conf_intf_id) {
		case INTF_ID_FIXED:
			*(uint64_t *)(&addr->s6_addr32[2]) = conf_intf_id_val;
			break;
		case INTF_ID_RANDOM:
			read(urandom_fd, &addr->s6_addr32[2], 8);
			break;
		case INTF_ID_CSID:
			break;
		case INTF_ID_IPV4:
			for (i = 0; i < 4; i++) {
				sprintf(str, "%i", (ppp->peer_ipaddr >> (i*8)) & 0xff);
				sscanf(str, "%x", &n);
				addr->s6_addr16[4 + i] = htons(n);
			}
	}
}

static struct ipv6db_item_t *get_ip(struct ppp_t *ppp)
{
	struct ippool_item_t *it;

	spin_lock(&pool_lock);
	if (!list_empty(&ippool)) {
		it = list_entry(ippool.next, typeof(*it), entry);
		list_del(&it->entry);
	} else
		it = NULL;
	spin_unlock(&pool_lock);

	if (it)
		generate_intf_id(ppp, &it->it.addr);

	return it ? &it->it : NULL;
}

static void put_ip(struct ppp_t *ppp, struct ipv6db_item_t *it)
{
	struct ippool_item_t *pit = container_of(it, typeof(*pit), it);

	spin_lock(&pool_lock);
	list_add_tail(&pit->entry, &ippool);
	spin_unlock(&pool_lock);
}

static struct ipdb_t ipdb = {
	.get_ipv6 = get_ip,
	.put_ipv6 = put_ip,
};

static uint64_t parse_intfid(const char *opt)
{
	union {
		uint64_t u64;
		uint16_t u16[4];
	} u;

	int n[4];
	int i;

	if (sscanf(opt, "%x:%x:%x:%x", &n[0], &n[1], &n[2], &n[3]) != 4)
		goto err;
	
	for (i = 0; i < 4; i++) {
		if (n[i] < 0 || n[i] > 0xffff)
			goto err;
		u.u16[i] = htons(n[i]);
	}

	return u.u64;

err:
	log_error("ipv6pool: failed to parse intf-id\n");
	conf_intf_id = INTF_ID_RANDOM;
	return 0;
}

static void ippool_init(void)
{
	struct conf_sect_t *s = conf_get_section("ipv6-pool");
	struct conf_option_t *opt;
	
	if (!s)
		return;
	
	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "intf-id")) {
			if (!strcmp(opt->val, "random"))
				conf_intf_id = INTF_ID_RANDOM;
			else if (!strcmp(opt->val, "calling-sid"))
				conf_intf_id = INTF_ID_CSID;
			else if (!strcmp(opt->val, "ipv4"))
				conf_intf_id = INTF_ID_IPV4;
			else {
				conf_intf_id = INTF_ID_FIXED;
				conf_intf_id_val = parse_intfid(opt->val);
			}
		}
		if (opt->val)
			continue;
		add_prefix(opt->name);
	}

	urandom_fd = open("/dev/urandom", O_RDONLY);

	ipdb_register(&ipdb);
}

DEFINE_INIT(101, ippool_init);

