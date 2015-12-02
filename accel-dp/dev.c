#include <string.h>

#include <rte_malloc.h>

#include "init.h"
#include "dev.h"

#define DEV_MAX 65536

static struct net_device **dev_list;
static int next_idx = 1;

struct net_device *netdev_get_by_index(int id)
{
	struct net_device *dev;

	if (id <= 0 || id >= DEV_MAX)
		return NULL;

	dev = dev_list[id];

	if (dev)
		++dev->refs;

	return dev;
}

struct net_device *netdev_alloc(const char *name, int priv_size, void (*setup)(struct net_device *dev))
{
	struct net_device *dev;
	int i;

	for (i = 0; i < DEV_MAX; i++) {
		if (dev_list[i] && !strcmp(dev_list[i]->name, name))
			return NULL;
	}

	for (; next_idx < DEV_MAX; next_idx++) {
		if (!dev_list[next_idx])
			break;
	}

	if (next_idx == DEV_MAX) {
		for (next_idx = 1; next_idx < DEV_MAX; next_idx++) {
			if (!dev_list[next_idx])
				break;
		}

		if (next_idx == DEV_MAX)
			return NULL;
	}

	dev = rte_malloc(NULL, sizeof(*dev) + priv_size, 0);
	strcpy(dev->name, name);
	dev->index = next_idx;

	dev->refs = 1;
	dev->destructor = netdev_free;

	if (setup)
		setup(dev);

	dev_list[next_idx] = dev;

	if (++next_idx == DEV_MAX)
		next_idx = 1;

	return dev;
}

void netdev_unregister(struct net_device *dev)
{
	dev_list[dev->index] = NULL;

	netdev_put(dev);
}

void netdev_free(struct net_device *dev)
{
	rte_free(dev);
}

void netdev_put(struct net_device *dev)
{
	if (--dev->refs == 0)
		dev->destructor(dev);
}

static void init()
{
	dev_list = rte_zmalloc(0, DEV_MAX * sizeof(void *), 0);
}

DEFINE_INIT(1, init);
