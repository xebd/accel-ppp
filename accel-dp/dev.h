#ifndef __NET_DEVICE_H
#define __NET_DEVICE_H

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct rte_mbuf;

struct net_device {
	char name[IFNAMSIZ];
	int index;

	unsigned char hwaddr[6];

	int refs;

	void (*xmit)(struct rte_mbuf *mbuf, struct net_device *dev);
	void (*destructor)(struct net_device *dev);
};

struct net_device *netdev_get_by_index(int id);
void netdev_put(struct net_device *dev);
void netdev_free(struct net_device *dev);
struct net_device *netdev_alloc(const char *name, int priv_size, void (*setup)(struct net_device *dev));
void netdev_unregister(struct net_device *dev);

static inline void *netdev_priv(struct net_device *dev)
{
	return dev + 1;
}

#endif
