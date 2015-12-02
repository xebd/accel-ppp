#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include "init.h"
#include "conf_file.h"
#include "common.h"
#include "dev.h"
#include "kni_dev.h"

#include "iputils.h"

struct knidev {
	int port;
	int xport;
	struct net_device *dev;
	struct rte_kni *kni;
	int ifindex;
};

static int kni_cnt;
static struct knidev **dev_list;

int kni_dev_count()
{
	return kni_cnt;
}

uint16_t kni_dev_rx_burst(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, const uint16_t nb_pkts)
{
	return rte_kni_rx_burst(dev_list[port_id]->kni, rx_pkts, nb_pkts);
}

uint16_t kni_dev_tx_burst(uint8_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	return rte_kni_tx_burst(dev_list[port_id]->kni, tx_pkts, nb_pkts);
}

static void knidev_xmit(struct rte_mbuf *mbuf, struct net_device *dev)
{
	struct knidev *kni_dev = netdev_priv(dev);

	mbuf->port = kni_dev->xport;
}

static int kni_change_mtu(uint8_t port, unsigned mtu)
{
	return 0;
}

static int kni_config_network_if(uint8_t port, uint8_t if_up)
{
	return 0;
}

static int parse_ip_addr(const char *str, in_addr_t *addr, int *mask)
{
	char *ptr = strchr(str, '/');
	char tmp[32];

	if (ptr) {
		memcpy(tmp, str, ptr - str);
		tmp[ptr - str] = 0;
		*addr = inet_addr(tmp);
		*mask = atoi(ptr + 1);
		if (*mask <= 0 || *mask > 32)
			return -1;
	} else {
		*addr = inet_addr(str);
		*mask = 32;
	}

	return *addr == INADDR_NONE;
}

struct ifconfig_arg {
	struct knidev *dev;
	struct conf_opt *opt;
	int err;
};

static void *kni_ifconfig(void *a)
{
	struct ifconfig_arg *arg = a;
	struct knidev *dev = arg->dev;
	struct conf_opt *opt = arg->opt;
	struct ifreq ifr;
	const char *opt1;
	in_addr_t addr;
	int mask;

	strcpy(ifr.ifr_name, opt->name);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr, sizeof(ifr))) {
		fprintf(stderr, "%s: SIOCGIFINDEX: %s\n", opt->name, strerror(errno));
		arg->err = errno;
		return NULL;
	}

	dev->ifindex = ifr.ifr_ifindex;

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr, sizeof(ifr));

	ifr.ifr_flags |= IFF_UP | IFF_NOARP;

	while (ioctl(sock_fd, SIOCSIFFLAGS, &ifr, sizeof(ifr)))
		sleep(1);

	opt1 = conf_get_subopt(opt, "ip-addr");
	if (opt1) {
		if (parse_ip_addr(opt1, &addr, &mask)) {
			arg->err = EINVAL;
			return NULL;
		}

		ipaddr_add(dev->ifindex, addr, mask);
	}

	arg->err = 0;

	return NULL;
}

int kni_dev_init(struct rte_mempool *mbuf_pool)
{
	struct conf_sect *s = conf_get_sect("interface");
	struct conf_opt *opt;
	struct rte_kni_conf conf;
	struct rte_kni_ops ops;
	struct rte_kni *kni;
	struct net_device *dev;
	struct knidev *knidev;
	pthread_t tid;
	struct ifconfig_arg arg;
	int i = 0, x = rte_eth_dev_count();

	for (opt = s->opt; opt; opt = opt->next) {
		const char *busid = conf_get_subopt(opt, "busid");
		if (!strcmp(busid, "kni"))
			kni_cnt++;
	}

	if (!kni_cnt)
		return 0;

	rte_kni_init(kni_cnt);

	dev_list = rte_malloc(NULL, kni_cnt * sizeof(void *), 0);

	memset(&conf, 0, sizeof(conf));
	memset(&ops, 0, sizeof(ops));

	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_if;

	for (opt = s->opt; opt; opt = opt->next) {
		const char *busid = conf_get_subopt(opt, "busid");
		if (strcmp(busid, "kni"))
			continue;

		strcpy(conf.name, opt->name);
		conf.group_id = i;
		conf.mbuf_size = ETHER_MAX_LEN + 8;

		ops.port_id = i;

		kni = rte_kni_alloc(mbuf_pool, &conf, &ops);

		if (!kni) {
			fprintf(stderr, "failed to create %s\n", opt->name);
			return -1;
		}

		dev = netdev_alloc(opt->name, sizeof(*knidev), NULL);
		dev->xmit = knidev_xmit;
		knidev = netdev_priv(dev);
		knidev->port = i;
		knidev->xport = i + x;
		knidev->dev = dev;
		knidev->kni = kni;

		dev_list[i] = knidev;

		arg.dev = knidev;
		arg.opt = opt;
		arg.err = -1;

		pthread_create(&tid, NULL, kni_ifconfig, &arg);

		while (arg.err == -1)
			rte_kni_handle_request(kni);

		pthread_join(tid, NULL);

		if (arg.err != 0)
			return -1;
	}

	return 0;
}

