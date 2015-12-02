#include <unistd.h>

#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include "init.h"
#include "conf_file.h"
#include "dev.h"

#define TX_RING_SIZE 512
#define RX_RING_SIZE 512

struct ethdev {
	int port;
};

static struct ethdev **dev_list;

static void ethdev_xmit(struct rte_mbuf *mbuf, struct net_device *dev)
{
	struct ethdev *eth_dev = netdev_priv(dev);

	mbuf->port = eth_dev->port;
}

int eth_dev_init(struct rte_mempool *mbuf_pool)
{
	struct conf_sect *s = conf_get_sect("interface");
	struct conf_opt *opt;
	int i, cnt = rte_eth_dev_count();
	struct rte_eth_dev_info info;
	char busid[64];
	const char *opt1;
	int rxd, txd;
	struct net_device *dev;
	struct ethdev *eth_dev;
	struct ether_addr addr;
	struct rte_eth_link link;
	struct rte_eth_conf conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_NONE,
			.max_rx_pkt_len = ETHER_MAX_LEN + 8,
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};

	dev_list = rte_malloc(NULL, cnt * sizeof(void *), 0);

	for (i = 0; i < cnt; i++) {
		rte_eth_dev_info_get(i, &info);

		sprintf(busid, "%04x:%02x:%02x.%i", info.pci_dev->addr.domain, info.pci_dev->addr.bus, info.pci_dev->addr.devid, info.pci_dev->addr.function);

		for (opt = s->opt; opt; opt = opt->next) {
			const char *opt_busid = conf_get_subopt(opt, "busid");
			if (!strcmp(opt_busid, busid) || !strcmp(opt_busid, busid + 5))
				break;
		}

		opt1 = conf_get_subopt(opt, "txd");
		if (opt1)
			txd = atoi(opt1);
		else
			txd = TX_RING_SIZE;

		opt1 = conf_get_subopt(opt, "rxd");
		if (opt1)
			rxd = atoi(opt1);
		else
			rxd = RX_RING_SIZE;

		if (rte_eth_dev_configure(i, 1, 1, &conf)) {
			fprintf(stderr, "%s: %s\n", busid, rte_strerror(rte_errno));
			return -1;
		}

		if (rte_eth_rx_queue_setup(i, 0, rxd, rte_eth_dev_socket_id(i), NULL, mbuf_pool)) {
			fprintf(stderr, "%s: %s\n", busid, rte_strerror(rte_errno));
			return -1;
		}

		if (rte_eth_tx_queue_setup(i, 0, txd, rte_eth_dev_socket_id(i), NULL)) {
			fprintf(stderr, "%s: %s\n", busid, rte_strerror(rte_errno));
			return -1;
		}

		if (rte_eth_dev_start(i)) {
			fprintf(stderr, "%s: %s\n", busid, rte_strerror(rte_errno));
			return -1;
		}

		rte_eth_link_get_nowait(i, &link);
		if (!link.link_status) {
			sleep(1);
			rte_eth_link_get_nowait(i, &link);
		}

		if (!link.link_status)
			printf("%s: link down\n", opt->name);

		rte_eth_macaddr_get(i, &addr);

		dev = netdev_alloc(opt->name, sizeof(*eth_dev), NULL);
		dev->xmit = ethdev_xmit;
		memcpy(dev->hwaddr, addr.addr_bytes, ETHER_ADDR_LEN);
		eth_dev = netdev_priv(dev);
		eth_dev->port = i;

		dev_list[i] = eth_dev;
	}

	return 0;
}
