#include <rte_config.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_distributor.h>
#include <rte_debug.h>

#include "init.h"
#include "kni_dev.h"
#include "event.h"
#include "log.h"

#define BURST_SIZE 32

#define MBUF_DROP 255

static struct rte_distributor *d;
static int term;
static int port_cnt;

struct xmit_buf {
	struct rte_mbuf *bufs[BURST_SIZE];
	int cnt;
};

int distributor_init(int ded)
{
	d = rte_distributor_create("distributor", rte_socket_id(), rte_lcore_count() - ded);
	return d == NULL;
}

static void flush_port(int port, struct xmit_buf *xb)
{
	int nb;

	if (likely(port < port_cnt))
		nb = rte_eth_tx_burst(port, 0, xb->bufs, xb->cnt);
	else
		nb = kni_dev_tx_burst(port - port_cnt, 0, xb->bufs, xb->cnt);

	if (unlikely(nb < xb->cnt)) {
		do {
			rte_pktmbuf_free(xb->bufs[nb]);
		} while (++nb < xb->cnt);
	}
}

static void distributor_tx(struct rte_mbuf **bufs, int nb, struct xmit_buf *xmit_bufs)
{
	struct rte_mbuf *mb;
	int i, p;

	_mm_prefetch(bufs[0], 0);
	_mm_prefetch(bufs[1], 0);
	_mm_prefetch(bufs[2], 0);
	for (i = 0; i < nb; i++) {
		_mm_prefetch(bufs[i + 3], 0);

		mb = bufs[i];

		p = mb->port;

		if (likely(p != MBUF_DROP)) {
			struct xmit_buf *xb = &xmit_bufs[p];
			xb->bufs[xb->cnt++] = mb;
			if (xb->cnt == BURST_SIZE)
				flush_port(p, xb);
		} else
			rte_pktmbuf_free(mb);
	}
}

void distributor_loop(int chk_event)
{
	int kni_port_cnt = kni_dev_count();
	struct rte_mbuf *bufs[BURST_SIZE*2];
	int port, nb, i;
	struct xmit_buf *xmit_bufs;
	int tot_port_cnt;
	struct xmit_buf *xb;

	port_cnt = rte_eth_dev_count();
	tot_port_cnt = port_cnt + kni_port_cnt;

	xmit_bufs = rte_malloc(NULL, (tot_port_cnt * sizeof(struct xmit_buf)), 0);

	for (i = 0; i < tot_port_cnt; i++)
		xmit_bufs[i].cnt = 0;

	while (!term) {
		for (port = 0; port < port_cnt; port++) {
			nb = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

			if (likely(nb))
				rte_distributor_process(d, bufs, nb);

			nb = rte_distributor_returned_pkts(d, bufs, BURST_SIZE*2);

			if (likely(nb))
				distributor_tx(bufs, nb, xmit_bufs);
		}

		for (port = 0; port < kni_port_cnt; port++) {
			nb = kni_dev_rx_burst(port, 0, bufs, BURST_SIZE);

			if (likely(nb))
				rte_distributor_process(d, bufs, nb);

			nb = rte_distributor_returned_pkts(d, bufs, BURST_SIZE*2);

			if (likely(nb))
				distributor_tx(bufs, nb, xmit_bufs);
		}

		_mm_prefetch(&xmit_bufs[0], 0);
		_mm_prefetch(&xmit_bufs[1], 0);
		_mm_prefetch(&xmit_bufs[2], 0);
		for (i = 0; i < tot_port_cnt; i++) {
			_mm_prefetch(&xmit_bufs[i + 3], 0);

			xb = &xmit_bufs[i];

			if (likely(xb->cnt))
				flush_port(i, xb);
		}

		if (chk_event)
			event_process(0);
	}
}

int lcore_worker(void *a)
{
	struct rte_mbuf *mb = NULL;

	while (!term) {
		mb = rte_distributor_get_pkt(d, 0, mb);
		mb->port = MBUF_DROP;
	}

	return 0;
}

int lcore_distributor(void *a)
{
	distributor_loop(0);

	return 0;
}
