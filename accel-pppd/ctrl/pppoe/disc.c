#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"

#include "pppoe.h"

#include "memdebug.h"

struct tree {
	pthread_mutex_t lock;
	struct rb_root root;
};

#define HASH_BITS 0xff
static struct tree *tree;

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static struct triton_md_handler_t disc_hnd;

static mempool_t pkt_pool;

int disc_sock;

void pppoe_disc_start(struct pppoe_serv_t *serv)
{
	struct rb_node **p, *parent = NULL;
	struct tree *t;
	int ifindex = serv->ifindex, i;
	struct pppoe_serv_t *n;

	t = &tree[ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);

	p = &t->root.rb_node;

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);
		i = n->ifindex;

		if (ifindex < i)
			p = &(*p)->rb_left;
		else if (ifindex > i)
			p = &(*p)->rb_right;
		else {
			pthread_mutex_unlock(&t->lock);
			log_error("pppoe: disc: attempt to add duplicate ifindex\n");
			return;
		}
	}

	rb_link_node(&serv->node, parent, p);
	rb_insert_color(&serv->node, &t->root);

	pthread_mutex_unlock(&t->lock);
}

void pppoe_disc_stop(struct pppoe_serv_t *serv)
{
	struct tree *t = &tree[serv->ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);
	rb_erase(&serv->node, &t->root);
	pthread_mutex_unlock(&t->lock);
}

static int forward(int ifindex, void *pkt, int len)
{
	struct pppoe_serv_t *n;
	struct tree *t = &tree[ifindex & HASH_BITS];
	struct rb_node **p = &t->root.rb_node, *parent = NULL;
	int r = 0;
	struct ethhdr *ethhdr = (struct ethhdr *)(pkt + 4);

	pthread_mutex_lock(&t->lock);

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);

		if (ifindex < n->ifindex)
			p = &(*p)->rb_left;
		else if (ifindex > n->ifindex)
			p = &(*p)->rb_right;
		else {
			if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) || !memcmp(ethhdr->h_dest, n->hwaddr, ETH_ALEN)) {
				*(int *)pkt = len;
				triton_context_call(&n->ctx, (triton_event_func)pppoe_serv_read, pkt);
				r = 1;
			}
			break;
		}
	}

	pthread_mutex_unlock(&t->lock);

	return r;
}

static void notify_down(int ifindex)
{
	struct pppoe_serv_t *n;
	struct tree *t = &tree[ifindex & HASH_BITS];
	struct rb_node **p = &t->root.rb_node, *parent = NULL;

	pthread_mutex_lock(&t->lock);

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);

		if (ifindex < n->ifindex)
			p = &(*p)->rb_left;
		else if (ifindex > n->ifindex)
			p = &(*p)->rb_right;
		else {
			triton_context_call(&n->ctx, (triton_event_func)_server_stop, n);
			break;
		}
	}

	pthread_mutex_unlock(&t->lock);
}

static int disc_read(struct triton_md_handler_t *h)
{
	uint8_t *pack = NULL;
	struct ethhdr *ethhdr;
	struct pppoe_hdr *hdr;
	int n;
	struct sockaddr_ll src;
	socklen_t slen = sizeof(src);

	while (1) {
		if (!pack)
			pack = mempool_alloc(pkt_pool);

		n = recvfrom(disc_sock, pack + 4, ETHER_MAX_LEN, MSG_DONTWAIT, (struct sockaddr *)&src, &slen);

		if (n < 0) {
			if (errno == EAGAIN)
				break;

			if (errno == ENETDOWN) {
				notify_down(src.sll_ifindex);
				continue;
			}

			log_error("pppoe: disc: read: %s\n", strerror(errno));
			continue;
		}

		ethhdr = (struct ethhdr *)(pack + 4);
		hdr = (struct pppoe_hdr *)(pack + 4 + ETH_HLEN);

		if (n < ETH_HLEN + sizeof(*hdr)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received (%i)\n", n);
			continue;
		}

		if (mac_filter_check(ethhdr->h_source)) {
			__sync_add_and_fetch(&stat_filtered, 1);
			continue;
		}

		//if (memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) && memcmp(ethhdr->h_dest, serv->hwaddr, ETH_ALEN))
		//	continue;

		if (!memcmp(ethhdr->h_source, bc_addr, ETH_ALEN)) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is broadcast)\n");
			continue;
		}

		if ((ethhdr->h_source[0] & 1) != 0) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is not unicast)\n");
			continue;
		}

		if (n < ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received\n");
			continue;
		}

		if (hdr->ver != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported version %i)\n", hdr->ver);
			continue;
		}

		if (hdr->type != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported type %i)\n", hdr->type);
		}

		if (forward(src.sll_ifindex, pack, n))
			pack = NULL;
	}

	mempool_free(pack);

	return 0;
}

static void disc_close(struct triton_context_t *ctx);

static struct triton_context_t disc_ctx = {
	.close = disc_close,
};

static struct triton_md_handler_t disc_hnd = {
	.read = disc_read,
};

static void disc_close(struct triton_context_t *ctx)
{
	triton_md_unregister_handler(&disc_hnd, 1);
	triton_context_unregister(ctx);
}

static void init()
{
	struct sockaddr_ll addr;
	int i, f = 1;

	pkt_pool = mempool_create(ETHER_MAX_LEN + 4);

	tree = malloc((HASH_BITS + 1) * sizeof(struct tree));
	for (i = 0; i <= HASH_BITS; i++) {
		pthread_mutex_init(&tree[i].lock, NULL);
		tree[i].root = RB_ROOT;
	}

	disc_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC));
	if (disc_sock < 0)
		return;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_PPP_DISC);

	setsockopt(disc_sock, SOL_SOCKET, SO_BROADCAST, &f, sizeof(f));

	if (bind(disc_sock, (struct sockaddr *)&addr, sizeof(addr))) {
		log_error("pppoe: disc: bind: %s\n", strerror(errno));
		close(disc_sock);
		return;
	}

	fcntl(disc_sock, F_SETFL, O_NONBLOCK);
	fcntl(disc_sock, F_SETFD, FD_CLOEXEC);

	disc_hnd.fd = disc_sock;

	triton_context_register(&disc_ctx, NULL);
	triton_md_register_handler(&disc_ctx, &disc_hnd);
	triton_md_enable_handler(&disc_hnd, MD_MODE_READ);
	triton_context_wakeup(&disc_ctx);
}

DEFINE_INIT(1, init);


