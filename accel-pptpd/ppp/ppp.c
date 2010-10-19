#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "linux_ppp.h"

#include <openssl/md5.h>

#include "triton.h"

#include "events.h"
#include "ppp.h"
#include "ppp_fsm.h"
#include "log.h"

#include "memdebug.h"

int __export conf_ppp_verbose;

static LIST_HEAD(layers);
int __export sock_fd;

struct layer_node_t
{
	struct list_head entry;
	int order;
	struct list_head items;
};

static int ppp_chan_read(struct triton_md_handler_t*);
static int ppp_unit_read(struct triton_md_handler_t*);
static void init_layers(struct ppp_t *);
static void _free_layers(struct ppp_t *);
static void start_first_layer(struct ppp_t *);

void __export ppp_init(struct ppp_t *ppp)
{
	memset(ppp,0,sizeof(*ppp));
	INIT_LIST_HEAD(&ppp->layers);
	INIT_LIST_HEAD(&ppp->chan_handlers);
	INIT_LIST_HEAD(&ppp->unit_handlers);
	INIT_LIST_HEAD(&ppp->pd_list);
}

static void _free_ppp(struct ppp_t *ppp)
{
	_free(ppp->chan_buf);
	_free(ppp->unit_buf);

	if (ppp->username)
		_free(ppp->username);
}

static void generate_sessionid(struct ppp_t *ppp)
{
	MD5_CTX ctx;
	uint8_t md5[MD5_DIGEST_LENGTH];
	int i;
		
	MD5_Init(&ctx);
	MD5_Update(&ctx,&ppp->unit_idx, 4);
	MD5_Update(&ctx,&ppp->unit_fd, 4);
	MD5_Update(&ctx,&ppp->chan_fd, 4);
	MD5_Update(&ctx,&ppp->fd, 4);
	MD5_Update(&ctx,&ppp->start_time, sizeof(time_t));
	MD5_Update(&ctx,ppp->ctrl->ctx, sizeof(void *));
	MD5_Final(md5,&ctx);

	for( i = 0; i < 16; i++)
		sprintf(ppp->sessionid + i*2, "%02X", md5[i]);
}

int __export establish_ppp(struct ppp_t *ppp)
{
	/* Open an instance of /dev/ppp and connect the channel to it */
	if (ioctl(ppp->fd, PPPIOCGCHAN, &ppp->chan_idx) == -1) {
		log_ppp_error("ioctl(PPPIOCGCHAN): %s\n", strerror(errno));
		return -1;
	}

	ppp->chan_fd = open("/dev/ppp", O_RDWR);
	if (ppp->chan_fd < 0) {
		log_ppp_error("Couldn't reopen /dev/ppp\n");
		return -1;
	}

	if (ioctl(ppp->chan_fd, PPPIOCATTCHAN, &ppp->chan_idx) < 0) {
		log_ppp_error("Couldn't attach to channel %d\n", ppp->chan_idx);
		goto exit_close_chan;
	}

	ppp->unit_fd = open("/dev/ppp", O_RDWR);
	if (ppp->unit_fd < 0) {
		log_ppp_error("Couldn't reopen /dev/ppp\n");
		goto exit_close_chan;
	}

	ppp->unit_idx = -1;
	if (ioctl(ppp->unit_fd, PPPIOCNEWUNIT, &ppp->unit_idx) < 0) {
		log_ppp_error("Couldn't create new ppp unit\n");
		goto exit_close_unit;
	}

  if (ioctl(ppp->chan_fd, PPPIOCCONNECT, &ppp->unit_idx) < 0) {
		log_ppp_error("Couldn't attach to PPP unit %d\n", ppp->unit_idx);
		goto exit_close_unit;
	}

	if (fcntl(ppp->chan_fd, F_SETFL, O_NONBLOCK)) {
		log_ppp_error("ppp: cann't to set nonblocking mode: %s\n", strerror(errno));
		goto exit_close_unit;
	}
	
	if (fcntl(ppp->unit_fd, F_SETFL, O_NONBLOCK)) {
		log_ppp_error("ppp: cann't to set nonblocking mode: %s\n", strerror(errno));
		goto exit_close_unit;
	}

	ppp->start_time = time(NULL);
	generate_sessionid(ppp);
	sprintf(ppp->ifname, "ppp%i", ppp->unit_idx);

	if (conf_ppp_verbose)
		log_ppp_info("connect: %s <--> %s(%s)\n", ppp->ifname, ppp->ctrl->name, ppp->chan_name);
	
	init_layers(ppp);

	if (list_empty(&ppp->layers)) {
		log_ppp_error("no layers to start\n");
		goto exit_close_unit;
	}

	ppp->chan_buf = _malloc(PPP_MRU);
	ppp->unit_buf = _malloc(PPP_MRU);

	ppp->chan_hnd.fd = ppp->chan_fd;
	ppp->chan_hnd.read = ppp_chan_read;
	ppp->unit_hnd.fd = ppp->unit_fd;
	ppp->unit_hnd.read = ppp_unit_read;
	triton_md_register_handler(ppp->ctrl->ctx, &ppp->chan_hnd);
	triton_md_register_handler(ppp->ctrl->ctx, &ppp->unit_hnd);
	
	triton_md_enable_handler(&ppp->chan_hnd, MD_MODE_READ);
	triton_md_enable_handler(&ppp->unit_hnd, MD_MODE_READ);

	log_ppp_debug("ppp established\n");

	triton_event_fire(EV_PPP_STARTING, ppp);
	
	start_first_layer(ppp);

	return 0;

exit_close_unit:
	close(ppp->unit_fd);
exit_close_chan:
	close(ppp->chan_fd);

	_free_ppp(ppp);

	return -1;
}

static void destablish_ppp(struct ppp_t *ppp)
{
	triton_md_unregister_handler(&ppp->chan_hnd);
	triton_md_unregister_handler(&ppp->unit_hnd);
	
	close(ppp->unit_fd);
	close(ppp->chan_fd);
	close(ppp->fd);

	ppp->unit_fd = -1;
	ppp->chan_fd = -1;
	ppp->fd = -1;

	_free(ppp->unit_buf);
	_free(ppp->chan_buf);

	_free_layers(ppp);
	
	log_ppp_debug("ppp destablished\n");

	triton_event_fire(EV_PPP_FINISHED, ppp);
	ppp->ctrl->finished(ppp);

	if (ppp->username) {
		_free(ppp->username);
		ppp->username = NULL;
	}
}

/*void print_buf(uint8_t *buf, int size)
{
	int i;
	for(i=0;i<size;i++)
		printf("%x ",buf[i]);
	printf("\n");
}*/

int __export ppp_chan_send(struct ppp_t *ppp, void *data, int size)
{
	int n;

	//printf("ppp_chan_send: ");
	//print_buf((uint8_t*)data,size);
	
	n = write(ppp->chan_fd,data,size);
	if (n < size)
		log_ppp_error("ppp_chan_send: short write %i, excpected %i\n", n, size);
	return n;
}

int __export ppp_unit_send(struct ppp_t *ppp, void *data, int size)
{
	int n;

	//printf("ppp_unit_send: ");
	//print_buf((uint8_t*)data,size);
	
	n=write(ppp->unit_fd, data, size);
	if (n < size)
		log_ppp_error("ppp_unit_send: short write %i, excpected %i\n",n,size);
	return n;
}

static int ppp_chan_read(struct triton_md_handler_t *h)
{
	struct ppp_t *ppp = container_of(h, typeof(*ppp), chan_hnd);
	struct ppp_handler_t *ppp_h;
	uint16_t proto;

	while(1) {
cont:
		ppp->chan_buf_size = read(h->fd, ppp->chan_buf, PPP_MRU);
		if (ppp->chan_buf_size < 0) {
			if (errno == EAGAIN)
				return 0;
			log_ppp_error("ppp_chan_read: %s\n", strerror(errno));
			return 0;
		}

		//printf("ppp_chan_read: ");
		//print_buf(ppp->chan_buf,ppp->chan_buf_size);

		if (ppp->chan_buf_size < 2) {
			log_ppp_error("ppp_chan_read: short read %i\n", ppp->chan_buf_size);
			continue;
		}

		proto = ntohs(*(uint16_t*)ppp->chan_buf);
		list_for_each_entry(ppp_h, &ppp->chan_handlers, entry) {
			if (ppp_h->proto == proto) {
				ppp_h->recv(ppp_h);
				if (ppp->chan_fd == -1) {
					ppp->ctrl->finished(ppp);
					return 1;
				}
				goto cont;
			}
		}

		lcp_send_proto_rej(ppp, proto);
		//log_ppp_warn("ppp_chan_read: discarding unknown packet %x\n", proto);
	}
}

static int ppp_unit_read(struct triton_md_handler_t *h)
{
	struct ppp_t *ppp = container_of(h, typeof(*ppp), unit_hnd);
	struct ppp_handler_t *ppp_h;
	uint16_t proto;

	while (1) {
cont:
		ppp->unit_buf_size = read(h->fd, ppp->unit_buf, PPP_MRU);
		if (ppp->unit_buf_size < 0) {
			if (errno == EAGAIN)
				return 0;
			log_ppp_error("ppp_chan_read: %s\n",strerror(errno));
			return 0;
		}

		md_check(ppp->unit_buf);
		//printf("ppp_unit_read: ");
		//print_buf(ppp->unit_buf,ppp->unit_buf_size);

		if (ppp->unit_buf_size < 2) {
			log_ppp_error("ppp_chan_read: short read %i\n", ppp->unit_buf_size);
			continue;
		}

		proto=ntohs(*(uint16_t*)ppp->unit_buf);
		list_for_each_entry(ppp_h, &ppp->unit_handlers, entry) {
			if (ppp_h->proto == proto) {
				ppp_h->recv(ppp_h);
				if (ppp->unit_fd == -1) {
					ppp->ctrl->finished(ppp);
					return 1;
				}
				goto cont;
			}
		}
		lcp_send_proto_rej(ppp, proto);
		//log_ppp_warn("ppp_unit_read: discarding unknown packet %x\n", proto);
	}
}

void ppp_recv_proto_rej(struct ppp_t *ppp, uint16_t proto)
{
	struct ppp_handler_t *ppp_h;

	list_for_each_entry(ppp_h, &ppp->chan_handlers, entry) {
		if (ppp_h->proto == proto) {
			if (ppp_h->recv_proto_rej)
				ppp_h->recv_proto_rej(ppp_h);
			return;
		}
	}
	
	list_for_each_entry(ppp_h, &ppp->unit_handlers, entry) {
		if (ppp_h->proto == proto) {
			if (ppp_h->recv_proto_rej)
				ppp_h->recv_proto_rej(ppp_h);
			return;
		}
	}
}

void __export ppp_layer_started(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	struct layer_node_t *n = d->node;

	if (d->started)
		return;

	d->started = 1;

	list_for_each_entry(d, &n->items, entry)
		if (!d->started) return;

	if (n->entry.next == &ppp->layers) {
		ppp->ctrl->started(ppp);
		triton_event_fire(EV_PPP_STARTED, ppp);
	} else {
		n = list_entry(n->entry.next, typeof(*n), entry);
		list_for_each_entry(d, &n->items, entry) {
			d->starting = 1;
			if (d->layer->start(d)) {
				ppp_terminate(ppp, TERM_NAS_ERROR, 0);
				return;
			}
		}
	}
}

void __export ppp_layer_finished(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	struct layer_node_t *n = d->node;

	d->finished = 1;
	d->starting = 0;

	list_for_each_entry(n, &ppp->layers, entry) {
		list_for_each_entry(d, &n->items, entry) {
			if (!d->finished)
				return;
		}
	}

	destablish_ppp(ppp);
}

void __export ppp_terminate(struct ppp_t *ppp, int cause, int hard)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;
	int s = 0;

	if (!ppp->terminate_cause)
		ppp->terminate_cause = cause;

	if (ppp->terminating) {
		if (hard)
			destablish_ppp(ppp);
		return;
	}
	
	ppp->terminating = 1;

	log_ppp_debug("ppp_terminate\n");

	triton_event_fire(EV_PPP_FINISHING, ppp);

	if (hard) {
		destablish_ppp(ppp);
		return;
	}
	
	list_for_each_entry(n,&ppp->layers,entry) {
		list_for_each_entry(d,&n->items,entry) {
			if (d->starting) {
				s = 1;
				d->layer->finish(d);
			}
		}
	}
	if (s)
		return;
	destablish_ppp(ppp);
}

void __export ppp_register_chan_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_add_tail(&h->entry,&ppp->chan_handlers);
}
void __export ppp_register_unit_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_add_tail(&h->entry,&ppp->unit_handlers);
}
void __export ppp_unregister_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_del(&h->entry);
}

static int get_layer_order(const char *name)
{
	if (!strcmp(name,"lcp")) return 0;
	if (!strcmp(name,"auth")) return 1;
	if (!strcmp(name,"ccp")) return 2;
	if (!strcmp(name,"ipcp")) return 2;
	return -1;
}

int __export ppp_register_layer(const char *name, struct ppp_layer_t *layer)
{
	int order;
	struct layer_node_t *n,*n1;

	order = get_layer_order(name);

	if (order < 0)
		return order;

	list_for_each_entry(n, &layers, entry) {
		if (order > n->order)
			continue;
		if (order < n->order) {
			n1 = _malloc(sizeof(*n1));
			memset(n1, 0, sizeof(*n1));
			n1->order = order;
			INIT_LIST_HEAD(&n1->items);
			list_add_tail(&n1->entry, &n->entry);
			n = n1;
		}
		goto insert;
	}
	n1 = _malloc(sizeof(*n1));
	memset(n1, 0, sizeof(*n1));
	n1->order = order;
	INIT_LIST_HEAD(&n1->items);
	list_add_tail(&n1->entry, &layers);
	n = n1;
insert:
	list_add_tail(&layer->entry, &n->items);

	return 0;
}
void __export ppp_unregister_layer(struct ppp_layer_t *layer)
{
	list_del(&layer->entry);
}

static void init_layers(struct ppp_t *ppp)
{
	struct layer_node_t *n, *n1;
	struct ppp_layer_t *l;
	struct ppp_layer_data_t *d;

	list_for_each_entry(n,&layers,entry) {
		n1 = _malloc(sizeof(*n1));
		memset(n1, 0, sizeof(*n1));
		INIT_LIST_HEAD(&n1->items);
		list_add_tail(&n1->entry, &ppp->layers);
		list_for_each_entry(l, &n->items, entry) {
			d = l->init(ppp);
			d->layer = l;
			d->started = 0;
			d->node = n1;
			list_add_tail(&d->entry, &n1->items);
		}
	}
}

static void _free_layers(struct ppp_t *ppp)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;
	
	while (!list_empty(&ppp->layers)) {
		n = list_entry(ppp->layers.next, typeof(*n), entry);
		while (!list_empty(&n->items)) {
			d = list_entry(n->items.next, typeof(*d), entry);
			list_del(&d->entry);
			d->layer->free(d);
		}
		list_del(&n->entry);
		_free(n);
	}
}

static void start_first_layer(struct ppp_t *ppp)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;

	n = list_entry(ppp->layers.next, typeof(*n), entry);
	list_for_each_entry(d, &n->items, entry) {
		d->starting = 1;
		if (d->layer->start(d)) {
			ppp_terminate(ppp, TERM_NAS_ERROR, 0);
			return;
		}
	}
}

struct ppp_layer_data_t *ppp_find_layer_data(struct ppp_t *ppp, struct ppp_layer_t *layer)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;

	list_for_each_entry(n,&ppp->layers,entry) {
		list_for_each_entry(d,&n->items,entry) {
			if (d->layer == layer)
				return d;
		}
	}
	
	return NULL;
}

static void __init init(void)
{
	char *opt;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		perror("socket");
		_exit(EXIT_FAILURE);
	}

	opt = conf_get_opt("ppp", "verbose");
	if (opt && atoi(opt) > 0)
		conf_ppp_verbose = 1;
}

