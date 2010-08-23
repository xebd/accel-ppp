
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/ppp_defs.h>
#include <linux/if_ppp.h>

#include "triton/triton.h"

#include "ppp.h"
#include "ppp_fsm.h"
#include "log.h"

static LIST_HEAD(layers);

struct layer_node_t
{
	struct list_head entry;
	int order;
	struct list_head items;
};

static void ppp_chan_read(struct triton_md_handler_t*);
static void ppp_unit_read(struct triton_md_handler_t*);
static void init_layers(struct ppp_t *);
static void start_first_layer(struct ppp_t *);

struct ppp_t *init_ppp(void)
{
	struct ppp_t *ppp=malloc(sizeof(*ppp));
	memset(ppp,0,sizeof(*ppp));
	return ppp;
}

static void free_ppp(struct ppp_t *ppp)
{
	free(ppp->chan_buf);
	free(ppp->unit_buf);
}

int establish_ppp(struct ppp_t *ppp)
{
	/* Open an instance of /dev/ppp and connect the channel to it */
	if (ioctl(ppp->fd, PPPIOCGCHAN, &ppp->chan_idx)==-1)
	{
	    log_error("Couldn't get channel number\n");
	    return -1;
	}

	ppp->chan_fd=open("/dev/ppp", O_RDWR);
	if (ppp->chan_fd<0)
	{
	    log_error("Couldn't reopen /dev/ppp\n");
	    return -1;
	}

	if (ioctl(ppp->chan_fd, PPPIOCATTCHAN, &ppp->chan_idx)<0)
	{
	    log_error("Couldn't attach to channel %d\n", ppp->chan_idx);
	    goto exit_close_chan;
	}

	ppp->unit_fd=open("/dev/ppp", O_RDWR);
	if (ppp->unit_fd<0)
	{
	    log_error("Couldn't reopen /dev/ppp\n");
	    goto exit_close_chan;
	}

	ppp->unit_idx=-1;
	if (ioctl(ppp->unit_fd, PPPIOCNEWUNIT, &ppp->unit_idx)<0)
	{
		log_error("Couldn't create new ppp unit\n");
		goto exit_close_unit;
	}

  if (ioctl(ppp->chan_fd, PPPIOCCONNECT, &ppp->unit_idx)<0)
  {
		log_error("Couldn't attach to PPP unit %d\n", ppp->unit_idx);
		goto exit_close_unit;
	}

	log_info("connect: ppp%i <--> pptp(%s)\n",ppp->unit_idx,ppp->chan_name);
	
	ppp->chan_buf=malloc(PPP_MRU);
	ppp->unit_buf=malloc(PPP_MRU);

	INIT_LIST_HEAD(&ppp->chan_handlers);
	INIT_LIST_HEAD(&ppp->unit_handlers);
	
	init_layers(ppp);

	if (list_empty(&ppp->layers))
	{
		log_error("no layers to start\n");
		goto exit_close_unit;
	}

	ppp->chan_hnd.fd=ppp->chan_fd;
	ppp->chan_hnd.read=ppp_chan_read;
	ppp->chan_hnd.twait=-1;
	ppp->unit_hnd.fd=ppp->unit_fd;
	ppp->unit_hnd.read=ppp_unit_read;
	ppp->unit_hnd.twait=-1;
	triton_md_register_handler(&ppp->chan_hnd);
	triton_md_register_handler(&ppp->unit_hnd);
	
	triton_md_enable_handler(&ppp->chan_hnd,MD_MODE_READ);
	triton_md_enable_handler(&ppp->unit_hnd,MD_MODE_READ);

	log_debug("ppp established\n");

	start_first_layer(ppp);

	return 0;

exit_close_unit:
	close(ppp->unit_fd);
exit_close_chan:
	close(ppp->chan_fd);

	free_ppp(ppp);

	return -1;
}

void destablish_ppp(struct ppp_t *ppp)
{
	triton_md_unregister_handler(&ppp->chan_hnd);
	triton_md_unregister_handler(&ppp->unit_hnd);
	
	close(ppp->unit_fd);
	close(ppp->chan_fd);

	free(ppp->unit_buf);
	free(ppp->chan_buf);
	
	log_debug("ppp destablished\n");

	if (ppp->events.finished) ppp->events.finished(ppp);
}

void print_buf(uint8_t *buf,int size)
{
	int i;
	for(i=0;i<size;i++)
		printf("%x ",buf[i]);
	printf("\n");
}

int ppp_chan_send(struct ppp_t *ppp, void *data, int size)
{
	int n;

	//printf("ppp_chan_send: ");
	//print_buf((uint8_t*)data,size);
	
	n=write(ppp->chan_fd,data,size);
	if (n<size)
		log_error("ppp_chan_send: short write %i, excpected %i\n",n,size);
	return n;
}

int ppp_unit_send(struct ppp_t *ppp, void *data, int size)
{
	int n;

	//printf("ppp_unit_send: ");
	//print_buf((uint8_t*)data,size);
	
	n=write(ppp->unit_fd,data,size);
	if (n<size)
		log_error("ppp_unit_send: short write %i, excpected %i\n",n,size);
	return n;
}

static void ppp_chan_read(struct triton_md_handler_t*h)
{
	struct ppp_t *ppp=container_of(h,typeof(*ppp),chan_hnd);
	struct ppp_handler_t *ppp_h;
	uint16_t proto;

	ppp->chan_buf_size=read(h->fd,ppp->chan_buf,PPP_MRU);

	//printf("ppp_chan_read: ");
	//print_buf(ppp->chan_buf,ppp->chan_buf_size);

	if (ppp->chan_buf_size<2)
	{
		log_error("ppp_chan_read: short read %i\n",ppp->chan_buf_size);
		return;
	}

	proto=ntohs(*(uint16_t*)ppp->chan_buf);
	list_for_each_entry(ppp_h,&ppp->chan_handlers,entry)
	{
		if (ppp_h->proto==proto)
		{
			ppp_h->recv(ppp_h);
			return;
		}
	}

	log_warn("ppp_chan_read: discarding unknown packet %x\n",proto);
}

static void ppp_unit_read(struct triton_md_handler_t*h)
{
	struct ppp_t *ppp=container_of(h,typeof(*ppp),unit_hnd);
	struct ppp_handler_t *ppp_h;
	uint16_t proto;

	ppp->unit_buf_size=read(h->fd,ppp->unit_buf,PPP_MRU);

	printf("ppp_unit_read: ");
	print_buf(ppp->unit_buf,ppp->unit_buf_size);

	if (ppp->unit_buf_size<2)
	{
		log_error("ppp_chan_read: short read %i\n",ppp->unit_buf_size);
		return;
	}

	proto=ntohs(*(uint16_t*)ppp->unit_buf);
	list_for_each_entry(ppp_h,&ppp->unit_handlers,entry)
	{
		if (ppp_h->proto==proto)
		{
			ppp_h->recv(ppp_h);
			return;
		}
	}

	log_warn("ppp_chan_read: discarding unknown packet %x\n",proto);
}

void ppp_layer_started(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	struct layer_node_t *n=d->node;
	
	d->started=1;

	list_for_each_entry(d,&n->items,entry)
		if (!d->started) return;

	if (n->entry.next==&ppp->layers)
	{
		if (ppp->events.started) ppp->events.started(ppp);
	}else
	{
		n=list_entry(n->entry.next,typeof(*n),entry);
		list_for_each_entry(d,&n->items,entry)
		{
			d->starting=1;
			d->layer->start(d);
		}
	}
}

void ppp_layer_finished(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	struct layer_node_t *n=d->node;
	
	d->starting=0;
	d->started=0;

	list_for_each_entry(n,&ppp->layers,entry)
	{
		list_for_each_entry(d,&n->items,entry)
		{
			if (d->starting)
				return;
		}
	}
	destablish_ppp(ppp);
}

void ppp_terminate(struct ppp_t *ppp)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;
	int s=0;

	log_debug("ppp_terminate\n");

	list_for_each_entry(n,&ppp->layers,entry)
	{
		list_for_each_entry(d,&n->items,entry)
		{
			if (d->starting)
			{
				s=1;
				d->layer->finish(d);
			}
		}
	}
	if (s) return;
	destablish_ppp(ppp);
}

void ppp_register_chan_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_add_tail(&h->entry,&ppp->chan_handlers);
}
void ppp_register_unit_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_add_tail(&h->entry,&ppp->unit_handlers);
}
void ppp_unregister_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_del(&h->entry);
}

static int get_layer_order(const char *name)
{
	if (!strcmp(name,"lcp")) return 0;
	if (!strcmp(name,"auth")) return 1;
	if (!strcmp(name,"ipcp")) return 2;
	if (!strcmp(name,"ccp")) return 2;
	return -1;
}

int ppp_register_layer(const char *name, struct ppp_layer_t *layer)
{
	int order;
	struct layer_node_t *n,*n1;

	order=get_layer_order(name);

	if (order<0)
		return order;

	list_for_each_entry(n,&layers,entry)
	{
		if (order>n->order)
			continue;
		if (order<n->order)
		{
			n1=malloc(sizeof(*n1));
			memset(n1,0,sizeof(*n1));
			n1->order=order;
			INIT_LIST_HEAD(&n1->items);
			list_add_tail(&n1->entry,&n->entry);
			n=n1;
		}
		goto insert;
	}
	n1=malloc(sizeof(*n1));
	memset(n1,0,sizeof(*n1));
	n1->order=order;
	INIT_LIST_HEAD(&n1->items);
	list_add_tail(&n1->entry,&layers);
	n=n1;
insert:
	list_add_tail(&layer->entry,&n->items);

	return 0;
}
void ppp_unregister_layer(struct ppp_layer_t *layer)
{
	list_del(&layer->entry);
}

static void init_layers(struct ppp_t *ppp)
{
	struct layer_node_t *n,*n1;
	struct ppp_layer_t *l;
	struct ppp_layer_data_t *d;

	INIT_LIST_HEAD(&ppp->layers);

	list_for_each_entry(n,&layers,entry)
	{
		n1=(struct layer_node_t*)malloc(sizeof(*n1));
		memset(n1,0,sizeof(*n1));
		INIT_LIST_HEAD(&n1->items);
		list_add_tail(&n1->entry,&ppp->layers);
		list_for_each_entry(l,&n->items,entry)
		{
			d=l->init(ppp);
			d->layer=l;
			d->started=0;
			d->node=n1;
			list_add_tail(&d->entry,&n1->items);
		}
	}
}

static void start_first_layer(struct ppp_t *ppp)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;

	n=list_entry(ppp->layers.next,typeof(*n),entry);
	list_for_each_entry(d,&n->items,entry)
	{
		d->starting=1;
		d->layer->start(d);
	}
}

struct ppp_layer_data_t *ppp_find_layer_data(struct ppp_t *ppp, struct ppp_layer_t *layer)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;

	list_for_each_entry(n,&ppp->layers,entry)
	{
		list_for_each_entry(d,&n->items,entry)
		{
			if (d->layer==layer)
				return d;
		}
	}
	
	return NULL;
}
