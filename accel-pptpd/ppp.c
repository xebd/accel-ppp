
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
#include "events.h"

static void ppp_read(struct triton_md_handler_t*);
static void ppp_write(struct triton_md_handler_t*);
static void ppp_timeout(struct triton_md_handler_t*);

struct ppp_t *alloc_ppp(void)
{
	struct ppp_t *ppp=malloc(sizeof(*ppp));
	memset(ppp,0,sizeof(*ppp));
	ppp->out_buf=malloc(PPP_MTU+PPP_HDRLEN);
	ppp->in_buf=malloc(PPP_MRU+PPP_HDRLEN);
	ppp->mtu=PPP_MTU;
	ppp->mru=PPP_MRU;
	return ppp;
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
		goto exit_clodse_unit;
	}

  if (ioctl(ppp->chan_fd, PPPIOCCONNECT, &ppp->unit_idx)<0)
  {
		log_error("Couldn't attach to PPP unit %d\n", ppp->unit_idx);
		goto exit_clodse_unit;
	}

	log_info("connect: ppp%i <--> pptp(%s)\n",ppp->unit_idx,ppp->chan_name);

	ppp->h=malloc(sizeof(*ppp->h));
	memset(ppp->h,0,sizeof(*ppp->h));
	ppp->h->pd=ppp;
	ppp->h->fd=ppp->chan_fd;
	ppp->h->read=ppp_read;
	ppp->h->write=ppp_write;
	ppp->h->timeout=ppp_timeout;
	ppp->h->twait=-1;
	triton_md_register_handler(ppp->h);
	triton_md_enable_handler(ppp->h,MD_MODE_READ);
	INIT_LIST_HEAD(&ppp->layers);

	ppp->lcp_layer=ppp_lcp_init(ppp);
	/*list_add_tail(&ppp->lcp_layer->entry,&ppp->layers);
	ppp_fsm_open(ppp->lcp_layer);
	ppp_fsm_lower_up(ppp->lcp_layer);*/
	ppp->cur_layer=PPP_LAYER_LCP;
	lcp_start(ppp);

	return 0;

exit_clodse_unit:
	close(ppp->unit_fd);
exit_close_chan:
	close(ppp->chan_fd);
	return -1;
}

int ppp_send(struct ppp_t *ppp, void *data, int size)
{
	int n;

	if (ppp->out_buf_size) return -1;
	if (size>PPP_MTU+PPP_HDRLEN) return -1;

	n=write(ppp->unit_fd,data,size);
	if (n>=0)
	{
		if (n!=ppp->out_buf_size-ppp->out_buf_pos)
		{
			ppp->out_buf_pos+=n;
			triton_md_enable_handler(ppp->h,MD_MODE_WRITE);
		}
	}
	return n;
}

static void ppp_read(struct triton_md_handler_t*h)
{
	struct ppp_t *ppp=(struct ppp_t *)h->pd;
	struct ppp_layer_t *l=NULL;
	uint16_t proto;

	ppp->in_buf_size=read(h->fd,ppp->in_buf,PPP_MRU+PPP_HDRLEN);

	proto=ntohs(*(uint16_t*)ppp->in_buf);
	list_for_each_entry(l,&ppp->layers,entry)
	{
		if (l->proto==proto)
		{
			l->recv(l);
			return;
		}
	}

	log_warn("discarding unknown packet %x\n",proto);
}
static void ppp_write(struct triton_md_handler_t*h)
{
	struct ppp_t *ppp=(struct ppp_t *)h->pd;

	int n=write(ppp->unit_fd,ppp->out_buf+ppp->out_buf_pos,ppp->out_buf_size-ppp->out_buf_pos);
	if (n>=0)
	{
		ppp->out_buf_pos+=n;
		if (ppp->out_buf_pos==ppp->out_buf_size)
		{
			triton_md_disable_handler(ppp->h,MD_MODE_WRITE);
			ppp->out_buf_pos=0;
			ppp->out_buf_size=0;
		}
	}
}
static void ppp_timeout(struct triton_md_handler_t*h)
{

}

void ppp_layer_started(struct ppp_t *ppp)
{
	int i;
	switch(ppp->cur_layer)
	{
		case PPP_LAYER_LCP:
			ppp->cur_layer++;
			if (auth_start(ppp))
				break;
		case PPP_LAYER_AUTH:
			ppp->cur_layer++;
			if (ccp_start(ppp))
				break;
		case PPP_LAYER_CCP:
			ppp->cur_layer++;
			if (ipcp_start(ppp))
				break;
		case PPP_LAYER_IPCP:
				break;
	}
}
void ppp_terminate(struct ppp_t *ppp)
{
	switch(ppp->cur_layer)
	{
		case PPP_LAYER_IPCP:
			ppp->cur_layer--;
			ipcp_finish(ppp);
		case PPP_LAYER_CCP:
			ppp->cur_layer--;
			ccp_finish(ppp);
		case PPP_LAYER_AUTH:
			ppp->cur_layer--;
			auth_finish(ppp);
		case PPP_LAYER_LCP:
			ppp->cur_layer--;
			lcp_finish(ppp);
	}
}

