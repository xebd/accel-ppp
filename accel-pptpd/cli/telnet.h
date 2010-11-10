#ifndef __TELNET_H
#define __TELNET_H

struct client_t
{
	struct list_head entry;
	struct triton_md_handler_t hnd;
	uint8_t *recv_buf;
	int recv_pos;
	struct list_head xmit_queue;
	struct buffer_t *xmit_buf;
	int xmit_pos;
	int auth:1;
};

int telnet_send(struct client_t *cln, const void *buf, int size);
void telnet_disconnect(struct client_t *cln);
int process_cmd(struct client_t *cln);

#endif

