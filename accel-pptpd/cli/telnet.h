#ifndef __TELNET_H
#define __TELNET_H

struct client_t
{
	struct list_head entry;
	struct triton_md_handler_t hnd;
	struct list_head xmit_queue;
	struct buffer_t *xmit_buf;
	int xmit_pos;
	struct list_head history;
	struct list_head *history_pos;
	uint8_t *cmdline;
	int cmdline_pos;
	int cmdline_pos2;
	int cmdline_len;
	int auth:1;
	int echo:1;
	int telcmd:1;
	int esc:1;
};

int telnet_send(struct client_t *cln, const void *buf, int size);
void telnet_disconnect(struct client_t *cln);
int process_cmd(struct client_t *cln);

#endif

