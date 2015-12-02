#ifndef __IF_DP_H
#define __IF_DP_H

#include <stdint.h>

enum {
	MSG_SOCKET,
	MSG_CONNECT,
	MSG_BIND,
	MSG_LISTEN,
	MSG_RECV,
	MSG_SEND,
	MSG_IOCTL,
	MSG_PPP_OPEN,
	MSG_SOCK_IOCTL,
	__MSG_MAX_ID
};

#define MSG_MAX_ID (__MSG_MAX_ID - 1)

struct msg_hdr {
	uint8_t id;
};

struct msg_socket {
	uint8_t id;
	int domain;
	int type;
	int proto;
};

struct msg_connect {
	uint8_t id;
	socklen_t addrlen;
	char addr[0];
};

struct msg_bind {
	uint8_t id;
	socklen_t addrlen;
	char addr[0];
};

struct msg_listen {
	uint8_t id;
	int backlog;
};

struct msg_recv {
	uint8_t id;
	size_t len;
	int flags;
	socklen_t addrlen;
};

struct msg_send {
	uint8_t id;
	size_t len;
	int flags;
	socklen_t addrlen;
};

struct msg_ioctl {
	uint8_t id;
	unsigned long request;
	char arg[0];
};

struct msg_result {
	int err;
	ssize_t len;
	socklen_t addrlen;
	struct sockaddr_storage ss;
};

#endif

