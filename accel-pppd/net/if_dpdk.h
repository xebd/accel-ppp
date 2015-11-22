#ifndef __IF_DPDK_H
#define __IF_DPDK_H

#define MSG_SOCKET      1
#define MSG_CONNECT     2
#define MSG_BIND        3
#define MSG_LISTEN      4
#define MSG_RECV        5
#define MSG_SEND        6
#define MSG_PPP_OPEN    7
#define MSG_PPP_IOCTL   8
#define MSG_SOCK_IOCTL  9
#define MSG_RESULT      10

struct msg_socket {
	int id;
	int domain;
	int type;
	int proto;
};

struct msg_connect {
	int id;
	socklen_t addrlen;
	char addr[0];
};

struct msg_bind {
	int id;
	socklen_t addrlen;
	char addr[0];
};

struct msg_listen {
	int id;
	int backlog;
};

struct msg_recv {
	int id;
	size_t len;
	int flags;
	socklen_t addrlen;
};

struct msg_send {
	int id;
	size_t len;
	int flags;
	socklen_t addrlen;
};

struct msg_ioctl {
	int id;
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

