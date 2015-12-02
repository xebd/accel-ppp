#ifndef __SOCK_H
#define __SOCK_H

#include "event.h"

#define SOCK_BUF_SIZE 1024

#define PF_PPP 255

struct sock;

struct proto_ops {
	int (*socket)(struct sock *sk, int type, int proto);
	int (*bind)(struct sock *sk, const struct sockaddr *addr, socklen_t addrlen);
	int (*listen)(struct sock *sk, int backlog);
	int (*connect)(struct sock *sk, const struct sockaddr *addr, socklen_t addrlen);
	int (*recv)(struct sock *sk, size_t len, int flags, socklen_t addrlen);
	int (*send)(struct sock *sk, void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen);
	int (*ioctl)(struct sock *sk, unsigned long request, void *arg);
	void (*close)(struct sock *sk);
};

struct msg_result;

struct sock {
	struct event_handler hnd;
	void *priv;
	struct msg_result *res;
	const struct proto_ops *ops;
};

int sock_errno(struct sock *sk, int err);

int sock_no_listen(struct sock *sk, int backlog);
int sock_no_connect(struct sock *sk, const struct sockaddr *addr, socklen_t addrlen);
int sock_no_ioctl(struct sock *sk, unsigned long request, void *arg);

void sock_register_proto(int domain, int type, int proto, const struct proto_ops *ops);

#endif
