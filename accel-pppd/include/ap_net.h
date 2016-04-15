#ifndef __AP_NET_H
#define __AP_NET_H

struct ap_net {
	const char *name;
	int (*socket)(int domain, int type, int proto);
	int (*connect)(int sock, const struct sockaddr *, socklen_t len);
	int (*bind)(int sock, const struct sockaddr *, socklen_t len);
	int (*listen)(int sock, int backlog);
	ssize_t (*read)(int sock, void *buf, size_t len);
	ssize_t (*recvfrom)(int sock, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
	ssize_t (*write)(int sock, const void *buf, size_t len);
	ssize_t (*sendto)(int sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
	int (*set_nonblocking)(int sock, int f);
	int (*setsockopt)(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
	int (*sock_ioctl)(unsigned long request, void *arg);
	int (*ppp_open)();
	int (*ppp_ioctl)(int fd, unsigned long request, void *arg);
};

int ap_net_register(const struct ap_net *net);
const struct ap_net *ap_net_find(const char *name);

#endif
