#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "triton.h"

#include "ap_net.h"

#define MAX_NET 2

static const struct ap_net *nets[MAX_NET];
static int net_cnt;

extern int sock_fd;

__export __thread const struct ap_net *net;

static int def_socket(int domain, int type, int proto)
{
	return socket(domain, type, proto);
}

static int def_connect(int sock, const struct sockaddr *addr, socklen_t len)
{
	return connect(sock, addr, len);
}

static int def_bind(int sock, const struct sockaddr *addr, socklen_t len)
{
	return bind(sock, addr, len);
}

static int def_listen(int sock, int backlog)
{
	return listen(sock, backlog);
}

static ssize_t def_read(int sock, void *buf, size_t len)
{
	return read(sock, buf, len);
}

static ssize_t def_recvfrom(int sock, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	return recvfrom(sock, buf, len, flags, src_addr, addrlen);
}

static ssize_t def_write(int sock, const void *buf, size_t len)
{
	return write(sock, buf, len);
}

static ssize_t def_sendto(int sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return sendto(sock, buf, len, flags, dest_addr, addrlen);
}

static int def_set_nonblocking(int sock, int f)
{
	return fcntl(sock, F_SETFL, O_NONBLOCK);
}

static int def_setsockopt(int sock, int level, int optname, const void *optval, socklen_t optlen)
{
	return setsockopt(sock, level, optname, optval, optlen);
}

static int def_ppp_open()
{
	return open("/dev/ppp", O_RDWR);
}

static int def_ppp_ioctl(int fd, unsigned long request, void *arg)
{
	return ioctl(fd, request, arg);
}

static int def_sock_ioctl(unsigned long request, void *arg)
{
	return ioctl(sock_fd, request, arg);
}

__export const struct ap_net def_net = {
	.name = "kernel",
	.socket = def_socket,
	.connect = def_connect,
	.bind = def_bind,
	.listen = def_listen,
	.read = def_read,
	.recvfrom = def_recvfrom,
	.write = def_write,
	.sendto = def_sendto,
	.set_nonblocking = def_set_nonblocking,
	.setsockopt = def_setsockopt,
	.ppp_open = def_ppp_open,
	.ppp_ioctl = def_ppp_ioctl,
	.sock_ioctl = def_sock_ioctl,
};

static void __init init()
{
	nets[0] = &def_net;
	net_cnt = 1;
}

int __export ap_net_register(const struct ap_net *net)
{
	int i;

	if (net_cnt == MAX_NET)
		return -1;

	for (i = 0; i < net_cnt; i++) {
		if (!strcmp(net->name, nets[i]->name))
			return -1;
	}

	nets[net_cnt++] = net;

	return 0;
}

__export const struct ap_net *ap_net_find(const char *name)
{
	int i;

	for (i = 0; i < net_cnt; i++) {
		if (!strcmp(name, nets[i]->name))
			return nets[i];
	}

	return NULL;
}
