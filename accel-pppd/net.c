#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "triton.h"

#include "ap_session.h"

__export __thread const struct ap_net *net;

static int def_pppox_socket(int proto)
{
	return socket(AF_PPPOX, SOCK_STREAM, proto);
}

static int def_pppox_connect(int sock, const struct sockaddr *addr, socklen_t len)
{
	return connect(sock, addr, len);
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
	.pppox_socket = def_pppox_socket,
	.pppox_connect = def_pppox_connect,
	.ppp_open = def_ppp_open,
	.ppp_ioctl = def_ppp_ioctl,
	.sock_ioctl = def_sock_ioctl,
};
