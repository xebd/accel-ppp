#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>

#include <rte_malloc.h>

#include "sock.h"
#include "common.h"
#include "dev.h"

struct packet_priv {
	int type;
};

static int packet_socket(struct sock *sk, int type, int proto)
{
	struct packet_priv *priv = rte_malloc(NULL, sizeof(*sk->priv), 0);

	if (!priv)
		return sock_errno(sk, ENOMEM);

	priv->type = type;

	sk->priv = priv;

	return sock_errno(sk, 0);
}

static int packet_bind(struct sock *sk, const struct sockaddr *a, socklen_t addrlen)
{
	struct sockaddr_ll *addr = (struct sockaddr_ll *)a;
	struct net_device *dev = NULL;

	if (addrlen != sizeof(*addr))
		return sock_errno(sk, EINVAL);

	if (addr->sll_ifindex) {
		dev = netdev_get_by_index(addr->sll_ifindex);
		if (!dev)
			return sock_errno(sk, ENODEV);
	}

	return sock_errno(sk, 0);
}

static int packet_recv(struct sock *sk, size_t len, int flags, socklen_t addrlen)
{

	return sock_errno(sk, EAGAIN);
}

static int packet_send(struct sock *sk, void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen)
{

	return sock_errno(sk, 0);
}

static void packet_close(struct sock *sk)
{
	rte_free(sk->priv);
}

static const struct proto_ops proto = {
	.socket = packet_socket,
	.bind = packet_bind,
	.listen = sock_no_listen,
	.connect = sock_no_connect,
	.recv = packet_recv,
	.send = packet_send,
	.ioctl = sock_no_ioctl,
	.close = packet_close,
};

static void __init init()
{
	sock_register_proto(PF_PACKET, SOCK_RAW, 0, &proto);
}

