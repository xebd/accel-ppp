#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/ppp-ioctl.h>
#include <linux/if.h>

#include "triton.h"
#include "ap_net.h"
#include "log.h"

#include "if_dpdk.h"

static struct sockaddr_un dpdk_addr;
static int dpdk_sock;

static int dpdk_socket(int domain, int type, int proto)
{
	struct msg_socket msg = {
		.id = MSG_SOCKET,
		.domain = domain,
		.type = type,
		.proto = proto,
	};
	struct msg_result res;

	int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&dpdk_addr, sizeof(dpdk_addr))) {
		close(sock);
		return -1;
	}

	if (write(sock, &msg, sizeof(msg)) < 0) {
		close(sock);
		return -1;
	}

	if (read(sock, &res, sizeof(res)) != sizeof(res)) {
		close(sock);
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		close(sock);
		errno = res.err;
		return -1;
	}

	return sock;
}

static int dpdk_connect(int sock, const struct sockaddr *addr, socklen_t len)
{
	struct msg_connect msg = {
		.id = MSG_CONNECT,
		.addrlen = len,
	};
	struct msg_result res;
	struct iovec iov[2] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = (void *)addr,
			.iov_len = len,
		}
	};

	if (writev(sock, iov, 2) < 0)
		return -1;

	if (read(sock, &res, sizeof(res)) != sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	return 0;
}

static int dpdk_bind(int sock, const struct sockaddr *addr, socklen_t len)
{
	struct msg_bind msg = {
		.id = MSG_BIND,
		.addrlen = len,
	};
	struct msg_result res;
	struct iovec iov[2] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = (void *)addr,
			.iov_len = len,
		}
	};

	if (writev(sock, iov, 2) < 0)
		return -1;

	if (read(sock, &res, sizeof(res)) != sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	return 0;
}

static int dpdk_listen(int sock, int backlog)
{
	struct msg_listen msg = {
		.id = MSG_LISTEN,
		.backlog = backlog,
	};
	struct msg_result res;

	if (write(sock, &msg, sizeof(msg)) < 0)
		return -1;

	if (read(sock, &res, sizeof(res)) != sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	return 0;
}

static ssize_t dpdk_recv(int sock, void *buf, size_t len, int flags)
{
	struct msg_recv msg = {
		.id = MSG_RECV,
		.len = len,
		.flags = flags,
		.addrlen = 0,
	};
	struct msg_result res;
	struct iovec iov[2] = {
		{
			.iov_base = &res,
			.iov_len = sizeof(res),
		},
		{
			.iov_base = buf,
			.iov_len = len,
		}
	};

	if (write(sock, &msg, sizeof(msg)))
		return -1;

again:
	if (readv(sock, iov, 2) < sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	if (!res.len)
		goto again;

	return res.len;
}

static ssize_t dpdk_recvfrom(int sock, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{
	struct msg_recv msg = {
		.id = MSG_RECV,
		.len = len,
		.flags = flags,
		.addrlen = 0,
	};
	struct msg_result res;
	struct iovec iov[2] = {
		{
			.iov_base = &res,
			.iov_len = sizeof(res),
		},
		{
			.iov_base = buf,
			.iov_len = len,
		}
	};

	if (write(sock, &msg, sizeof(msg)))
		return -1;

again:
	if (readv(sock, iov, 2) < sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	if (!res.len)
		goto again;

	memcpy(src_addr, &res.ss, res.addrlen);
	*addrlen = res.addrlen;

	return res.len;
}

static ssize_t dpdk_send(int sock, const void *buf, size_t len, int flags)
{
	struct msg_send msg = {
		.id = MSG_SEND,
		.len = len,
		.flags = flags,
		.addrlen = 0,
	};
	struct msg_result res;
	struct iovec iov[2] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = (void *)buf,
			.iov_len = len,
		}
	};

	if (writev(sock, iov, 2) < 0)
		return -1;

	if (read(sock, &res, sizeof(res)) != sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	return res.len;
}

static ssize_t dpdk_sendto(int sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
	struct msg_send msg = {
		.id = MSG_SEND,
		.len = len,
		.flags = flags,
		.addrlen = addrlen,
	};
	struct msg_result res;
	struct iovec iov[3] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = (void *)dest_addr,
			.iov_len = addrlen,
		},
		{
			.iov_base = (void *)buf,
			.iov_len = len,
		}
	};

	if (writev(sock, iov, 3) < 0)
		return -1;

	if (read(sock, &res, sizeof(res)) != sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	return res.len;
}

static int dpdk_set_nonblocking(int sock, int f)
{
	return 0;
}

static int dpdk_setsockopt(int sock, int level, int optname, const void *optval, socklen_t optlen)
{
	return 0;
}


static int dpdk_ppp_open()
{
	int id = MSG_PPP_OPEN;
	struct msg_result res;
	int sock = socket(AF_UNIX, SOCK_DGRAM, 0);

	if (sock < 0)
		return -1;

	if (connect(sock, (struct sockaddr *)&dpdk_addr, sizeof(dpdk_addr))) {
		close(sock);
		return -1;
	}

	if (write(sock, &id, sizeof(id)) < 0) {
		close(sock);
		return -1;
	}

	if (read(sock, &res, sizeof(res)) != sizeof(res)) {
		close(sock);
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		close(sock);
		errno = res.err;
		return -1;
	}

	return sock;
}

static int dpdk_ppp_ioctl(int fd, unsigned long request, void *arg)
{
	struct msg_ioctl msg = {
		.id = MSG_PPP_IOCTL,
		.request = request,
	};
	struct msg_result res;
	struct iovec iov[2] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = arg,
		}
	};

	switch (request) {
		case PPPIOCSNPMODE:
			iov[1].iov_len = sizeof(struct npioctl);
			break;
		case PPPIOCSCOMPRESS:
			iov[1].iov_len = sizeof(struct ppp_option_data);
			break;
		case PPPIOCGFLAGS:
		case PPPIOCGCHAN:
		case PPPIOCNEWUNIT:
			iov[1].iov_len = 0;
			break;
		case PPPIOCSFLAGS:
		case PPPIOCSMRU:
		case PPPIOCATTCHAN:
		case PPPIOCCONNECT:
			iov[1].iov_len = sizeof(int);
			break;

	}

	if (writev(fd, iov, iov[1].iov_len ? 2 : 1) < 0)
		return -1;

	iov[0].iov_base = &res;
	iov[0].iov_len = sizeof(res);
	iov[1].iov_base = arg;
	iov[1].iov_len = 1024;

	if (readv(fd, iov, 2) < sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	return res.len;
}

static int dpdk_sock_ioctl(unsigned long request, void *arg)
{
	struct msg_ioctl msg = {
		.id = MSG_SOCK_IOCTL,
		.request = request,
	};
	struct msg_result res;
	struct iovec iov[2] = {
		{
			.iov_base = &msg,
			.iov_len = sizeof(msg),
		},
		{
			.iov_base = arg,
			.iov_len = sizeof(struct ifreq),
		}
	};

	if (writev(dpdk_sock, iov, 2) < 0)
		return -1;

	iov[0].iov_base = &res;
	iov[0].iov_len = sizeof(res);

	if (readv(dpdk_sock, iov, 2) < sizeof(res)) {
		errno = EBADE;
		return -1;
	}

	if (res.err) {
		errno = res.err;
		return -1;
	}

	return res.len;
}

static const struct ap_net dpdk_net = {
	.socket = dpdk_socket,
	.connect = dpdk_connect,
	.bind = dpdk_bind,
	.listen = dpdk_listen,
	.recv = dpdk_recv,
	.recvfrom = dpdk_recvfrom,
	.send = dpdk_send,
	.sendto = dpdk_sendto,
	.set_nonblocking = dpdk_set_nonblocking,
	.setsockopt = dpdk_setsockopt,
	.ppp_open = dpdk_ppp_open,
	.ppp_ioctl = dpdk_ppp_ioctl,
	.sock_ioctl = dpdk_sock_ioctl,
};

static void init()
{
	const char *opt = conf_get_opt("net-dpdk", "socket");

	if (!opt)
		return;

	if (strlen(opt) >= sizeof(dpdk_addr.sun_path)) {
		log_error("net-dpdk: socket path is too long\n");
		return;
	}

	strcpy(dpdk_addr.sun_path, opt);

	dpdk_addr.sun_family = AF_UNIX;

	dpdk_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (dpdk_sock < 0)
		return;

	if (connect(dpdk_sock, (struct sockaddr *)&dpdk_addr, sizeof(dpdk_addr))) {
		log_error("dpdk: connect: %s\n", strerror(errno));
		close(dpdk_sock);
		return;
	}
}

DEFINE_INIT(1, init)
