#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <rte_malloc.h>

#include "init.h"
#include "common.h"
#include "conf_file.h"
#include "event.h"
#include "sock.h"

#include "if_dp.h"

struct protosw {
	struct list_head entry;
	int domain;
	int type;
	int proto;
	const struct proto_ops *ops;
};

static struct event_handler ctrl_hnd;

static LIST_HEAD(proto_list);

void sock_register_proto(int domain, int type, int proto, const struct proto_ops *ops)
{
	struct list_head *pos = proto_list.next;
	struct protosw *p;

	while (pos != &proto_list) {
		p = list_entry(pos, typeof(*p), entry);
		if (p->domain == domain && type && !p->type)
			break;
		pos = pos->next;
	}

	p = malloc(sizeof(*p));
	p->domain = domain;
	p->type = type;
	p->proto = proto;

	list_add_tail(&p->entry, pos);
}

static int sock_send_errno(int fd, int err)
{
	struct msg_result msg = {
		.err = err,
		.len = 0,
		.addrlen = 0,
	};

	return write(fd, &msg, sizeof(msg)) != sizeof(msg);
}

int sock_errno(struct sock *sk, int err)
{
	sk->res->err = 0;
	sk->res->len = 0;
	sk->res->addrlen = 0;
	return sizeof(*sk->res);
}

static int msg_socket(struct sock *sk, void *buf, int size)
{
	struct msg_socket *msg = (struct msg_socket *)buf;
	struct protosw *p;
	int dom = 0;

	list_for_each_entry(p, &proto_list, entry) {
		if (p->domain != msg->domain)
			continue;

		dom = 1;

		if (p->type && p->type != msg->type)
			continue;

		if (p->proto && p->proto != msg->proto)
			continue;

		sk->ops = p->ops;

		break;
	}

	if (!sk->ops) {
		sock_send_errno(sk->hnd.fd, dom ? EPROTONOSUPPORT : EAFNOSUPPORT);
		return -1;
	}

	return sk->ops->socket(sk, msg->type, msg->proto);
}

static int msg_connect(struct sock *sk, void *buf, int size)
{
	struct msg_connect *msg = (struct msg_connect *)buf;

	assert(sk->ops);
	/*if (unlikely(!sk->ops)) {
		sock_send_errno(sk->hnd.fd, ENOTSOCK);
		return -1;
	}*/

	return sk->ops->connect(sk, (struct sockaddr *)msg->addr, msg->addrlen);
}

static int msg_bind(struct sock *sk, void *buf, int size)
{
	struct msg_bind *msg = (struct msg_bind *)buf;

	assert(sk->ops);
	/*if (unlikely(!sk->ops)) {
		sock_send_errno(sk->hnd.fd, ENOTSOCK);
		return -1;
	}*/

	return sk->ops->bind(sk, (struct sockaddr *)msg->addr, msg->addrlen);
}

static int msg_listen(struct sock *sk, void *buf, int size)
{
	struct msg_listen *msg = (struct msg_listen *)buf;

	assert(sk->ops);
	/*if (unlikely(!sk->ops)) {
		sock_send_errno(sk->hnd.fd, ENOTSOCK);
		return -1;
	}*/

	return sk->ops->listen(sk, msg->backlog);
}

static int msg_recv(struct sock *sk, void *buf, int size)
{
	struct msg_recv *msg = (struct msg_recv *)buf;

	assert(sk->ops);
	/*if (unlikely(!sk->ops)) {
		sock_send_errno(sk->hnd.fd, ENOTSOCK);
		return -1;
	}*/

	return sk->ops->recv(sk, msg->len, msg->flags, msg->addrlen);
}

static int msg_send(struct sock *sk, void *buf, int size)
{
	struct msg_send *msg = (struct msg_send *)buf;
	struct sockaddr *addr = (struct sockaddr *)(msg + 1);

	assert(sk->ops);
	/*if (unlikely(!sk->ops)) {
		sock_send_errno(sk->hnd.fd, ENOTSOCK);
		return -1;
	}*/

	return sk->ops->send(sk, (char *)(msg + 1) + msg->addrlen, msg->len, msg->flags, addr, msg->addrlen);
}

static int msg_ioctl(struct sock *sk, void *buf, int size)
{
	struct msg_ioctl *msg = (struct msg_ioctl *)buf;

	assert(sk->ops);

	return sk->ops->ioctl(sk, msg->request, msg->arg);
}

static int msg_ppp_open(struct sock *sk, void *buf, int size)
{
	struct msg_socket *msg = (struct msg_socket *)buf;
	msg->domain = PF_PPP;
	msg->type = SOCK_DGRAM;
	msg->proto = 0;

	return msg_socket(sk, buf, size);
}

static int msg_sock_ioctl(struct sock *sk, void *buf, int size)
{
	//struct msg_ioctl *msg = (struct msg_ioctl *)buf;

	return 0;
}

typedef int (*handler)(struct sock *sk, void *buf, int size);
static handler msg_hnd[__MSG_MAX_ID] = {
	[MSG_SOCKET] = msg_socket,
	[MSG_CONNECT] = msg_connect,
	[MSG_BIND] = msg_bind,
	[MSG_LISTEN] = msg_listen,
	[MSG_RECV] = msg_recv,
	[MSG_SEND] = msg_send,
	[MSG_IOCTL] = msg_ioctl,
	[MSG_PPP_OPEN] = msg_ppp_open,
	[MSG_SOCK_IOCTL] = msg_sock_ioctl,
};

int sock_no_listen(struct sock *sk, int backlog)
{
	return sock_send_errno(sk->hnd.fd, ENOSYS);
}

int sock_no_connect(struct sock *sk, const struct sockaddr *addr, socklen_t addrlen)
{
	return sock_send_errno(sk->hnd.fd, ENOSYS);
}

int sock_no_ioctl(struct sock *sk, unsigned long request, void *arg)
{
	return sock_send_errno(sk->hnd.fd, ENOSYS);
}

static int sock_read(struct event_handler *h)
{
	struct sock *sk = container_of(h, typeof(*sk), hnd);
	char *buf = rte_malloc(NULL, SOCK_BUF_SIZE, 0);
	int r;
	struct msg_hdr *hdr = (struct msg_hdr *)buf;

	if (!buf)
		goto close;

	r = read(h->fd, buf, SOCK_BUF_SIZE);

	if (r < sizeof(*hdr))
		goto close;

	if (hdr->id >= __MSG_MAX_ID) {
		if (sock_send_errno(h->fd, ENOSYS))
			goto close;
	}

	sk->res = (struct msg_result *)buf;
	r = msg_hnd[hdr->id](sk, buf, r);

	if (likely(r > 0)) {
		if (unlikely(write(h->fd, buf, r) != r))
			goto close;
	}

	rte_free(buf);

	if (likely(r == 0))
		return 0;

close:
	if (sk->ops)
		sk->ops->close(sk);

	event_del_handler(h, 1);

	if (buf)
		rte_free(buf);

	return 1;
}

static int ctrl_accept(struct event_handler *h)
{
	int sock;
	struct sockaddr_un addr;
	socklen_t addrlen;
	struct sock *sk;

	while (1) {
		addrlen = sizeof(addr);
		sock = accept(h->fd, (struct sockaddr *)&addr, &addrlen);
		if (sock < 0)
			break;

		sk = rte_malloc(NULL, sizeof(*sk), 0);
		if (sk) {
			sk->hnd.fd = sock;
			sk->hnd.read = sock_read;
			sk->ops = NULL;

			fcntl(sock, F_SETFL, O_NONBLOCK);

			event_add_handler(&sk->hnd, EVENT_READ);
		} else
			close(h->fd);
	}

	return 0;
}

int ctrl_init()
{
	const char *opt = conf_get_opt("core", "ctrl-socket");
	int sock;
	struct sockaddr_un addr;

	if (event_init())
		return -1;

	if (!opt) {
		fprintf(stderr, "ctrl-socket not specified\n");
		return -1;
	}

	if (strlen(opt) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "ctrl-socket path is too large\n");
		return -1;
	}

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, opt);

	unlink(opt);

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return -1;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		fprintf(stderr, "ctrl-socket: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	if (listen(sock, 1024)) {
		perror("listen");
		close(sock);
		return -1;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);

	ctrl_hnd.fd = sock;
	ctrl_hnd.read = ctrl_accept;
	event_add_handler(&ctrl_hnd, EVENT_READ);

	return 0;
}

