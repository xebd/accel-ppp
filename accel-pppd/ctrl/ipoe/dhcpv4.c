#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <linux/if.h>

#include "events.h"
#include "list.h"
#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "memdebug.h"
#include "ap_session.h"
#include "ipdb.h"

#include "dhcpv4.h"

#define BUF_SIZE 4096

struct dhcpv4_relay_ctx {
	struct list_head entry;
	struct triton_context_t *ctx;
	triton_event_func recv;
};

static int conf_verbose;
static in_addr_t conf_dns1;
static in_addr_t conf_dns2;

static mempool_t pack_pool;
static mempool_t opt_pool;

static LIST_HEAD(relay_list);
static pthread_mutex_t relay_lock = PTHREAD_MUTEX_INITIALIZER;

static pthread_key_t raw_sock_key;
static __thread int raw_sock = -1;

static int dhcpv4_read(struct triton_md_handler_t *h);
int dhcpv4_packet_add_opt(struct dhcpv4_packet *pack, int type, const void *data, int len);

static int open_raw_sock(void)
{
	if (raw_sock == -1) {
		raw_sock = socket(AF_PACKET, SOCK_RAW, 0);
		if (raw_sock < 0) {
			log_error("dhcpv4: socket(AF_PACKET, SOCK_RAW): %s\n", strerror(errno));
			return -1;
		}

		fcntl(raw_sock, F_SETFL, O_NONBLOCK);
		fcntl(raw_sock, F_SETFD, fcntl(raw_sock, F_GETFD) | FD_CLOEXEC);

		pthread_setspecific(raw_sock_key, (void *)(long)raw_sock);
	}

	return raw_sock;
}

static void close_raw_sock(void *arg)
{
	close((long)arg);
}

static struct dhcpv4_iprange *parse_range(const char *str)
{
	unsigned int f1,f2,f3,f4,m,n, mask, start, end, len;
	struct dhcpv4_iprange *r;

	n = sscanf(str, "%u.%u.%u.%u/%u", &f1, &f2, &f3, &f4, &m);

	if (n != 5)
		goto parse_err;
	if (f1 > 255)
		goto parse_err;
	if (f2 > 255)
		goto parse_err;
	if (f3 > 255)
		goto parse_err;
	if (f4 > 255)
		goto parse_err;
	if (m == 0 || m > 30)
		goto parse_err;

	start = (f1 << 24) | (f2 << 16) | (f3 << 8) | f4;
	mask = ~((1 << (32 - m)) - 1);
	start = start & mask;
	end = start | ~mask;

	len = (end - start - 1) / (8 * sizeof(long)) + 1;

	r = _malloc(sizeof(*r) + len * sizeof(long));
	memset(r, 0, sizeof(*r));
	memset(r->free, 0xff, len * sizeof(long));
	r->routerip = start + 1;
	r->startip = start;
	r->mask = m;
	r->len = len;
	pthread_mutex_init(&r->lock, NULL);

	end -= start;
	r->free[(end - 1) / ( 8 * sizeof(long))] &= (1 << ((end - 1) % (8 * sizeof(long)) + 1)) - 1;
	r->free[0] &= ~3;

	return r;

parse_err:
	log_emerg("dhcpv4: failed to parse range=%s\n", str);
	return NULL;
}

struct dhcpv4_serv *dhcpv4_create(struct triton_context_t *ctx, const char *ifname, const char *opt)
{
	struct dhcpv4_serv *serv;
	int sock;
	struct sockaddr_in addr;
	struct ifreq ifr;
	int f = 1;
	char *str0, *str, *ptr1, *ptr2;
	int end, ifindex;

	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("dhcpv4(%s): ioctl(SIOCGIFINDEX): %s\n", ifname, strerror(errno));
		return NULL;
	}
	ifindex = ifr.ifr_ifindex;

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(DHCP_SERV_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &f, sizeof(f)))
		log_error("setsockopt(SO_REUSEADDR): %s\n", strerror(errno));


	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &f, sizeof(f))) {
		log_error("setsockopt(SO_BROADCAST): %s\n", strerror(errno));
		goto out_err;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &f, sizeof(f))) {
		log_error("setsockopt(SO_NO_CHECK): %s\n", strerror(errno));
		goto out_err;
	}

	if (bind(sock, &addr, sizeof(addr))) {
		log_error("bind: %s\n", strerror(errno));
		goto out_err;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname))) {
		log_error("setsockopt(SO_BINDTODEVICE): %s\n", strerror(errno));
		goto out_err;
	}

	if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		log_error("dhcpv4(%s): ioctl(SIOCGIFHWADDR): %s\n", ifname, strerror(errno));
		goto out_err;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);
	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	serv = _malloc(sizeof(*serv));
	memset(serv, 0, sizeof(*serv));

	memcpy(serv->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	serv->ctx = ctx;
	serv->hnd.fd = sock;
	serv->hnd.read = dhcpv4_read;
	serv->ifindex = ifindex;

	if (opt && *opt) {
		str0 = _strdup(opt);
		str = str0;

		while (1) {
			for (ptr1 = str + 1; *ptr1 && *ptr1 != '='; ptr1++);

			if (!*ptr1)
				break;

			*ptr1 = 0;

			for (ptr2 = ++ptr1; *ptr2 && *ptr2 != ','; ptr2++);

			end = *ptr2 == 0;

			if (!end)
				*ptr2 = 0;

			if (ptr2 == ptr1)
				break;

			if (strcmp(str, "range") == 0)
				serv->range = parse_range(ptr1);

			if (end)
				break;

			str = ptr2 + 1;
		}

		_free(str0);
	}

	triton_md_register_handler(ctx, &serv->hnd);
	triton_md_enable_handler(&serv->hnd, MD_MODE_READ);

	return serv;

out_err:
	close(sock);
	return NULL;
}

void dhcpv4_free(struct dhcpv4_serv *serv)
{
	triton_md_unregister_handler(&serv->hnd, 1);
	if (serv->range)
		_free(serv->range);
	_free(serv);
}

void dhcpv4_print_packet(struct dhcpv4_packet *pack, int relay, void (*print)(const char *fmt, ...))
{
	const char *msg_name[] = {"Discover", "Offer", "Request", "Decline", "Ack", "Nak", "Release", "Inform"};

	print("[DHCPv4 %s%s xid=%x ", relay ? "relay " : "", msg_name[pack->msg_type - 1], pack->hdr->xid);

	if (pack->hdr->ciaddr) {
		in_addr_t addr = ntohl(pack->hdr->ciaddr);
		print("ciaddr=%i.%i.%i.%i ",
			(addr >> 24) & 0xff,
			(addr >> 16) & 0xff,
			(addr >> 8) & 0xff,
			addr & 0xff);
	}

	if (pack->hdr->yiaddr) {
		in_addr_t addr = ntohl(pack->hdr->yiaddr);
		print("yiaddr=%i.%i.%i.%i ",
			(addr >> 24) & 0xff,
			(addr >> 16) & 0xff,
			(addr >> 8) & 0xff,
			addr & 0xff);
	}

	if (pack->hdr->siaddr) {
		in_addr_t addr = ntohl(pack->hdr->siaddr);
		print("siaddr=%i.%i.%i.%i ",
			(addr >> 24) & 0xff,
			(addr >> 16) & 0xff,
			(addr >> 8) & 0xff,
			addr & 0xff);
	}

	if (pack->hdr->giaddr) {
		in_addr_t addr = ntohl(pack->hdr->giaddr);
		print("giaddr=%i.%i.%i.%i ",
			(addr >> 24) & 0xff,
			(addr >> 16) & 0xff,
			(addr >> 8) & 0xff,
			addr & 0xff);
	}

	print("chaddr=%02x:%02x:%02x:%02x:%02x:%02x ",
		pack->hdr->chaddr[0],
		pack->hdr->chaddr[1],
		pack->hdr->chaddr[2],
		pack->hdr->chaddr[3],
		pack->hdr->chaddr[4],
		pack->hdr->chaddr[5],
		pack->hdr->chaddr[6]);

	dhcpv4_print_options(pack, print);

	print("]\n");
}

static int dhcpv4_parse_packet(struct dhcpv4_packet *pack, int len)
{
	struct dhcpv4_option *opt;
	uint8_t *ptr, *endptr = pack->data + len;

	if (len < sizeof(struct dhcpv4_hdr)) {
		if (conf_verbose)
			log_warn("dhcpv4: short packet received\n");
		return -1;
	}

	if (pack->hdr->htype != 1)
		return -1;

	if (pack->hdr->hlen != 6)
		return -1;

	if (memcmp(pack->hdr->magic, DHCP_MAGIC, 4))
		return -1;

	ptr = pack->data + sizeof(struct dhcpv4_hdr);

	while (ptr < endptr) {
		if (*ptr == 0) {
			ptr++;
			continue;
		}

		if (*ptr == 0xff) {
			ptr++;
			break;
		}

		opt = mempool_alloc(opt_pool);
		if (!opt) {
			log_emerg("out of memory\n");
			return -1;
		}
		memset(opt, 0, sizeof(*opt));
		opt->type = *ptr++;
		opt->len = *ptr++;
		opt->data = ptr;
		ptr += opt->len;

		if (ptr > endptr)
			return -1;

		list_add_tail(&opt->entry, &pack->options);

		if (opt->type == 53)
			pack->msg_type = opt->data[0];
		else if (opt->type == 82)
			pack->relay_agent = opt;
		else if (opt->type == 62)
			pack->client_id = opt;
		else if (opt->type == 50)
			pack->request_ip = *(uint32_t *)opt->data;
		else if (opt->type == 54)
			pack->server_id = *(uint32_t *)opt->data;
	}

	if (pack->msg_type == 0 || pack->msg_type > 8)
		return -1;

	if (dhcpv4_check_options(pack))
		return -1;

	pack->ptr = ptr;

	/*if (conf_verbose) {
		log_info2("recv ");
		print_packet(pack, log_info2);
	}*/

	return 0;
}

static struct dhcpv4_packet *dhcpv4_packet_alloc()
{
	struct dhcpv4_packet *pack = mempool_alloc(pack_pool);

	if (!pack)
		return NULL;

	memset(pack, 0, sizeof(*pack));

	INIT_LIST_HEAD(&pack->options);

	pack->hdr = (struct dhcpv4_hdr *)pack->data;
	pack->ptr = (uint8_t *)(pack->hdr + 1);
	pack->refs = 1;

	memcpy(pack->hdr->magic, DHCP_MAGIC, 4);

	return pack;
}

void dhcpv4_packet_ref(struct dhcpv4_packet *pack)
{
	__sync_add_and_fetch(&pack->refs, 1);
}

struct dhcpv4_option *dhcpv4_packet_find_opt(struct dhcpv4_packet *pack, int type)
{
	struct dhcpv4_option *opt;

	list_for_each_entry(opt, &pack->options, entry) {
		if (opt->type == type)
			return opt;
	}

	return NULL;
}

void dhcpv4_packet_free(struct dhcpv4_packet *pack)
{
	struct dhcpv4_option *opt;

	if (__sync_sub_and_fetch(&pack->refs, 1))
		return;

	while (!list_empty(&pack->options)) {
		opt = list_entry(pack->options.next, typeof(*opt), entry);
		list_del(&opt->entry);
		mempool_free(opt);
	}

	mempool_free(pack);
}

int dhcpv4_parse_opt82(struct dhcpv4_option *opt, uint8_t **agent_circuit_id, uint8_t **agent_remote_id)
{
	uint8_t *ptr = opt->data;
	uint8_t *endptr = ptr + opt->len;
	int type, len;

	while (ptr < endptr) {
		type = *ptr++;
		len = *ptr++;

		if (ptr + len > endptr)
			return -1;

		if (type == 1)
			*agent_circuit_id = ptr - 1;
		else if (type == 2)
			*agent_remote_id = ptr - 1;

		ptr += len;
	}

	return 0;
}

int dhcpv4_packet_insert_opt82(struct dhcpv4_packet *pack, const char *agent_circuit_id, const char *agent_remote_id)
{
	int len1 = strlen(agent_circuit_id);
	int len2 = strlen(agent_remote_id);
	uint8_t *data = _malloc(4 + len1 + len2);
	uint8_t *ptr = data;
	int r;

	pack->ptr--;

	*ptr++ = 1;
	*ptr++ = len1;
	memcpy(ptr, agent_circuit_id, len1); ptr += len1;

	*ptr++ = 2;
	*ptr++ = len2;
	memcpy(ptr, agent_remote_id, len2); ptr += len2;

	r = dhcpv4_packet_add_opt(pack, 82, data, 4 + len1 + len2);
	_free(data);

	*pack->ptr++ = 255;

	return r;
}

static int dhcpv4_read(struct triton_md_handler_t *h)
{
	struct dhcpv4_packet *pack;
	struct dhcpv4_serv *serv = container_of(h, typeof(*serv), hnd);
	struct sockaddr_in addr;
	socklen_t len;
	int n;

	while (1) {
		pack = dhcpv4_packet_alloc();
		if (!pack) {
			log_emerg("out of memory\n");
			return 1;
		}

		len = sizeof(addr);
		n = recvfrom(h->fd, pack->data, BUF_SIZE, 0, &addr, &len);
		if (n == -1) {
			mempool_free(pack);
			if (errno == EAGAIN)
				return 0;
			log_error("dhcpv4: recv: %s\n", strerror(errno));
			continue;
		}

		if (dhcpv4_parse_packet(pack, n)) {
			dhcpv4_packet_free(pack);
			continue;
		}

		if (pack->hdr->op != DHCP_OP_REQUEST) {
			dhcpv4_packet_free(pack);
			continue;
		}

		pack->src_addr = addr.sin_addr.s_addr;

		if (serv->recv)
			serv->recv(serv, pack);

		dhcpv4_packet_free(pack);
	}
}

static int dhcpv4_relay_read(struct triton_md_handler_t *h)
{
	struct dhcpv4_packet *pack;
	struct dhcpv4_relay *r = container_of(h, typeof(*r), hnd);
	int n;
	struct dhcpv4_relay_ctx *c;

	while (1) {
		pack = dhcpv4_packet_alloc();
		if (!pack) {
			log_emerg("out of memory\n");
			return 1;
		}

		n = read(h->fd, pack->data, BUF_SIZE);
		if (n == -1) {
			mempool_free(pack);
			if (errno == EAGAIN)
				return 0;
			log_error("dhcpv4: recv: %s\n", strerror(errno));
			continue;
		}

		if (dhcpv4_parse_packet(pack, n)) {
			dhcpv4_packet_free(pack);
			continue;
		}

		if (pack->hdr->op != DHCP_OP_REPLY) {
			dhcpv4_packet_free(pack);
			continue;
		}

		pthread_mutex_lock(&relay_lock);
		list_for_each_entry(c, &r->ctx_list, entry) {
			dhcpv4_packet_ref(pack);
			triton_context_call(c->ctx, c->recv, pack);
		}
		pthread_mutex_unlock(&relay_lock);

		dhcpv4_packet_free(pack);
	}
}


uint16_t ip_csum(uint16_t *buf, int len)
{
	uint32_t sum=0;
	int i;

	for (i=0; i < len; i += 2)
		sum += *buf++;

	// take only 16 bits out of the 32 bit sum and add up the carries
	while (sum >> 16)
	  sum = (sum & 0xffff) + (sum >> 16);

	// one's complement the result
	sum = ~sum;

	return sum & 0xffff;
}


static int dhcpv4_send_raw(struct dhcpv4_serv *serv, struct dhcpv4_packet *pack, in_addr_t saddr, in_addr_t daddr)
{
	uint8_t hdr[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)];
	struct ether_header *eth = (struct ether_header *)hdr;
	struct iphdr *ip = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	int len = pack->ptr - pack->data;
	struct iovec iov[2];
	static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct sockaddr_ll ll_addr;
	struct msghdr msg;
	int sock = open_raw_sock();

	memset(&ll_addr, 0, sizeof(ll_addr));
	ll_addr.sll_family = AF_PACKET;
	ll_addr.sll_ifindex = serv->ifindex;
	ll_addr.sll_protocol = ntohs(ETH_P_IP);

	msg.msg_name = &ll_addr;
	msg.msg_namelen = sizeof(ll_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	memcpy(eth->ether_dhost, (pack->hdr->flags & DHCP_F_BROADCAST) ? bc_addr : pack->hdr->chaddr, ETH_ALEN);
	memcpy(eth->ether_shost, serv->hwaddr, ETH_ALEN);
	eth->ether_type = htons(ETH_P_IP);

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0x10;
	ip->tot_len = ntohs(sizeof(*ip) + sizeof(*udp) + len);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 128;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;
	ip->saddr = saddr;
	ip->daddr = (pack->hdr->flags & DHCP_F_BROADCAST) ? INADDR_BROADCAST : daddr;
	ip->check = ip_csum((uint16_t *)ip, 20);

	udp->source = ntohs(DHCP_SERV_PORT);
	udp->dest = ntohs(DHCP_CLIENT_PORT);
	udp->len = htons(sizeof(*udp) + len);
	udp->check = 0;

	iov[0].iov_base = hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = pack->data;
	iov[1].iov_len = len;

	len = sendmsg(sock, &msg, 0);

	if (len < 0) {
		perror("sendmsg");
		printf("%i %i\n", errno, serv->ifindex);
		return -1;
	}

	return 0;
}

static int dhcpv4_send_udp(struct dhcpv4_serv *serv, struct dhcpv4_packet *pack, in_addr_t ip, int port)
{
	struct sockaddr_in addr;
	int n;
	int len = pack->ptr - pack->data;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ip;

	n = sendto(serv->hnd.fd, pack->data, len, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (n != len)
		return -1;

	return 0;
}

int dhcpv4_packet_add_opt(struct dhcpv4_packet *pack, int type, const void *data, int len)
{
	struct dhcpv4_option *opt = mempool_alloc(opt_pool);

	if (!opt) {
		log_emerg("out of memory\n");
		return -1;
	}

	*pack->ptr++ = type;
	*pack->ptr++ = len;

	opt->type = type;
	opt->len = len;
	opt->data = pack->ptr;
	pack->ptr += len;

	memcpy(opt->data, data, len);

	list_add_tail(&opt->entry, &pack->options);

	if (type == 82)
		pack->relay_agent = opt;

	return 0;
}

static inline int dhcpv4_packet_add_opt_u8(struct dhcpv4_packet *pack, int type, uint8_t val)
{
	return dhcpv4_packet_add_opt(pack, type, &val, 1);
}

static inline int dhcpv4_packet_add_opt_u32(struct dhcpv4_packet *pack, int type, uint32_t val)
{
	val = htonl(val);
	return dhcpv4_packet_add_opt(pack, type, &val, 4);
}

int dhcpv4_send_reply(int msg_type, struct dhcpv4_serv *serv, struct dhcpv4_packet *req, uint32_t yiaddr, uint32_t siaddr, uint32_t router, uint32_t mask, int lease_time, int renew_time, struct dhcpv4_packet *relay)
{
	struct dhcpv4_packet *pack;
	int val, r;
	struct dns {
		in_addr_t dns1;
		in_addr_t dns2;
	} dns;
	int dns_avail = 0;
	struct dhcpv4_option *opt;

	pack = dhcpv4_packet_alloc();
	if (!pack) {
		log_emerg("out of memory\n");
		return -1;
	}

	memcpy(pack->hdr, req->hdr, sizeof(*req->hdr));

	pack->hdr->op = DHCP_OP_REPLY;
	pack->hdr->yiaddr = yiaddr;
	if (msg_type == DHCPACK)
		pack->hdr->ciaddr = req->hdr->ciaddr;
	else
		pack->hdr->ciaddr = 0;
	pack->hdr->siaddr = 0;
	pack->hdr->giaddr = req->hdr->giaddr;

	if (dhcpv4_packet_add_opt_u8(pack, 53, msg_type))
		goto out_err;

	if (dhcpv4_packet_add_opt(pack, 54, &siaddr, 4))
		goto out_err;

	if (dhcpv4_packet_add_opt_u32(pack, 51, lease_time))
		goto out_err;

	if (renew_time) {
		if (dhcpv4_packet_add_opt_u32(pack, 58, renew_time))
			goto out_err;
	}

	if (router && dhcpv4_packet_add_opt(pack, 3, &router, 4))
		goto out_err;

	val = htonl(~((1 << (32 - mask)) - 1));
	if (dhcpv4_packet_add_opt(pack, 1, &val, 4))
		goto out_err;

	if (relay) {
		list_for_each_entry(opt, &relay->options, entry) {
			if (opt->type == 53 || opt->type == 54 || opt->type == 51 || opt->type == 58 || opt->type == 1 || (opt->type == 3 && router))
				continue;
			if (opt->type == 6)
				dns_avail = 1;
			if (dhcpv4_packet_add_opt(pack, opt->type, opt->data, opt->len))
				goto out_err;
		}
	}

	if (!dns_avail) {
		if (conf_dns1 && conf_dns2) {
			dns.dns1 = conf_dns1;
			dns.dns2 = conf_dns2;
			if (dhcpv4_packet_add_opt(pack, 6, &dns, 8))
				goto out_err;
		} else if (conf_dns1) {
			if (dhcpv4_packet_add_opt(pack, 6, &conf_dns1, 4))
				goto out_err;
		}
	}

	*pack->ptr++ = 255;

	if (conf_verbose) {
		pack->msg_type = msg_type;
		log_ppp_info2("send ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if (req->hdr->giaddr)
		r = dhcpv4_send_udp(serv, pack, req->hdr->giaddr, DHCP_SERV_PORT);
	else if (req->hdr->ciaddr && !(pack->hdr->flags & DHCP_F_BROADCAST))
		r = dhcpv4_send_udp(serv, pack, req->hdr->ciaddr, DHCP_CLIENT_PORT);
	else
		r = dhcpv4_send_raw(serv, pack, siaddr, yiaddr);

	dhcpv4_packet_free(pack);

	return r;

out_err:
	dhcpv4_packet_free(pack);
	return -1;
}

int dhcpv4_send_nak(struct dhcpv4_serv *serv, struct dhcpv4_packet *req)
{
	struct dhcpv4_packet *pack;
	int val, r;

	pack = dhcpv4_packet_alloc();
	if (!pack) {
		log_emerg("out of memory\n");
		return -1;
	}

	memcpy(pack->hdr, req->hdr, sizeof(*req->hdr));

	pack->hdr->op = DHCP_OP_REPLY;
	pack->hdr->ciaddr = 0;
	pack->hdr->yiaddr = 0;
	pack->hdr->siaddr = 0;
	pack->hdr->giaddr = req->hdr->giaddr;

	val = DHCPNAK;
	if (dhcpv4_packet_add_opt(pack, 53, &val, 1))
		goto out_err;

	*pack->ptr++ = 255;

	if (conf_verbose) {
		pack->msg_type = DHCPNAK;
		log_info2("send ");
		dhcpv4_print_packet(pack, 0, log_info2);
	}

	if (req->hdr->giaddr)
		r = dhcpv4_send_udp(serv, pack, req->hdr->giaddr, DHCP_SERV_PORT);
	else
		r = dhcpv4_send_raw(serv, pack, 0, 0xffffffff);

	dhcpv4_packet_free(pack);

	return r;

out_err:
	dhcpv4_packet_free(pack);
	return -1;

	return 0;
}

struct dhcpv4_relay *dhcpv4_relay_create(const char *_addr, in_addr_t giaddr, struct triton_context_t *ctx, triton_event_func recv)
{
	char str[17], *ptr;
	struct dhcpv4_relay *r;
	in_addr_t addr;// = inet_addr(_addr);
	int port = DHCP_SERV_PORT;
	struct sockaddr_in raddr;
	struct sockaddr_in laddr;
	int sock = -1;
	int f = 1;
	struct dhcpv4_relay_ctx *c;

	ptr = strchr(_addr, ':');
	if (ptr) {
		memcpy(str, _addr, ptr - _addr);
		str[ptr - _addr] = 0;
		addr = inet_addr(str);
		port = atoi(ptr + 1);
	} else
		addr = inet_addr(_addr);

	memset(&raddr, 0, sizeof(raddr));
	raddr.sin_family = AF_INET;
	raddr.sin_addr.s_addr = addr;
	raddr.sin_port = htons(port);

	memset(&laddr, 0, sizeof(laddr));
	laddr.sin_family = AF_INET;
	laddr.sin_addr.s_addr = giaddr;
	laddr.sin_port = htons(DHCP_SERV_PORT);

	pthread_mutex_lock(&relay_lock);
	list_for_each_entry(r, &relay_list, entry) {
		if (r->addr == addr && r->giaddr == giaddr)
			goto found;
	}

	r = _malloc(sizeof(*r));
	memset(r, 0, sizeof(*r));
	INIT_LIST_HEAD(&r->ctx_list);
	r->addr = addr;
	r->giaddr = giaddr;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (!sock) {
		log_error("socket: %s\n", strerror(errno));
		goto out_err_unlock;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &f, sizeof(f)))
		log_error("dhcpv4: setsockopt(SO_REUSEADDR): %s\n", strerror(errno));

	if (bind(sock, &laddr, sizeof(laddr))) {
		log_error("dhcpv4: relay: %s: bind: %s\n", _addr, strerror(errno));
		goto out_err_unlock;
	}

	if (connect(sock, &raddr, sizeof(raddr))) {
		log_error("dhcpv4: relay: %s: connect: %s\n", _addr, strerror(errno));
		goto out_err_unlock;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);
	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	r->hnd.fd = sock;
	r->hnd.read = dhcpv4_relay_read;

	r->ctx.before_switch = log_switch;

	triton_context_register(&r->ctx, NULL);
	triton_md_register_handler(&r->ctx, &r->hnd);
	triton_md_enable_handler(&r->hnd, MD_MODE_READ);
	triton_context_wakeup(&r->ctx);

	list_add_tail(&r->entry, &relay_list);

found:
	c = _malloc(sizeof(*c));
	c->ctx = ctx;
	c->recv = recv;
	list_add_tail(&c->entry, &r->ctx_list);

	pthread_mutex_unlock(&relay_lock);

	return r;

out_err_unlock:
	pthread_mutex_unlock(&relay_lock);

	if (sock != -1)
		close(sock);
	_free(r);
	return NULL;
}

static void __dhcpv4_relay_free(struct dhcpv4_relay *r)
{
	triton_md_unregister_handler(&r->hnd, 1);
	triton_context_unregister(&r->ctx);
	_free(r);
}

void dhcpv4_relay_free(struct dhcpv4_relay *r, struct triton_context_t *ctx)
{
	struct dhcpv4_relay_ctx *c;

	pthread_mutex_lock(&relay_lock);
	list_for_each_entry(c, &r->ctx_list, entry) {
		if (c->ctx == ctx) {
			list_del(&c->entry);
			_free(c);
			break;
		}
	}

	if (list_empty(&r->ctx_list)) {
		list_del(&r->entry);
		triton_context_call(&r->ctx, (triton_event_func)__dhcpv4_relay_free, r);
	}
	pthread_mutex_unlock(&relay_lock);
}

int dhcpv4_relay_send(struct dhcpv4_relay *relay, struct dhcpv4_packet *request, uint32_t server_id, const char *agent_circuit_id, const char *agent_remote_id)
{
	int n;
	int len = request->ptr - request->data;
	uint32_t giaddr = request->hdr->giaddr;
	struct dhcpv4_option *opt = NULL;
	uint32_t _server_id;

	if (!request->relay_agent && agent_remote_id && dhcpv4_packet_insert_opt82(request, agent_circuit_id, agent_remote_id))
		return -1;

	request->hdr->giaddr = relay->giaddr;

	if (server_id) {
		opt = dhcpv4_packet_find_opt(request, 54);
		if (opt) {
			_server_id = *(uint32_t *)opt->data;
			*(uint32_t *)opt->data = server_id;
		}
	}

	if (conf_verbose) {
		log_ppp_info2("send ");
		dhcpv4_print_packet(request, 1, log_ppp_info2);
	}

	len = request->ptr - request->data;
	n = write(relay->hnd.fd, request->data, len);

	request->hdr->giaddr = giaddr;

	if (opt)
		*(uint32_t *)opt->data = _server_id;

	if (n != len)
		return -1;

	return 0;
}

int dhcpv4_relay_send_release(struct dhcpv4_relay *relay, uint8_t *chaddr, uint32_t xid, uint32_t ciaddr,
	struct dhcpv4_option *client_id, struct dhcpv4_option *relay_agent,
	const char *agent_circuit_id, const char *agent_remote_id)
{
	struct dhcpv4_packet *pack;
	int n, len;

	pack = dhcpv4_packet_alloc();
	if (!pack) {
		log_emerg("out of memory\n");
		return -1;
	}

	memset(pack->hdr, 0, sizeof(*pack->hdr));

	pack->msg_type = DHCPRELEASE;
	pack->hdr->op = DHCP_OP_REQUEST;
	pack->hdr->htype = 1;
	pack->hdr->hlen = 6;
	pack->hdr->ciaddr = ciaddr;
	pack->hdr->giaddr = relay->giaddr;
	pack->hdr->xid = xid;
	memcpy(pack->hdr->magic, DHCP_MAGIC, 4);
	memcpy(pack->hdr->chaddr, chaddr, 6);

	if (dhcpv4_packet_add_opt(pack, 53, &pack->msg_type, 1))
		goto out_err;

	if (client_id && dhcpv4_packet_add_opt(pack, 61, client_id->data, client_id->len))
		goto out_err;

	if (relay_agent && dhcpv4_packet_add_opt(pack, 82, relay_agent->data, relay_agent->len))
		goto out_err;
	else if (!relay_agent && agent_remote_id) {
		pack->ptr++;
		if (dhcpv4_packet_insert_opt82(pack, agent_circuit_id, agent_remote_id))
			goto out_err;
		pack->ptr--;
	}

	*pack->ptr++ = 255;

	len = pack->ptr - pack->data;

	if (conf_verbose) {
		log_ppp_info2("send ");
		dhcpv4_print_packet(pack, 1, log_ppp_info2);
	}

	n = write(relay->hnd.fd, pack->data, len);

	dhcpv4_packet_free(pack);

	return n == len ? 0 : -1;

out_err:
	dhcpv4_packet_free(pack);
	return -1;
}

int dhcpv4_get_ip(struct dhcpv4_serv *serv, uint32_t *yiaddr, uint32_t *siaddr, int *mask)
{
	int i, k;

	if (!serv->range)
		return 0;

	pthread_mutex_lock(&serv->range->lock);

	while (1) {
		for (i = serv->range->pos; i < serv->range->len; i++) {
			k = ffsl(serv->range->free[i]);
			if (k) {
				serv->range->free[i] &= ~(1 << (k - 1));
				serv->range->pos = i;
				pthread_mutex_unlock(&serv->range->lock);
				*yiaddr = htonl(serv->range->startip + i * 8 * sizeof(long) + k - 1);
				*siaddr = htonl(serv->range->routerip);
				*mask = serv->range->mask;
				return 1;
			}
		}

		if (serv->range->pos == 0)
			break;

		serv->range->pos = 0;
	}

	pthread_mutex_unlock(&serv->range->lock);
	return 0;
}

void dhcpv4_put_ip(struct dhcpv4_serv *serv, uint32_t ip)
{
	int n = ntohl(ip) - serv->range->startip;

	if (n <= 0 || n / (8 * sizeof(long)) >= serv->range->len)
		return;

	pthread_mutex_lock(&serv->range->lock);
	serv->range->free[n / (8 * sizeof(long))] |= 1 << (n % (8 * sizeof(long)));
	pthread_mutex_unlock(&serv->range->lock);
}

void dhcpv4_reserve_ip(struct dhcpv4_serv *serv, uint32_t ip)
{
	int n = ntohl(ip) - serv->range->startip;

	if (n <= 0 || n / (8 * sizeof(long)) >= serv->range->len)
		return;

	pthread_mutex_lock(&serv->range->lock);
	serv->range->free[n / (8 * sizeof(long))] |= 1 << (n % (8 * sizeof(long)));
	pthread_mutex_unlock(&serv->range->lock);
}

static void load_config()
{
	const char *opt;

	opt = conf_get_opt("ipoe", "verbose");
	if (opt)
		conf_verbose = atoi(opt);

	opt = conf_get_opt("dns", "dns1");
	if (opt)
		conf_dns1 = inet_addr(opt);

	opt = conf_get_opt("dns", "dns2");
	if (opt)
		conf_dns2 = inet_addr(opt);
}

static void init()
{
	pack_pool = mempool_create(BUF_SIZE + sizeof(struct dhcpv4_packet));
	opt_pool = mempool_create(sizeof(struct dhcpv4_option));

	pthread_key_create(&raw_sock_key, close_raw_sock);

	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(100, init);
