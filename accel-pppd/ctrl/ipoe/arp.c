#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>

#include "list.h"
#include "triton.h"
#include "log.h"

#include "ipoe.h"

#include "memdebug.h"

struct _arphdr {
	__be16 ar_hrd;
	__be16 ar_pro;
	__u8   ar_hln;
	__u8   ar_pln;
	__be16 ar_op;
	__u8   ar_sha[ETH_ALEN];
	__be32 ar_spa;
	__u8   ar_tha[ETH_ALEN];
	__be32 ar_tpa;
} __packed;

static int arp_read(struct triton_md_handler_t *h)
{
	struct arp_serv *s = container_of(h, typeof(*s), h);
	char buf[128];
	int n;
	struct _arphdr *ah = (struct _arphdr *)buf;
	struct _arphdr ah2;
	struct sockaddr_ll src, dst;
	socklen_t slen = sizeof(src);
	struct ipoe_session *ses, *ses1, *ses2;

	memset(&dst, 0, sizeof(dst));
	dst.sll_family = AF_PACKET;
	dst.sll_ifindex = s->ipoe->ifindex;
	dst.sll_protocol = htons(ETH_P_ARP);

	ah2.ar_hrd = htons(ARPHRD_ETHER);
	ah2.ar_pro = htons(ETH_P_IP);
	ah2.ar_hln = ETH_ALEN;
	ah2.ar_pln = 4;
	ah2.ar_op = htons(ARPOP_REPLY);

	while (1) {
		n = recvfrom(h->fd, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&src, &slen);
		if (n < 0) {
			if (errno == EAGAIN)
				break;
			continue;
		}

		if (n < sizeof(*ah))
			continue;

		if (ah->ar_op != htons(ARPOP_REQUEST))
			continue;

		if (ah->ar_pln != 4)
			continue;

		if (ah->ar_pro != htons(ETH_P_IP))
			continue;

		if (ah->ar_hln != ETH_ALEN)
			continue;

		if (memcmp(ah->ar_sha, src.sll_addr, ETH_ALEN))
			continue;

		ses1 = ses2 = NULL;
		pthread_mutex_lock(&s->ipoe->lock);
		list_for_each_entry(ses, &s->ipoe->sessions, entry) {
			if (ses->yiaddr == ah->ar_spa) {
				ses1 = ses;
				if (ses->ses.state != AP_STATE_ACTIVE)
					break;
			}
			if (ses->yiaddr == ah->ar_tpa) {
				ses2 = ses;
				if (ses->ses.state != AP_STATE_ACTIVE)
					break;
			}
			if (ses1 && ses2)
				break;
		}

		if (!ses1 || (ses1->ses.state != AP_STATE_ACTIVE) ||
			  (ses2 && ses2->ses.state != AP_STATE_ACTIVE)) {
			pthread_mutex_unlock(&s->ipoe->lock);
			continue;
		}

		if (ses2) {
			if (s->ipoe->opt_arp == 1 || ses1 == ses2) {
				pthread_mutex_unlock(&s->ipoe->lock);
				continue;
			}
			if (s->ipoe->opt_arp == 2)
				memcpy(ah2.ar_sha, ses2->hwaddr, ETH_ALEN);
			else
				memcpy(ah2.ar_sha, s->ipoe->hwaddr, ETH_ALEN);
		} else
			memcpy(ah2.ar_sha, s->ipoe->hwaddr, ETH_ALEN);

		pthread_mutex_unlock(&s->ipoe->lock);

		memcpy(dst.sll_addr, ah->ar_sha, ETH_ALEN);
		memcpy(ah2.ar_tha, ah->ar_sha, ETH_ALEN);
		ah2.ar_spa = ah->ar_tpa;
		ah2.ar_tpa = ah->ar_spa;

		sendto(h->fd, &ah2, sizeof(ah2), MSG_DONTWAIT, (struct sockaddr *)&dst, sizeof(dst));
	}

	return 0;
}

struct arp_serv *arpd_start(struct ipoe_serv *ipoe)
{
	int sock;
	struct sockaddr_ll addr;
	struct arp_serv *s;
	int f = 1, fd;
	char fname[1024];

	sprintf(fname, "/proc/sys/net/ipv4/conf/%s/proxy_arp", ipoe->ifname);
	fd = open(fname, O_WRONLY);
	if (fd >= 0) {
		fname[0] = '0';
		write(fd, fname, 1);
		close(fd);
	}

	sock = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_error("ipoe: arp: socket: %s\n", strerror(errno));
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	addr.sll_ifindex = ipoe->ifindex;

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &f, sizeof(f))) {
		log_error("ipoe: setsockopt(SO_BROADCAST): %s\n", strerror(errno));
		close(sock);
		return NULL;
	}

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		log_error("ipoe: arp: bind: %s\n", strerror(errno));
		close(sock);
		return NULL;
	}

	s = _malloc(sizeof(*s));
	s->ipoe = ipoe;
	s->h.fd = sock;
	s->h.read = arp_read;

	fcntl(sock, F_SETFL, O_NONBLOCK);
	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	triton_md_register_handler(&ipoe->ctx, &s->h);
	triton_md_enable_handler(&s->h, MD_MODE_READ);

	return s;
}

void arpd_stop(struct arp_serv *arp)
{
	triton_md_unregister_handler(&arp->h, 1);
	_free(arp);
}

