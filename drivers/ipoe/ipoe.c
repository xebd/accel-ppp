#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/mroute.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/semaphore.h>
#include <linux/version.h>

#include <net/genetlink.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/flow.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "ipoe.h"

#define BEGIN_UPDATE 1
#define UPDATE 2
#define END_UPDATE 3

#define HASH_BITS 0xff

#define IPOE_MAGIC 0x55aa

#define IPOE_QUEUE_LEN 100
#define IPOE_RATE_U 3000 //3s
#define IPOE_TIMEOUT_U 30 //5s

#define IPOE_NLMSG_SIZE (NLMSG_DEFAULT_SIZE - GENL_HDRLEN - 128)

#ifndef DEFINE_SEMAPHORE
#define DEFINE_SEMAPHORE(name) struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
struct ipoe_stats 
{
	struct u64_stats_sync sync;
	u64 packets;
	u64 bytes;
};
#endif

struct ipoe_session 
{
	struct list_head entry;
	struct list_head entry2;

	__be32 addr;
	__be32 peer_addr;
	__u8 hwaddr[ETH_ALEN];

	struct net_device *dev;
	struct net_device *link_dev;

	atomic_t refs;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	struct ipoe_stats __percpu *rx_stats;
	struct ipoe_stats __percpu *tx_stats;
#endif
};

struct ipoe_network
{
	struct rcu_head rcu_head;
	struct list_head entry;
	
	__be32 addr;
	__be32 mask;
};

struct ipoe_entry_u
{
	struct rcu_head rcu_head;
	struct list_head entry1;
	struct list_head entry2;

	__be32 addr;
	unsigned long tstamp;
};

static struct list_head ipoe_list[HASH_BITS + 1];
static struct list_head ipoe_list1_u[HASH_BITS + 1];
static LIST_HEAD(ipoe_list2);
static LIST_HEAD(ipoe_list2_u);
static DEFINE_SEMAPHORE(ipoe_wlock);
static LIST_HEAD(ipoe_networks);
static struct work_struct ipoe_queue_work;
static struct sk_buff_head ipoe_queue;

static void ipoe_start_queue_work(unsigned long);
static DEFINE_TIMER(ipoe_timer_u, ipoe_start_queue_work, 0, 0);

static struct ipoe_session *ipoe_lookup(__be32 addr);
static int ipoe_do_nat(struct sk_buff *skb, __be32 new_addr, int to_peer);
static void ipoe_queue_u(struct sk_buff *skb, __be32 addr);
static int ipoe_lookup1_u(__be32 addr, unsigned long *ts);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static const struct net_device_ops ipoe_netdev_ops;
#endif

static struct genl_family ipoe_nl_family;
static struct genl_multicast_group ipoe_nl_mcg;

static inline int hash_addr(__be32 addr)
{
#ifdef __LITTLE_ENDIAN
	return ((addr >> 24) ^ (addr >> 16)) & HASH_BITS;
#else
	return (addr  ^ (addr >> 8)) & HASH_BITS;
#endif	
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
static void ipoe_update_stats(struct sk_buff *skb, struct ipoe_stats *st)
{
	u64_stats_update_begin(&st->sync);
	st->packets++;
	st->bytes += skb->len;
	u64_stats_update_end(&st->sync);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static void __kfree_rcu(struct rcu_head *head)
{
	kfree(head);
}
#endif

static int ipoe_check_network(__be32 addr)
{
	struct ipoe_network *n;
	int r = 0;

	rcu_read_lock();

	list_for_each_entry_rcu(n, &ipoe_networks, entry) {
		if ((addr & n->mask) == n->addr) {
			r = 1;
			break;
		}
	}

	rcu_read_unlock();

	return r;
}

static int ipoe_do_nat(struct sk_buff *skb, __be32 new_addr, int to_peer)
{
	struct iphdr  *iph;
	int noff;
	int ihl;
	__be32 addr;

	noff = skb_network_offset(skb);

	iph = ip_hdr(skb);

	if (to_peer)
		addr = iph->daddr;
	else
		addr = iph->saddr;

	if (skb_cloned(skb) &&
			!skb_clone_writable(skb, sizeof(*iph) + noff) &&
			pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
		return -1;

	iph = ip_hdr(skb);

	if (to_peer)
		iph->daddr = new_addr;
	else
		iph->saddr = new_addr;

	csum_replace4(&iph->check, addr, new_addr);

	ihl = iph->ihl * 4;

	switch (iph->frag_off & htons(IP_OFFSET) ? 0 : iph->protocol) {
	case IPPROTO_TCP:
	{
		struct tcphdr *tcph;

		if (!pskb_may_pull(skb, ihl + sizeof(*tcph) + noff) ||
				(skb_cloned(skb) &&
				 !skb_clone_writable(skb, ihl + sizeof(*tcph) + noff) &&
				 pskb_expand_head(skb, 0, 0, GFP_ATOMIC)))
			return -1;

		tcph = (void *)(skb_network_header(skb) + ihl);
		inet_proto_csum_replace4(&tcph->check, skb, addr, new_addr, 1);
		break;
	}
	case IPPROTO_UDP:
	{
		struct udphdr *udph;

		if (!pskb_may_pull(skb, ihl + sizeof(*udph) + noff) ||
				(skb_cloned(skb) &&
				 !skb_clone_writable(skb, ihl + sizeof(*udph) + noff) &&
				 pskb_expand_head(skb, 0, 0, GFP_ATOMIC)))
			return -1;

		udph = (void *)(skb_network_header(skb) + ihl);
		if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
			inet_proto_csum_replace4(&udph->check, skb, addr, new_addr, 1);
			if (!udph->check)
				udph->check = CSUM_MANGLED_0;
		}
		break;
	}
	case IPPROTO_ICMP:
	{
		struct icmphdr *icmph;

		if (!pskb_may_pull(skb, ihl + sizeof(*icmph) + noff))
			return -1;

		icmph = (void *)(skb_network_header(skb) + ihl);

		if ((icmph->type != ICMP_DEST_UNREACH) &&
				(icmph->type != ICMP_TIME_EXCEEDED) &&
				(icmph->type != ICMP_PARAMETERPROB))
			break;

		if (!pskb_may_pull(skb, ihl + sizeof(*icmph) + sizeof(*iph) +
					noff))
			return -1;

		icmph = (void *)(skb_network_header(skb) + ihl);
		iph = (void *)(icmph + 1);
		
		if (skb_cloned(skb) &&
				!skb_clone_writable(skb, ihl + sizeof(*icmph) +
							 sizeof(*iph) + noff) &&
				pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
			return -1;

		icmph = (void *)(skb_network_header(skb) + ihl);
		iph = (void *)(icmph + 1);
		if (to_peer)
			iph->saddr = new_addr;
		else
			iph->daddr = new_addr;

		inet_proto_csum_replace4(&icmph->checksum, skb, addr, new_addr, 0);
		break;
	}
	default:
		break;
	}

	return 0;
}

static struct net *pick_net(struct sk_buff *skb)
{
#ifdef CONFIG_NET_NS
	const struct dst_entry *dst;

	if (skb->dev != NULL)
		return dev_net(skb->dev);
	dst = skb_dst(skb);
	if (dst != NULL && dst->dev != NULL)
		return dev_net(dst->dev);
#endif
	return &init_net;
}

static int ipoe_route4(struct sk_buff *skb)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct net *net = pick_net(skb);
	struct rtable *rt;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37)
	struct flowi fl4;
#else
	struct flowi4 fl4;
#endif

	memset(&fl4, 0, sizeof(fl4));
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37)
	fl4.fl4_dst = iph->daddr;
	fl4.fl4_tos = RT_TOS(iph->tos);
	fl4.fl4_scope = RT_SCOPE_UNIVERSE;
	if (ip_route_output_key(net, &rt, &fl4))
		return -1;
#else
	fl4.daddr = iph->daddr;
	fl4.flowi4_tos = RT_TOS(iph->tos);
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	rt = ip_route_output_key(net, &fl4);
	if (IS_ERR(rt))
		return -1;
#endif

	skb_dst_drop(skb);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37)
	skb_dst_set(skb, &rt->u.dst);
	skb->dev      = rt->u.dst.dev;
#else
	skb_dst_set(skb, &rt->dst);
	skb->dev      = rt->dst.dev;
#endif

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
static int ipoe_xmit(struct sk_buff *skb, struct net_device *dev)
#else
static netdev_tx_t ipoe_xmit(struct sk_buff *skb, struct net_device *dev)
#endif
{
	struct ipoe_session *ses = netdev_priv(dev);
	struct net_device_stats *stats = &dev->stats;
	struct iphdr  *iph;
	struct ethhdr *eth;
	struct sk_buff *skb1;
	/*struct arphdr *arp;
	unsigned char *arp_ptr;
	__be32 tip;*/
	int noff;

	if (!ses->peer_addr)
		goto drop;
	
	noff = skb_network_offset(skb);

	if (skb->protocol == htons(ETH_P_IP)) {
		if (!pskb_may_pull(skb, sizeof(*iph) + noff))
			goto drop;
		
		iph = ip_hdr(skb);

		//pr_info("ipoe: xmit %08x %08x\n", iph->saddr, iph->daddr);
		
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
		ipoe_update_stats(skb, this_cpu_ptr(ses->tx_stats));
#else
		stats->tx_packets++;
		stats->tx_bytes += skb->len;
#endif

		if (iph->daddr == ses->addr) {
			if (skb_shared(skb)) {
				skb1 = skb_clone(skb, GFP_ATOMIC);
				if (!skb1)
					goto drop;
				skb = skb1;
			}

			if (ipoe_do_nat(skb, ses->peer_addr, 1))
				goto drop;

			if (!ses->link_dev) {
				iph = ip_hdr(skb);
				
				ip_send_check(iph);
				
				if (ipoe_route4(skb))
					goto drop;

				pskb_pull(skb, ETH_HLEN);
				skb_reset_network_header(skb);

				ip_local_out(skb);

				return NETDEV_TX_OK;
			} else {
				eth = (struct ethhdr *)skb->data;

				memcpy(eth->h_dest, ses->hwaddr, ETH_ALEN);
				memcpy(eth->h_source, ses->link_dev->dev_addr, ETH_ALEN);
			}
		}
	} /*else if (skb->protocol == htons(ETH_P_ARP)) {
		if (!pskb_may_pull(skb, arp_hdr_len(dev) + noff))
			goto drop;
		
		arp = arp_hdr(skb);
		arp_ptr = (unsigned char *)(arp + 1);
		
		if (arp->ar_op == htons(ARPOP_REQUEST)) {
			memcpy(&tip, arp_ptr + ETH_ALEN + 4 + ETH_ALEN, 4);
			if (tip == ses->addr) {
				if (skb_cloned(skb) &&
						!skb_clone_writable(skb, arp_hdr_len(dev) + noff) &&
						pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
					goto drop;
				
				arp = arp_hdr(skb);
				arp_ptr = (unsigned char *)(arp + 1);
				memcpy(arp_ptr + ETH_ALEN + 4 + ETH_ALEN, &ses->peer_addr, 4);
			}
		}
	}*/
	
	if (ses->link_dev) {
		skb->dev = ses->link_dev;
		//skb->skb_iif = dev->ifindex;
		dev_queue_xmit(skb);

		return NETDEV_TX_OK;
	}
drop:
	stats->tx_dropped++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int ipoe_rcv_arp(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct ipoe_session *ses = NULL;
	struct arphdr *arp;
	unsigned char *arp_ptr;
	int noff;
	__be32 sip;
	struct sk_buff *skb1;
	unsigned char *cb_ptr;
	struct net_device_stats *stats;

	//pr_info("ipoe: recv arp\n");
	
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;
	
	cb_ptr = skb->cb + sizeof(skb->cb) - 2;
	
	if (*(__u16 *)cb_ptr == IPOE_MAGIC)
		goto drop;

	noff = skb_network_offset(skb);

	if (!pskb_may_pull(skb, arp_hdr_len(dev) + noff))
		goto drop;
	
	arp = arp_hdr(skb);
	arp_ptr = (unsigned char *)(arp + 1);

	if (arp->ar_pro != htons(ETH_P_IP))
		goto drop;
	
	memcpy(&sip, arp_ptr + ETH_ALEN, 4);

	if (!sip)
		goto drop;
	//pr_info("ipoe: recv arp %08x\n", sip);

	ses = ipoe_lookup(sip);

	if (!ses)
		goto drop;
	
	stats = &ses->dev->stats;
	
	if (ses->addr || skb->dev == ses->dev) {
		atomic_dec(&ses->refs);
		goto drop;
	}
	
	skb1 = skb_clone(skb, GFP_ATOMIC);
	if (!skb1) {
		stats->rx_dropped++;
		goto drop_unlock;
	}

	skb1->dev = ses->dev;
	skb1->skb_iif = ses->dev->ifindex;

	cb_ptr = skb1->cb + sizeof(skb1->cb) - 2;
	*(__u16 *)cb_ptr = IPOE_MAGIC;

	netif_rx(skb1);
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	ipoe_update_stats(skb, this_cpu_ptr(ses->rx_stats));
#else
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
#endif

drop_unlock:
	atomic_dec(&ses->refs);
	skb->pkt_type = PACKET_OTHERHOST;

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int ipoe_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct ipoe_session *ses = NULL;
	struct iphdr *iph;
	struct ethhdr *eth;
	int noff;
	struct sk_buff *skb1;
	unsigned char *cb_ptr;
	struct net_device_stats *stats;

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;
	
	cb_ptr = skb->cb + sizeof(skb->cb) - 2;

	if (*(__u16 *)cb_ptr == IPOE_MAGIC)
		goto drop;
	
	noff = skb_network_offset(skb);

	if (!pskb_may_pull(skb, sizeof(*iph) + noff))
		goto drop;
	
	iph = ip_hdr(skb);

	if (!iph->saddr)
		goto drop;

	//pr_info("ipoe: recv %08x %08x\n", iph->saddr, iph->daddr);
	if (!ipoe_check_network(iph->saddr))
		goto drop;
	
	ses = ipoe_lookup(iph->saddr);
	
	if (!ses) {
		ipoe_queue_u(skb, iph->saddr);
		goto drop;
	}
	
	//pr_info("ipoe: recv cb=%x\n", *(__u16 *)cb_ptr);
	
	if (ses->link_dev) {
		eth = eth_hdr(skb);
		if (memcmp(eth->h_source, ses->hwaddr, ETH_ALEN))
			goto drop_unlock;
	}

	stats = &ses->dev->stats;
	
	if (skb->dev == ses->dev) {
		//pr_info("ipoe: dup\n");
		atomic_dec(&ses->refs);
		goto drop;
	}

	if (ses->addr && ipoe_check_network(iph->daddr)) {
		atomic_dec(&ses->refs);
		goto drop;
	}
	
	skb1 = skb_clone(skb, GFP_ATOMIC);
	if (!skb1) {
		stats->rx_dropped++;
		goto drop_unlock;
	}

	if (ses->addr && ipoe_do_nat(skb1, ses->addr, 0)) {
		kfree_skb(skb1);
		goto drop_unlock;
	}

	skb1->dev = ses->dev;
	//skb1->skb_iif = ses->dev->ifindex;
	
	cb_ptr = skb1->cb + sizeof(skb1->cb) - 2;
	*(__u16 *)cb_ptr = IPOE_MAGIC;

	netif_rx(skb1);
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	ipoe_update_stats(skb, this_cpu_ptr(ses->rx_stats));
#else
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
#endif

drop_unlock:
	atomic_dec(&ses->refs);
	skb->pkt_type = PACKET_OTHERHOST;
	
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int ipoe_lookup1_u(__be32 addr, unsigned long *ts)
{
	struct ipoe_entry_u *e;
	struct list_head *head = &ipoe_list1_u[hash_addr(addr)];
	int r = 0;
	
	rcu_read_lock();

	list_for_each_entry_rcu(e, head, entry1) {
		if (e->addr == addr) {
			*ts = e->tstamp;
			r = 1;
			break;
		}
	}

	rcu_read_unlock();

	return r;
}

static struct ipoe_entry_u *ipoe_lookup2_u(__be32 addr)
{
	struct ipoe_entry_u *e;
	struct list_head *head = &ipoe_list1_u[hash_addr(addr)];

	list_for_each_entry_rcu(e, head, entry1) {
		if (e->addr == addr)
			return e;
	}

	return NULL;
}


static void ipoe_queue_u(struct sk_buff *skb, __u32 addr)
{
	unsigned long ts;

	if (ipoe_lookup1_u(addr, &ts) && jiffies_to_msecs(jiffies - ts) < IPOE_RATE_U) {
		//pr_info("not queue %08x\n", addr);
		return;
	}
	
	if (skb_queue_len(&ipoe_queue) > IPOE_QUEUE_LEN)
		return;

	skb = skb_clone(skb, GFP_ATOMIC);
	if (!skb)
		return;
	
	//pr_info("queue %08x\n", addr);

	skb_queue_tail(&ipoe_queue, skb);
	schedule_work(&ipoe_queue_work);
}

static void ipoe_start_queue_work(unsigned long dummy)
{
	schedule_work(&ipoe_queue_work);
}

static void ipoe_process_queue(struct work_struct *w)
{
	struct sk_buff *skb;
	struct ipoe_entry_u *e;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct sk_buff *report_skb = NULL;
	void *header = NULL;
	struct nlattr *ns;
	int id = 1;

	do {
		while ((skb = skb_dequeue(&ipoe_queue))) {
			eth = eth_hdr(skb);
			iph = ip_hdr(skb);
		
			e = ipoe_lookup2_u(iph->saddr);
			
			if (!e) {
				e = kmalloc(sizeof(*e), GFP_KERNEL);
				e->addr = iph->saddr;
				e->tstamp = jiffies;

				list_add_tail_rcu(&e->entry1, &ipoe_list1_u[hash_addr(iph->saddr)]);
				list_add_tail(&e->entry2, &ipoe_list2_u);
		
				//pr_info("create %08x\n", e->addr);
			} else if (jiffies_to_msecs(jiffies - e->tstamp) < IPOE_RATE_U) {
				//pr_info("skip %08x\n", e->addr);
				kfree_skb(skb);
				continue;
			} else {
				e->tstamp = jiffies;
				list_move_tail(&e->entry2, &ipoe_list2_u);
				//pr_info("update %08x\n", e->addr);
			}

			if (!report_skb) {
				report_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
				if (report_skb)
					header = genlmsg_put(report_skb, 0, ipoe_nl_mcg.id, &ipoe_nl_family, 0, IPOE_REP_PKT);
			}

			if (report_skb) {
				ns = nla_nest_start(report_skb, id++);
				if (!ns)
					goto nl_err;
			
				if (nla_put_u32(report_skb, IPOE_ATTR_IFINDEX, skb->dev ? skb->dev->ifindex : skb->skb_iif))
					goto nl_err;

				if (nla_put(report_skb, IPOE_ATTR_ETH_HDR, sizeof(*eth), eth))
					goto nl_err;

				if (nla_put(report_skb, IPOE_ATTR_IP_HDR, sizeof(*iph), iph))
					goto nl_err;

				if (nla_nest_end(report_skb, ns) >= IPOE_NLMSG_SIZE) {
					genlmsg_end(report_skb, header);
					genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
					report_skb = NULL;
				}

				kfree_skb(skb);
				continue;

nl_err:
				nlmsg_free(report_skb);
				report_skb = NULL;
			}
				
			kfree_skb(skb);
		}
		
		while (!list_empty(&ipoe_list2_u)) {
			e = list_entry(ipoe_list2_u.next, typeof(*e), entry2);
			if (jiffies_to_msecs(jiffies - e->tstamp) < IPOE_TIMEOUT_U * 1000)
				break;

			//pr_info("free %08x\n", e->addr);
			list_del(&e->entry2);
			list_del_rcu(&e->entry1);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
			kfree_rcu(e, rcu_head);
#else
			call_rcu(&e->rcu_head, __kfree_rcu);
#endif
		}

		synchronize_rcu();
	} while (skb_queue_len(&ipoe_queue));

	if (report_skb) {
		genlmsg_end(report_skb, header);
		genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
	}

	if (!list_empty(&ipoe_list2_u))
		mod_timer(&ipoe_timer_u, jiffies + IPOE_TIMEOUT_U * HZ);
	else
		del_timer(&ipoe_timer_u);
}

static struct ipoe_session *ipoe_lookup(__be32 addr)
{
	struct ipoe_session *ses;
	struct list_head *head;

	head = &ipoe_list[hash_addr(addr)];
	
	rcu_read_lock();

	list_for_each_entry_rcu(ses, head, entry) {
		if (ses->peer_addr == addr) {
			atomic_inc(&ses->refs);
			rcu_read_unlock();
			return ses;
		}
	}

	rcu_read_unlock();

	return NULL;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
static struct rtnl_link_stats64 *ipoe_stats64(struct net_device *dev,
					     struct rtnl_link_stats64 *stats)
{
	struct ipoe_session *ses = netdev_priv(dev);
	struct ipoe_stats *st;
	unsigned int start;
	int i;
	u64 packets, bytes;
	u64 rx_packets = 0, rx_bytes = 0, tx_packets = 0, tx_bytes = 0;

	for_each_possible_cpu(i) {
		st = per_cpu_ptr(ses->rx_stats, i);

		do {
			start = u64_stats_fetch_begin_bh(&st->sync);
			packets = st->packets;
			bytes = st->bytes;
		} while (u64_stats_fetch_retry_bh(&st->sync, start));
		
		rx_packets += packets;
		rx_bytes += bytes;

		st = per_cpu_ptr(ses->tx_stats, i);

		do {
			start = u64_stats_fetch_begin_bh(&st->sync);
			packets = st->packets;
			bytes = st->bytes;
		} while (u64_stats_fetch_retry_bh(&st->sync, start));
		
		tx_packets += packets;
		tx_bytes += bytes;
	}

	stats->rx_packets = rx_packets;
	stats->rx_bytes = rx_bytes;
	stats->tx_packets = tx_packets;
	stats->tx_bytes = tx_bytes;

	stats->rx_dropped = dev->stats.rx_dropped;
	stats->tx_dropped = dev->stats.tx_dropped;

	return stats;
}
#endif

static void ipoe_free_netdev(struct net_device *dev)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	struct ipoe_session *ses = netdev_priv(dev);

	if (ses->rx_stats)
		free_percpu(ses->rx_stats);
	if (ses->tx_stats)
		free_percpu(ses->tx_stats);
#endif
	
	free_netdev(dev);
}

static int ipoe_hard_header(struct sk_buff *skb, struct net_device *dev,
			       unsigned short type, const void *daddr,
			       const void *saddr, unsigned len)
{
	const struct ipoe_session *ses = netdev_priv(dev);

	if (ses->link_dev)
		return dev_hard_header(skb, ses->link_dev, type, daddr,
			       saddr, len);
	else
		return eth_header(skb, dev, type, daddr, saddr, len);
}

static const struct header_ops ipoe_hard_header_ops = {
	.create  	= ipoe_hard_header,
	.rebuild	= eth_rebuild_header,
	.parse		= eth_header_parse,
	.cache		= eth_header_cache,
	.cache_update	= eth_header_cache_update,
};

static void ipoe_netdev_setup(struct net_device *dev)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	dev->hard_start_xmit	= ipoe_xmit;
#else
	dev->netdev_ops = &ipoe_netdev_ops;
#endif
	dev->destructor = ipoe_free_netdev;

	dev->type = ARPHRD_ETHER;
	dev->hard_header_len = 0;
	dev->mtu = ETH_DATA_LEN;
	dev->flags = IFF_MULTICAST | IFF_POINTOPOINT;
	dev->iflink = 0;
	dev->addr_len = ETH_ALEN;
	dev->features  |= NETIF_F_NETNS_LOCAL;
	dev->header_ops	= &ipoe_hard_header_ops,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
#endif
}

static int ipoe_create(__be32 peer_addr, __be32 addr, const char *link_ifname, const __u8 *hwaddr)
{
	struct ipoe_session *ses;
	struct net_device *dev, *link_dev = NULL;
	char name[IFNAMSIZ];
	int r = -EINVAL;
	int h = hash_addr(peer_addr);

	if (link_ifname) {
		link_dev = dev_get_by_name(&init_net, link_ifname);
		if (!link_dev)
			return -EINVAL;
		sprintf(name, "%s.ipoe%%d", link_ifname);
	} else
		sprintf(name, "ipoe%%d");

	dev = alloc_netdev(sizeof(*ses), name, ipoe_netdev_setup);
	if (dev == NULL) {
		r = -ENOMEM;
		goto failed;
	}

	dev_net_set(dev, &init_net);

	r = dev_alloc_name(dev, name);
	if (r < 0) {
		r = -ENOMEM;
		goto failed_free;
	}
	
	ses = netdev_priv(dev);
	atomic_set(&ses->refs, 0);
	ses->dev = dev;
	ses->addr = addr;
	ses->peer_addr = peer_addr;
	ses->link_dev = link_dev;
	memcpy(ses->hwaddr, hwaddr, ETH_ALEN);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	ses->rx_stats = alloc_percpu(struct ipoe_stats);
	ses->tx_stats = alloc_percpu(struct ipoe_stats);
	if (!ses->rx_stats || !ses->tx_stats) {
		r = -ENOMEM;
		goto failed_free;
	}
#endif
	
	if (link_dev) {
		dev->features = link_dev->features;
		memcpy(dev->dev_addr, link_dev->dev_addr, ETH_ALEN);
		memcpy(dev->broadcast, link_dev->broadcast, ETH_ALEN);
	}

	if (addr)
		dev->flags |= IFF_NOARP;
	else
		dev->flags &= ~IFF_NOARP;

	rtnl_lock();
	r = register_netdevice(dev);
	rtnl_unlock();
	if (r < 0)
		goto failed_free;

	down(&ipoe_wlock);
	if (peer_addr)
		list_add_tail_rcu(&ses->entry, &ipoe_list[h]);
	list_add_tail(&ses->entry2, &ipoe_list2);
	r = dev->ifindex;
	up(&ipoe_wlock);

	return r;

failed_free:
	free_netdev(dev);
failed:
	if (link_dev)
		dev_put(link_dev);
	return r;
}

static int ipoe_nl_cmd_noop(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	int ret = -ENOBUFS;

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq,
			  &ipoe_nl_family, 0, IPOE_CMD_NOOP);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto err_out;
	}

	genlmsg_end(msg, hdr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	return genlmsg_unicast(msg, info->snd_pid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#endif

err_out:
	nlmsg_free(msg);

out:
	return ret;
}

static int ipoe_nl_cmd_create(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	__be32 peer_addr = 0, addr  = 0;
	int ret = 0;
	char ifname[IFNAMSIZ];
	__u8 hwaddr[ETH_ALEN];
	struct ipoe_session *ses;
	//struct net *net = genl_info_net(info);

	if (info->attrs[IPOE_ATTR_PEER_ADDR]) {
		peer_addr = nla_get_be32(info->attrs[IPOE_ATTR_PEER_ADDR]);
		if (peer_addr) {
			ses = ipoe_lookup(peer_addr);
			if (ses) {
				atomic_dec(&ses->refs);
				return -EEXIST;
			}
		}
	}

	if (info->attrs[IPOE_ATTR_ADDR])
		addr = nla_get_be32(info->attrs[IPOE_ATTR_ADDR]);

	if (info->attrs[IPOE_ATTR_IFNAME])
		nla_strlcpy(ifname, info->attrs[IPOE_ATTR_IFNAME], IFNAMSIZ - 1);

	if (info->attrs[IPOE_ATTR_HWADDR])
		nla_memcpy(hwaddr, info->attrs[IPOE_ATTR_HWADDR], ETH_ALEN);
	else
		memset(hwaddr, 0, sizeof(hwaddr));

	msg = nlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq,
			  &ipoe_nl_family, 0, IPOE_CMD_CREATE);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto err_out;
	}

	//pr_info("ipoe: create %08x %08x %s\n", peer_addr, addr, info->attrs[IPOE_ATTR_IFNAME] ? ifname : "-");
	
	ret = ipoe_create(peer_addr, addr, info->attrs[IPOE_ATTR_IFNAME] ? ifname : NULL, hwaddr);

	if (ret < 0) {
		nlmsg_free(msg);
		return ret;
	}

	nla_put_u32(msg, IPOE_ATTR_IFINDEX, ret);

	genlmsg_end(msg, hdr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	return genlmsg_unicast(msg, info->snd_pid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#endif

err_out:
	nlmsg_free(msg);

out:
	return ret;
}

static int ipoe_nl_cmd_delete(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *dev;
	struct ipoe_session *ses;
	int ifindex;
	int r = 0;
	int ret = -EINVAL;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;
	
	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	down(&ipoe_wlock);

	rcu_read_lock();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	dev = dev_get_by_index_rcu(ifindex);
#else
	dev = dev_get_by_index_rcu(&init_net, ifindex);
#endif
	if (!dev || dev->header_ops != &ipoe_hard_header_ops)
		r = 1;
	rcu_read_unlock();

	if (r)
		goto out_unlock;
	
	ses = netdev_priv(dev);

	//pr_info("ipoe: delete %08x\n", ses->peer_addr);
	
	if (ses->peer_addr)
		list_del_rcu(&ses->entry);
	list_del(&ses->entry2);

	up(&ipoe_wlock);

	synchronize_rcu();

	while (atomic_read(&ses->refs))
		schedule_timeout_uninterruptible(1);

	if (ses->link_dev)
		dev_put(ses->link_dev);

	unregister_netdev(ses->dev);

	ret = 0;

out_unlock:
	up(&ipoe_wlock);
	return ret;
}

static int ipoe_nl_cmd_modify(struct sk_buff *skb, struct genl_info *info)
{
	int ret = -EINVAL, r = 0;
	char ifname[IFNAMSIZ];
	struct net_device *dev, *link_dev, *old_dev;
	struct ipoe_session *ses, *ses1;
	int ifindex;
	__be32 peer_addr;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	down(&ipoe_wlock);

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	rcu_read_lock();
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	dev = dev_get_by_index_rcu(ifindex);
#else
	dev = dev_get_by_index_rcu(&init_net, ifindex);
#endif
	if (!dev || dev->header_ops != &ipoe_hard_header_ops)
		r = 1;
	rcu_read_unlock();

	if (r)
		goto out_unlock;
	
	ses = netdev_priv(dev);

	if (info->attrs[IPOE_ATTR_PEER_ADDR]) {
		peer_addr = nla_get_be32(info->attrs[IPOE_ATTR_PEER_ADDR]);
		if (peer_addr) {
			ses1 = ipoe_lookup(peer_addr);
			if (ses1) {
				atomic_dec(&ses1->refs);
				if (ses1 != ses) {
					ret = -EEXIST;
					goto out_unlock;
				}
			}
		}

		if (ses->peer_addr) {
			list_del_rcu(&ses->entry);
			synchronize_rcu();
		}
		
		ses->peer_addr = peer_addr;

		if (peer_addr)
			list_add_tail_rcu(&ses->entry, &ipoe_list[hash_addr(peer_addr)]);
	}

	if (info->attrs[IPOE_ATTR_IFNAME]) {
		nla_strlcpy(ifname, info->attrs[IPOE_ATTR_IFNAME], IFNAMSIZ - 1);
	
		if (*ifname) {
			link_dev = dev_get_by_name(&init_net, ifname);

			if (!link_dev)
				goto out_unlock;
		} else
			link_dev = NULL;
		
		old_dev = ses->link_dev;
		ses->link_dev = link_dev;

		if (link_dev) {
			ses->dev->features = link_dev->features;
			memcpy(dev->dev_addr, link_dev->dev_addr, ETH_ALEN);
			memcpy(dev->broadcast, link_dev->broadcast, ETH_ALEN);
		}

		if (old_dev)
			dev_put(old_dev);
	}

	if (info->attrs[IPOE_ATTR_ADDR]) {
		ses->addr = nla_get_be32(info->attrs[IPOE_ATTR_ADDR]);
		if (ses->addr)
			dev->flags |= IFF_NOARP;
		else
			dev->flags &= ~IFF_NOARP;
	}

	if (info->attrs[IPOE_ATTR_HWADDR])
		nla_memcpy(ses->hwaddr, info->attrs[IPOE_ATTR_HWADDR], ETH_ALEN);

	//pr_info("ipoe: modify %08x %08x\n", ses->peer_addr, ses->addr);

	ret = 0;

out_unlock:
	up(&ipoe_wlock);
	return ret;
}

static int fill_info(struct sk_buff *skb, struct ipoe_session *ses, u32 pid, u32 seq)
{
	void *hdr;

	hdr = genlmsg_put(skb, pid, seq, &ipoe_nl_family, NLM_F_MULTI, IPOE_CMD_GET);
	if (!hdr)
		return -EMSGSIZE;
	
	NLA_PUT_U32(skb, IPOE_ATTR_IFINDEX, ses->dev->ifindex);
	NLA_PUT_U32(skb, IPOE_ATTR_PEER_ADDR, ses->peer_addr);
	NLA_PUT_U32(skb, IPOE_ATTR_ADDR, ses->addr);

	return genlmsg_end(skb, hdr);

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int ipoe_nl_cmd_dump_sessions(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ipoe_session *ses;
	int idx = 0, start_idx = cb->args[0];

	down(&ipoe_wlock);

	list_for_each_entry(ses, &ipoe_list2, entry2) {
		if (idx > start_idx)
			start_idx = 0;

		if (idx++ < start_idx)
			continue;

		if (fill_info(skb, ses, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq) < 0)
			break;
	}

	up(&ipoe_wlock);

	cb->args[0] = idx;

	return skb->len;
}

static int ipoe_nl_cmd_add_net(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_network *n;

	if (!info->attrs[IPOE_ATTR_ADDR] || !info->attrs[IPOE_ATTR_MASK])
		return -EINVAL;
	
	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->addr = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);
	n->mask = nla_get_u32(info->attrs[IPOE_ATTR_MASK]);
	//pr_info("add net %08x/%08x\n", n->addr, n->mask);

	down(&ipoe_wlock);
	list_add_tail_rcu(&n->entry, &ipoe_networks);
	up(&ipoe_wlock);

	return 0;
}

static int ipoe_nl_cmd_del_net(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_network *n;
	__be32 addr;

	if (!info->attrs[IPOE_ATTR_ADDR])
		return -EINVAL;

	addr = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);

	rcu_read_lock();
	list_for_each_entry_rcu(n, &ipoe_networks, entry) {
		if (!addr || addr == n->addr) {
			//pr_info("del net %08x/%08x\n", n->addr, n->mask);
			list_del_rcu(&n->entry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
			kfree_rcu(n, rcu_head);
#else
			call_rcu(&n->rcu_head, __kfree_rcu);
#endif
		}
	}
	rcu_read_unlock();

	synchronize_rcu();

	return 0;
}


static struct nla_policy ipoe_nl_policy[IPOE_ATTR_MAX + 1] = {
	[IPOE_ATTR_NONE]		    = { .type = NLA_UNSPEC,                     },
	[IPOE_ATTR_ADDR]	      = { .type = NLA_U32,                        },
	[IPOE_ATTR_PEER_ADDR]	= { .type = NLA_U32,                          },
	[IPOE_ATTR_IFNAME]	    = { .type = NLA_STRING, .len = IFNAMSIZ - 1 },
	[IPOE_ATTR_HWADDR]	    = { .type = NLA_U64                         },
	[IPOE_ATTR_IFNAME]	    = { .type = NLA_STRING, .len = IFNAMSIZ - 1 },
	[IPOE_ATTR_MASK]	      = { .type = NLA_U32,                        },
};

static struct genl_ops ipoe_nl_ops[] = {
	{
		.cmd = IPOE_CMD_NOOP,
		.doit = ipoe_nl_cmd_noop,
		.policy = ipoe_nl_policy,
		/* can be retrieved by unprivileged users */
	},
	{
		.cmd = IPOE_CMD_CREATE,
		.doit = ipoe_nl_cmd_create,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_DELETE,
		.doit = ipoe_nl_cmd_delete,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_MODIFY,
		.doit = ipoe_nl_cmd_modify,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_GET,
		.dumpit = ipoe_nl_cmd_dump_sessions,
		.policy = ipoe_nl_policy,
	},
	{
		.cmd = IPOE_CMD_ADD_NET,
		.doit = ipoe_nl_cmd_add_net,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_DEL_NET,
		.doit = ipoe_nl_cmd_del_net,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family ipoe_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= IPOE_GENL_NAME,
	.version	= IPOE_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= IPOE_ATTR_MAX,
};

static struct genl_multicast_group ipoe_nl_mcg = {
	.name = IPOE_GENL_MCG_PKT,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static const struct net_device_ops ipoe_netdev_ops = {
	.ndo_start_xmit	= ipoe_xmit,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	.ndo_get_stats64 = ipoe_stats64,
#endif
};
#endif

static struct packet_type ip_packet_type = {
	.type = __constant_htons(ETH_P_IP),
	.func = ipoe_rcv,
};

static struct packet_type arp_packet_type = {
	.type = __constant_htons(ETH_P_ARP),
	.func = ipoe_rcv_arp,
};

/*static struct pernet_operations ipoe_net_ops = {
	.init = ipoe_init_net,
	.exit = ipoe_exit_net,
	.id   = &ipoe_net_id,
	.size = sizeof(struct ipoe_net),
};*/

static int __init ipoe_init(void)
{
	int err, i;

	printk("IPoE session driver v0.1\n");

	/*err = register_pernet_device(&ipoe_net_ops);
	if (err < 0)
		return err;*/
	for (i = 0; i < HASH_BITS + 1; i++) {
		INIT_LIST_HEAD(&ipoe_list[i]);
		INIT_LIST_HEAD(&ipoe_list1_u[i]);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	err = genl_register_family(&ipoe_nl_family);
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink interface\n");
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(ipoe_nl_ops); i++) {
		err = genl_register_ops(&ipoe_nl_family, &ipoe_nl_ops[i]);
		if (err)
			break;
	}

	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink interface\n");
		goto out_unreg;
	}
#else
	err = genl_register_family_with_ops(&ipoe_nl_family, ipoe_nl_ops,
					    ARRAY_SIZE(ipoe_nl_ops));
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink interface\n");
		goto out;
	}
#endif

	err = genl_register_mc_group(&ipoe_nl_family, &ipoe_nl_mcg);
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink multicast group\n");
		goto out_unreg;
	}

	skb_queue_head_init(&ipoe_queue);
	INIT_WORK(&ipoe_queue_work, ipoe_process_queue);

	dev_add_pack(&ip_packet_type);
	dev_add_pack(&arp_packet_type);

	return 0;

out_unreg:
	genl_unregister_family(&ipoe_nl_family);
out:
	return err;
}

static void __exit ipoe_fini(void)
{
	struct ipoe_network *n;
	struct ipoe_entry_u *e;
	struct ipoe_session *ses;
	int i;
	
	genl_unregister_mc_group(&ipoe_nl_family, &ipoe_nl_mcg);
	genl_unregister_family(&ipoe_nl_family);

	dev_remove_pack(&ip_packet_type);
	dev_remove_pack(&arp_packet_type);

	flush_work(&ipoe_queue_work);
	skb_queue_purge(&ipoe_queue);

	del_timer(&ipoe_timer_u);

	down(&ipoe_wlock);
	up(&ipoe_wlock);

	for (i = 0; i < HASH_BITS; i++)
		rcu_assign_pointer(ipoe_list[i].next, &ipoe_list[i]);
	
	rcu_barrier();

	while (!list_empty(&ipoe_list2)) {
		ses = list_entry(ipoe_list2.next, typeof(*ses), entry2);
		list_del(&ses->entry2);
	
		if (ses->link_dev)
			dev_put(ses->link_dev);
	
		unregister_netdev(ses->dev);
	}

	while (!list_empty(&ipoe_networks)) {
		n = list_entry(ipoe_networks.next, typeof(*n), entry);
		list_del(&n->entry);
		kfree(n);
	}

	while (!list_empty(&ipoe_list2_u)) {
		e = list_entry(ipoe_list2_u.next, typeof(*e), entry2);
		list_del(&e->entry2);
		kfree(e);
	}
}

module_init(ipoe_init);
module_exit(ipoe_fini);
MODULE_LICENSE("GPL");
