#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/mroute.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/semaphore.h>
#include <linux/netfilter_ipv4.h>
#include <linux/u64_stats_sync.h>
#include <linux/version.h>

#include <net/genetlink.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/flow.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/pkt_sched.h>

#include "ipoe.h"

#define BEGIN_UPDATE 1
#define UPDATE 2
#define END_UPDATE 3

#define HASH_BITS 0xff

#define IPOE_MAGIC 0x55aa
#define IPOE_MAGIC2 0x67f8bc32

#define IPOE_QUEUE_LEN 100
#define IPOE_RATE_U 3000 //3s
#define IPOE_TIMEOUT_U 30 //5s

#define IPOE_NLMSG_SIZE (NLMSG_DEFAULT_SIZE - GENL_HDRLEN - 128)

#ifndef DEFINE_SEMAPHORE
#define DEFINE_SEMAPHORE(name) struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
struct ipoe_stats {
	struct u64_stats_sync sync;
	u64 packets;
	u64 bytes;
};
#endif

struct ipoe_session {
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

struct ipoe_network {
	struct rcu_head rcu_head;
	struct list_head entry;

	__be32 addr;
	__be32 mask;
};

struct ipoe_iface {
	struct rcu_head rcu_head;
	struct list_head entry;

	int ifindex;
};

struct ipoe_entry_u {
	struct rcu_head rcu_head;
	struct list_head entry1;
	struct list_head entry2;

	__be32 addr;
	unsigned long tstamp;
};

struct vlan_dev {
	unsigned int magic;
	int ifindex;
	struct rcu_head rcu_head;
	struct list_head entry;

	spinlock_t lock;
	unsigned long vid[4096/8/sizeof(long)];
};

struct vlan_notify {
	struct list_head entry;
	int ifindex;
	int vid;
};

static struct list_head ipoe_list[HASH_BITS + 1];
static struct list_head ipoe_list1_u[HASH_BITS + 1];
static struct list_head ipoe_excl_list[HASH_BITS + 1];
static LIST_HEAD(ipoe_list2);
static LIST_HEAD(ipoe_list2_u);
static DEFINE_SEMAPHORE(ipoe_wlock);
static LIST_HEAD(ipoe_networks);
static LIST_HEAD(ipoe_interfaces);
static struct work_struct ipoe_queue_work;
static struct sk_buff_head ipoe_queue;

static LIST_HEAD(vlan_devices);
static LIST_HEAD(vlan_notifies);
static DEFINE_SPINLOCK(vlan_lock);
static struct work_struct vlan_notify_work;

static void ipoe_start_queue_work(unsigned long);
static DEFINE_TIMER(ipoe_timer_u, ipoe_start_queue_work, 0, 0);

static struct ipoe_session *ipoe_lookup(__be32 addr);
static int ipoe_do_nat(struct sk_buff *skb, __be32 new_addr, int to_peer);
static void ipoe_queue_u(struct sk_buff *skb, __be32 addr);
static int ipoe_lookup1_u(__be32 addr, unsigned long *ts);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static const struct net_device_ops ipoe_netdev_ops;
#endif

static struct genl_family ipoe_nl_family;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static struct genl_multicast_group ipoe_nl_mcg;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
#define u64_stats_fetch_begin_bh u64_stats_fetch_begin_irq
#define u64_stats_fetch_retry_bh u64_stats_fetch_retry_irq
#endif

static inline int hash_addr(__be32 addr)
{
#ifdef __LITTLE_ENDIAN
	return ((addr >> 24) ^ (addr >> 16)) & HASH_BITS;
#else
	return (addr  ^ (addr >> 8)) & HASH_BITS;
#endif
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
static void ipoe_update_stats(struct sk_buff *skb, struct ipoe_stats *st, int corr)
{
	u64_stats_update_begin(&st->sync);
	st->packets++;
	st->bytes += skb->len - corr;
	u64_stats_update_end(&st->sync);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
static void ipoe_kfree_rcu(struct rcu_head *head)
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
		if ((ntohl(addr) & n->mask) == n->addr) {
			r = 1;
			break;
		}
	}

	rcu_read_unlock();

	return r;
}

static int ipoe_check_exclude(__be32 addr)
{
	struct ipoe_network *n;
	struct list_head *ht;
	int r = 0;

	ht = &ipoe_excl_list[hash_addr(addr)];

	rcu_read_lock();

	list_for_each_entry_rcu(n, ht, entry) {
		if (addr  == n->addr) {
			r = 1;
			break;
		}
	}

	rcu_read_unlock();

	return r;
}

static int ipoe_check_interface(int ifindex)
{
	struct ipoe_iface *i;
	int r = 0;

	rcu_read_lock();

	list_for_each_entry_rcu(i, &ipoe_interfaces, entry) {
		if (i->ifindex == ifindex) {
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

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,38)
	struct flowi fl4;
#else
	struct flowi4 fl4;
#endif

	memset(&fl4, 0, sizeof(fl4));
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,38)
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
	struct dst_entry *dst;
	/*struct arphdr *arp;
	unsigned char *arp_ptr;
	__be32 tip;*/
	int noff;
	unsigned char *cb_ptr;

	if (!ses->peer_addr)
		goto drop;

	skb->tc_verd = SET_TC_NCLS(0);

	noff = skb_network_offset(skb);

	if (skb->protocol == htons(ETH_P_IP)) {
		if (!pskb_may_pull(skb, sizeof(*iph) + noff))
			goto drop;

		iph = ip_hdr(skb);

		//pr_info("ipoe: xmit %08x %08x\n", iph->saddr, iph->daddr);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
		ipoe_update_stats(skb, this_cpu_ptr(ses->tx_stats), ETH_HLEN);
#else
		stats->tx_packets++;
		stats->tx_bytes += skb->len - ETH_HLEN;
#endif


#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,30)
		dst = skb_dst(skb);
#else
		dst = skb->dst;
#endif
		if (dst && dst->dev != skb->dev) {
			skb->dev = dst->dev;
			dev_queue_xmit(skb);
			return NETDEV_TX_OK;
		}

		//pr_info("ipoe: xmit1 %08x %08x\n", iph->saddr, iph->daddr);
		if (iph->daddr == ses->addr) {
			if (skb_shared(skb)) {
				skb1 = skb_clone(skb, GFP_ATOMIC);
				if (!skb1)
					goto drop;
				dev_kfree_skb(skb);
				skb = skb1;
			}

			if (ipoe_do_nat(skb, ses->peer_addr, 1))
				goto drop;
		}

		if (!ses->link_dev) {
			iph = ip_hdr(skb);

			ip_send_check(iph);

			if (ipoe_route4(skb))
				goto drop;

			pskb_pull(skb, ETH_HLEN);
			skb_reset_network_header(skb);

			cb_ptr = skb->cb + sizeof(skb->cb) - 2;
			*(__u16 *)cb_ptr = IPOE_MAGIC;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
			skb->skb_iif = dev->ifindex;
#else
			skb->iif = dev->ifindex;
#endif

			//pr_info("ipoe: xmit2 %08x %08x %p %p\n", iph->saddr, iph->daddr, dev, skb->dev);
			nf_reset(skb);
			secpath_reset(skb);
			skb->vlan_tci = 0;
			skb_set_queue_mapping(skb, 0);

			ip_local_out(skb);

			return NETDEV_TX_OK;
		} else {
			eth = (struct ethhdr *)skb->data;

			memcpy(eth->h_dest, ses->hwaddr, ETH_ALEN);
			memcpy(eth->h_source, ses->link_dev->dev_addr, ETH_ALEN);
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
		cb_ptr = skb->cb + sizeof(skb->cb) - 2;
		*(__u16 *)cb_ptr = IPOE_MAGIC;
		skb->dev = ses->link_dev;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
		skb->skb_iif = dev->ifindex;
#else
		skb->iif = dev->ifindex;
#endif
		dev_queue_xmit(skb);

		return NETDEV_TX_OK;
	}
drop:
	stats->tx_dropped++;
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
					header = genlmsg_put(report_skb, 0, ipoe_nl_mcg.id, &ipoe_nl_family, 0, IPOE_REP_PKT);
#else
					header = genlmsg_put(report_skb, 0, ipoe_nl_family.mcgrp_offset, &ipoe_nl_family, 0, IPOE_REP_PKT);
#endif
			}

			if (report_skb) {
				ns = nla_nest_start(report_skb, id++);
				if (!ns)
					goto nl_err;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
				if (nla_put_u32(report_skb, IPOE_ATTR_IFINDEX, skb->dev ? skb->dev->ifindex : skb->skb_iif))
#else
				if (nla_put_u32(report_skb, IPOE_ATTR_IFINDEX, skb->dev ? skb->dev->ifindex : skb->iif))
#endif
					goto nl_err;

				if (nla_put(report_skb, IPOE_ATTR_ETH_HDR, sizeof(*eth), eth))
					goto nl_err;

				if (nla_put(report_skb, IPOE_ATTR_IP_HDR, sizeof(*iph), iph))
					goto nl_err;

				if (nla_nest_end(report_skb, ns) >= IPOE_NLMSG_SIZE) {
					genlmsg_end(report_skb, header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
					genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
#else
					genlmsg_multicast(&ipoe_nl_family, report_skb, 0, 0, GFP_KERNEL);
#endif
					report_skb = NULL;
					id = 1;
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
			call_rcu(&e->rcu_head, ipoe_kfree_rcu);
#endif
		}

		synchronize_rcu();
	} while (skb_queue_len(&ipoe_queue));

	if (report_skb) {
		genlmsg_end(report_skb, header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
		genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
#else
		genlmsg_multicast(&ipoe_nl_family, report_skb, 0, 0, GFP_KERNEL);
#endif
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static unsigned int ipt_in_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#else
static unsigned int ipt_in_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#endif
{
	struct ipoe_session *ses = NULL;
	struct iphdr *iph;
	struct ethhdr *eth;
	int noff;
	struct sk_buff *skb1;
	unsigned char *cb_ptr;
	struct net_device_stats *stats;
	int ret = NF_DROP;

	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	cb_ptr = skb->cb + sizeof(skb->cb) - 2;

	if (*(__u16 *)cb_ptr == IPOE_MAGIC)
		return NF_ACCEPT;

	noff = skb_network_offset(skb);

	if (!pskb_may_pull(skb, sizeof(*iph) + noff))
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	if (!iph->saddr)
		return NF_ACCEPT;

	//pr_info("ipoe: recv %08x %08x\n", iph->saddr, iph->daddr);

	ses = ipoe_lookup(iph->saddr);

	if (!ses) {
		if (ipoe_check_exclude(iph->saddr))
			return NF_ACCEPT;

		if (!ipoe_check_network(iph->saddr))
			return NF_ACCEPT;

		if (!ipoe_check_interface(in->ifindex))
			return NF_ACCEPT;

		ipoe_queue_u(skb, iph->saddr);
		return NF_DROP;
	}

	stats = &ses->dev->stats;

	if (ses->link_dev) {
		eth = eth_hdr(skb);
		if (memcmp(eth->h_source, ses->hwaddr, ETH_ALEN)) {
			stats->rx_dropped++;
			goto out;
		}
	}

	if (skb->dev == ses->dev) {
		ret = NF_ACCEPT;
		goto out;
	}

	if (ses->addr && ipoe_check_network(iph->daddr)) {
		ret = NF_ACCEPT;
		goto out;
	}

	skb1 = skb_clone(skb, GFP_ATOMIC);
	if (!skb1) {
		stats->rx_dropped++;
		goto out;
	}

	if (ses->addr > 1 && ipoe_do_nat(skb1, ses->addr, 0)) {
		kfree_skb(skb1);
		goto out;
	}

	skb1->dev = ses->dev;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	skb1->skb_iif = skb->dev->ifindex;
#else
	skb1->iif = skb->dev->ifindex;
#endif

	cb_ptr = skb1->cb + sizeof(skb1->cb) - 2;
	*(__u16 *)cb_ptr = IPOE_MAGIC;

	//skb1->tc_verd = SET_TC_NCLS(0);

	netif_rx(skb1);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	ipoe_update_stats(skb, this_cpu_ptr(ses->rx_stats), 0);
#else
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
#endif

out:
	atomic_dec(&ses->refs);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static unsigned int ipt_out_hook(unsigned int hook, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#else
static unsigned int ipt_out_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *skb))
#endif
{
	int noff, iif;
	struct iphdr *iph;
	struct ipoe_session *ses;
	unsigned char *cb_ptr;

	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	cb_ptr = skb->cb + sizeof(skb->cb) - 2;
	if (*(__u16 *)cb_ptr == IPOE_MAGIC)
		return NF_ACCEPT;

	noff = skb_network_offset(skb);

	if (!pskb_may_pull(skb, sizeof(*iph) + noff))
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	if (ipoe_check_exclude(iph->daddr))
		return NF_ACCEPT;

	if (!ipoe_check_network(iph->daddr))
		return NF_ACCEPT;

	if (ipoe_check_network(iph->saddr))
		return NF_ACCEPT;

	ses = ipoe_lookup(iph->daddr);
	if (!ses)
		return NF_ACCEPT;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
	iif = skb->skb_iif;
#else
	iif = skb->iif;
#endif

	if (iif == ses->dev->ifindex) {
		atomic_dec(&ses->refs);
		return NF_ACCEPT;
	}

	skb->dev = ses->dev;
	atomic_dec(&ses->refs);

	return NF_ACCEPT;
}

static int vlan_pt_recv(struct sk_buff *skb, struct net_device *dev, struct packet_type *prev, struct net_device *orig_dev)
{
	struct vlan_dev *d;
	struct vlan_notify *n;
	int vid;

	if (!dev->ml_priv)
		goto out;

	if (!vlan_tx_tag_present(skb))
		goto out;

	rcu_read_lock();

	d = rcu_dereference(dev->ml_priv);
	if (!d || d->magic != IPOE_MAGIC2 || d->ifindex != dev->ifindex) {
		rcu_read_unlock();
		goto out;
	}

	vid = skb->vlan_tci & VLAN_VID_MASK;
	//pr_info("vid %i\n", vid);

	if (d->vid[vid / (8*sizeof(long))] & (1lu << (vid % (8*sizeof(long)))))
		vid = -1;
	else {
		spin_lock(&d->lock);
		d->vid[vid / (8*sizeof(long))] |= 1lu << (vid % (8*sizeof(long)));
		spin_unlock(&d->lock);
	}
	rcu_read_unlock();

	if (vid == -1)
		goto out;

	//pr_info("queue %i %i\n", dev->ifindex, vid);

	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n)
		goto out;

	n->ifindex = dev->ifindex;
	n->vid = vid;

	spin_lock(&vlan_lock);
	list_add_tail(&n->entry, &vlan_notifies);
	spin_unlock(&vlan_lock);

	schedule_work(&vlan_notify_work);

out:
	kfree_skb(skb);
	return 0;
}

static void vlan_do_notify(struct work_struct *w)
{
	struct vlan_notify *n;
	struct sk_buff *report_skb = NULL;
	void *header = NULL;
	struct nlattr *ns;
	int id = 1;
	unsigned long flags;

	//pr_info("vlan_do_notify\n");

	while (1) {
		spin_lock_irqsave(&vlan_lock, flags);
		if (list_empty(&vlan_notifies))
			n = NULL;
		else {
			n = list_first_entry(&vlan_notifies, typeof(*n), entry);
			list_del(&n->entry);
		}
		spin_unlock_irqrestore(&vlan_lock, flags);

		if (!n)
			break;

		if (!report_skb) {
			report_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
			header = genlmsg_put(report_skb, 0, ipoe_nl_mcg.id, &ipoe_nl_family, 0, IPOE_VLAN_NOTIFY);
#else
			header = genlmsg_put(report_skb, 0, ipoe_nl_family.mcgrp_offset, &ipoe_nl_family, 0, IPOE_VLAN_NOTIFY);
#endif
		}

		//pr_info("notify %i vlan %i\n", id, n->vid);

		ns = nla_nest_start(report_skb, id++);
		if (!ns)
			goto nl_err;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
		if (nla_put_u32(report_skb, IPOE_ATTR_IFINDEX, n->ifindex))
#else
		if (nla_put_u32(report_skb, IPOE_ATTR_IFINDEX, n->ifindex))
#endif
			goto nl_err;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
		if (nla_put_u32(report_skb, IPOE_ATTR_ADDR, n->vid))
#else
		if (nla_put_u32(report_skb, IPOE_ATTR_ADDR, n->vid))
#endif
			goto nl_err;

		if (nla_nest_end(report_skb, ns) >= IPOE_NLMSG_SIZE) {
			genlmsg_end(report_skb, header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
			genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
#else
			genlmsg_multicast(&ipoe_nl_family, report_skb, 0, 0, GFP_KERNEL);
#endif
			report_skb = NULL;
			id = 1;
		}

		kfree(n);
		continue;

nl_err:
		nlmsg_free(report_skb);
		report_skb = NULL;
	}

	if (report_skb) {
		genlmsg_end(report_skb, header);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
		genlmsg_multicast(report_skb, 0, ipoe_nl_mcg.id, GFP_KERNEL);
#else
		genlmsg_multicast(&ipoe_nl_family, report_skb, 0, 0, GFP_KERNEL);
#endif
	}
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
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
	dev->header_ops	= &ipoe_hard_header_ops;
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
	struct in_device *in_dev;

	if (link_ifname) {
		link_dev = dev_get_by_name(&init_net, link_ifname);
		if (!link_dev)
			return -EINVAL;
	}

	sprintf(name, "ipoe%%d");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
	dev = alloc_netdev(sizeof(*ses), name, NET_NAME_UNKNOWN, ipoe_netdev_setup);
#else
	dev = alloc_netdev(sizeof(*ses), name, ipoe_netdev_setup);
#endif
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

	in_dev = __in_dev_get_rtnl(dev);
	if (in_dev) {
		if (addr == 1)
			IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 0;
		else
			IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 1;
	}

	dev->tx_queue_len = 100;

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq,
#else
	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
#endif
			  &ipoe_nl_family, 0, IPOE_CMD_NOOP);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto err_out;
	}

	genlmsg_end(msg, hdr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	return genlmsg_unicast(msg, info->snd_pid);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	hdr = genlmsg_put(msg, info->snd_pid, info->snd_seq,
#else
	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
#endif
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
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
	return genlmsg_unicast(msg, info->snd_pid);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_pid);
#else
	return genlmsg_unicast(genl_info_net(info), msg, info->snd_portid);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	rtnl_lock();
	dev = __dev_get_by_index(&init_net, ifindex);
#else
	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, ifindex);
#endif
	if (!dev || dev->header_ops != &ipoe_hard_header_ops)
		r = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	rtnl_unlock();
#else
	rcu_read_unlock();
#endif

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
	struct in_device *in_dev;
	struct ipoe_session *ses, *ses1;
	int ifindex;
	__be32 peer_addr;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	down(&ipoe_wlock);

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	rtnl_lock();
	dev = __dev_get_by_index(&init_net, ifindex);
#else
	rcu_read_lock();
	dev = dev_get_by_index_rcu(&init_net, ifindex);
#endif
	if (!dev || dev->header_ops != &ipoe_hard_header_ops)
		r = 1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	rtnl_unlock();
#else
	rcu_read_unlock();
#endif

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
		if (ses->addr && !ses->link_dev)
			dev->flags |= IFF_NOARP;
		else
			dev->flags &= ~IFF_NOARP;

		in_dev = __in_dev_get_rtnl(dev);
		if (in_dev) {
			if (ses->addr == 1)
				IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 0;
			else
				IPV4_DEVCONF(in_dev->cnf, RP_FILTER) = 1;
		}
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

	if (nla_put_u32(skb, IPOE_ATTR_IFINDEX, ses->dev->ifindex) ||
	    nla_put_u32(skb, IPOE_ATTR_PEER_ADDR, ses->peer_addr) ||
	    nla_put_u32(skb, IPOE_ATTR_ADDR, ses->addr))
		goto nla_put_failure;

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
		if (fill_info(skb, ses, NETLINK_CB(cb->skb).pid, cb->nlh->nlmsg_seq) < 0)
#else
		if (fill_info(skb, ses, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq) < 0)
#endif
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
	n->addr = ntohl(n->addr) & n->mask;
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
			call_rcu(&n->rcu_head, ipoe_kfree_rcu);
#endif
		}
	}
	rcu_read_unlock();

	synchronize_rcu();

	return 0;
}

static int ipoe_nl_cmd_add_exclude(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_network *n;
	struct list_head *ht;

	if (!info->attrs[IPOE_ATTR_ADDR])
		return -EINVAL;

	n = kmalloc(sizeof(*n), GFP_KERNEL);
	if (!n)
		return -ENOMEM;

	n->addr = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);

	ht = &ipoe_excl_list[hash_addr(n->addr)];

	down(&ipoe_wlock);
	list_add_tail_rcu(&n->entry, ht);
	up(&ipoe_wlock);

	return 0;
}

static void clean_excl_list(void)
{
	struct ipoe_network *n;
	struct list_head *ht;
	int i;

	down(&ipoe_wlock);
	rcu_read_lock();
	for (i = 0; i <= HASH_BITS; i++) {
		ht = &ipoe_excl_list[i];
		list_for_each_entry_rcu(n, ht, entry) {
			list_del_rcu(&n->entry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
			kfree_rcu(n, rcu_head);
#else
			call_rcu(&n->rcu_head, ipoe_kfree_rcu);
#endif
		}
	}
	rcu_read_unlock();
	up(&ipoe_wlock);
}

static int ipoe_nl_cmd_del_exclude(struct sk_buff *skb, struct genl_info *info)
{
	struct list_head *ht;
	struct ipoe_network *n;
	u32 addr;

	if (!info->attrs[IPOE_ATTR_ADDR])
		return -EINVAL;

	addr = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);
	if (!addr) {
		clean_excl_list();
		return 0;
	}

	ht = &ipoe_excl_list[hash_addr(addr)];

	down(&ipoe_wlock);
	rcu_read_lock();
	list_for_each_entry_rcu(n, ht, entry) {
		if (n->addr == addr) {
			list_del_rcu(&n->entry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
			kfree_rcu(n, rcu_head);
#else
			call_rcu(&n->rcu_head, ipoe_kfree_rcu);
#endif
		}
	}
	rcu_read_unlock();
	up(&ipoe_wlock);

	synchronize_rcu();

	return 0;
}

static int ipoe_nl_cmd_add_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_iface *i;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	i = kmalloc(sizeof(*i), GFP_KERNEL);
	if (!i)
		return -ENOMEM;

	i->ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	down(&ipoe_wlock);
	list_add_tail_rcu(&i->entry, &ipoe_interfaces);
	up(&ipoe_wlock);

	return 0;
}

static int ipoe_nl_cmd_del_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct ipoe_iface *i;
	int ifindex;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

	rcu_read_lock();
	list_for_each_entry_rcu(i, &ipoe_interfaces, entry) {
		if (ifindex == -1 || ifindex == i->ifindex) {
			//pr_info("del net %08x/%08x\n", n->addr, n->mask);
			list_del_rcu(&i->entry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
			kfree_rcu(i, rcu_head);
#else
			call_rcu(&i->rcu_head, ipoe_kfree_rcu);
#endif
		}
	}
	rcu_read_unlock();

	synchronize_rcu();

	return 0;
}

static int ipoe_nl_cmd_add_vlan_mon(struct sk_buff *skb, struct genl_info *info)
{
	struct vlan_dev *d;
	struct net_device *dev;
	int ifindex, i;

	if (!info->attrs[IPOE_ATTR_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	rtnl_lock();
	dev = __dev_get_by_index(&init_net, ifindex);
	rtnl_unlock();
#else
	dev = dev_get_by_index(&init_net, ifindex);
#endif

	if (!dev)
		return -ENODEV;

	down(&ipoe_wlock);
	if (dev->ml_priv) {
		up(&ipoe_wlock);
		dev_put(dev);
		return -EBUSY;
	}

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d) {
		up(&ipoe_wlock);
		dev_put(dev);
		return -ENOMEM;
	}

	d->magic = IPOE_MAGIC2;
	d->ifindex = ifindex;
	spin_lock_init(&d->lock);

	if (info->attrs[IPOE_ATTR_VLAN_MASK]) {
		memcpy(d->vid, nla_data(info->attrs[IPOE_ATTR_VLAN_MASK]), min((int)nla_len(info->attrs[IPOE_ATTR_VLAN_MASK]), (int)sizeof(d->vid)));

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
		if (dev->features & NETIF_F_HW_VLAN_FILTER) {
			rtnl_lock();
			for (i = 1; i < 4096; i++) {
				if (!(d->vid[i / (8*sizeof(long))] & (1lu << (i % (8*sizeof(long))))))
					dev->netdev_ops->ndo_vlan_rx_add_vid(dev, i);
			}
			rtnl_unlock();
		}
#else
		if (dev->features & NETIF_F_HW_VLAN_CTAG_FILTER) {
			rtnl_lock();
			for (i = 1; i < 4096; i++) {
				if (!(d->vid[i / (8*sizeof(long))] & (1lu << (i % (8*sizeof(long))))))
					dev->netdev_ops->ndo_vlan_rx_add_vid(dev, htons(ETH_P_8021Q), i);
			}
			rtnl_unlock();
		}
#endif
	}

	rcu_assign_pointer(dev->ml_priv, d);

	list_add_tail_rcu(&d->entry, &vlan_devices);
	up(&ipoe_wlock);

	dev_put(dev);

	return 0;
}

static int ipoe_nl_cmd_add_vlan_mon_vid(struct sk_buff *skb, struct genl_info *info)
{
	struct vlan_dev *d;
	int ifindex, vid;
	struct net_device *dev;
	unsigned long flags;

	if (!info->attrs[IPOE_ATTR_IFINDEX] || !info->attrs[IPOE_ATTR_ADDR])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);
	vid = nla_get_u32(info->attrs[IPOE_ATTR_ADDR]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	rtnl_lock();
	dev = __dev_get_by_index(&init_net, ifindex);
	rtnl_unlock();
#else
	dev = dev_get_by_index(&init_net, ifindex);
#endif

	if (!dev)
		return -ENODEV;

	down(&ipoe_wlock);

	if (!dev->ml_priv) {
		up(&ipoe_wlock);
		dev_put(dev);
		return -EINVAL;
	}

	d = dev->ml_priv;

	spin_lock_irqsave(&d->lock, flags);
	d->vid[vid / (8*sizeof(long))] &= ~(1lu << (vid % (8*sizeof(long))));
	spin_unlock_irqrestore(&d->lock, flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	if (dev->features & NETIF_F_HW_VLAN_FILTER)
		dev->netdev_ops->ndo_vlan_rx_add_vid(dev, vid);
#else
	if (dev->features & NETIF_F_HW_VLAN_CTAG_FILTER)
		dev->netdev_ops->ndo_vlan_rx_add_vid(dev, htons(ETH_P_8021Q), vid);
#endif

	up(&ipoe_wlock);

	dev_put(dev);

	return 0;
}

static int ipoe_nl_cmd_del_vlan_mon(struct sk_buff *skb, struct genl_info *info)
{
	struct vlan_dev *d;
	struct vlan_notify *vn;
	int ifindex;
	unsigned long flags;
	struct list_head *pos, *n;
	struct net_device *dev;

	if (info->attrs[IPOE_ATTR_IFINDEX])
		ifindex = nla_get_u32(info->attrs[IPOE_ATTR_IFINDEX]);
	else
		ifindex = -1;

	down(&ipoe_wlock);
	list_for_each_entry(d, &vlan_devices, entry) {
		if (ifindex == -1 || d->ifindex == ifindex) {
			//pr_info("del net %08x/%08x\n", n->addr, n->mask);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
			rtnl_lock();
			dev = __dev_get_by_index(&init_net, d->ifindex);
			rtnl_unlock();
#else
			dev = dev_get_by_index(&init_net, d->ifindex);
#endif

			if (dev) {
				if (dev->ml_priv == d)
					rcu_assign_pointer(dev->ml_priv, NULL);
				dev_put(dev);
			}

			list_del_rcu(&d->entry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
			kfree_rcu(d, rcu_head);
#else
			call_rcu(&d->rcu_head, ipoe_kfree_rcu);
#endif
		}
	}
	up(&ipoe_wlock);

	spin_lock_irqsave(&vlan_lock, flags);
	list_for_each_safe(pos, n, &vlan_notifies) {
		vn = list_entry(pos, typeof(*vn), entry);
		if (ifindex == -1 || vn->ifindex == ifindex) {
			list_del(&vn->entry);
			kfree(vn);
		}
	}
	spin_unlock_irqrestore(&vlan_lock, flags);

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
	[IPOE_ATTR_VLAN_MASK]	  = { .type = NLA_BINARY, .len = 4096/8       },
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
	{
		.cmd = IPOE_CMD_ADD_IF,
		.doit = ipoe_nl_cmd_add_interface,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_DEL_IF,
		.doit = ipoe_nl_cmd_del_interface,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_ADD_VLAN_MON,
		.doit = ipoe_nl_cmd_add_vlan_mon,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_ADD_VLAN_MON_VID,
		.doit = ipoe_nl_cmd_add_vlan_mon_vid,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_DEL_VLAN_MON,
		.doit = ipoe_nl_cmd_del_vlan_mon,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_ADD_EXCLUDE,
		.doit = ipoe_nl_cmd_add_exclude,
		.policy = ipoe_nl_policy,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = IPOE_CMD_DEL_EXCLUDE,
		.doit = ipoe_nl_cmd_del_exclude,
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static struct genl_multicast_group ipoe_nl_mcg = {
	.name = IPOE_GENL_MCG_PKT,
};
#else
static struct genl_multicast_group ipoe_nl_mcgs[] = {
	{ .name = IPOE_GENL_MCG_PKT, }
};
#endif

static struct nf_hook_ops ipt_ops[] __read_mostly = {
	{
		.hook = ipt_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
		.owner = THIS_MODULE,
	},
	{
		.hook = ipt_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
		.owner = THIS_MODULE,
	},
	{
		.hook = ipt_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
		.owner = THIS_MODULE,
	},
};

static struct packet_type vlan_pt __read_mostly = {
	.type = __constant_htons(ETH_P_ALL),
	.func = vlan_pt_recv,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
static const struct net_device_ops ipoe_netdev_ops = {
	.ndo_start_xmit	= ipoe_xmit,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
	.ndo_get_stats64 = ipoe_stats64,
#endif
};
#endif

/*static struct pernet_operations ipoe_net_ops = {
	.init = ipoe_init_net,
	.exit = ipoe_exit_net,
	.id   = &ipoe_net_id,
	.size = sizeof(struct ipoe_net),
};*/

static int __init ipoe_init(void)
{
	int err, i;

	printk("IPoE session driver v1.9.0\n");

	/*err = register_pernet_device(&ipoe_net_ops);
	if (err < 0)
		return err;*/
	for (i = 0; i <= HASH_BITS; i++) {
		INIT_LIST_HEAD(&ipoe_list[i]);
		INIT_LIST_HEAD(&ipoe_list1_u[i]);
		INIT_LIST_HEAD(&ipoe_excl_list[i]);
	}

	skb_queue_head_init(&ipoe_queue);
	INIT_WORK(&ipoe_queue_work, ipoe_process_queue);

	INIT_WORK(&vlan_notify_work, vlan_do_notify);

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
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	err = genl_register_family_with_ops(&ipoe_nl_family, ipoe_nl_ops, ARRAY_SIZE(ipoe_nl_ops));
#else
	err = genl_register_family_with_ops_groups(&ipoe_nl_family, ipoe_nl_ops, ipoe_nl_mcgs);
#endif
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink interface\n");
		goto out;
	}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	err = genl_register_mc_group(&ipoe_nl_family, &ipoe_nl_mcg);
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink multicast group\n");
		goto out_unreg;
	}
#endif

	err = nf_register_hooks(ipt_ops, ARRAY_SIZE(ipt_ops));
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register nf hooks\n");
		goto out_unreg;
	}

	dev_add_pack(&vlan_pt);

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
	struct vlan_dev *d;
	struct vlan_notify *vn;
	struct net_device *dev;
	int i;

	dev_remove_pack(&vlan_pt);
	nf_unregister_hooks(ipt_ops, ARRAY_SIZE(ipt_ops));

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
	genl_unregister_mc_group(&ipoe_nl_family, &ipoe_nl_mcg);
#endif
	genl_unregister_family(&ipoe_nl_family);

	flush_work(&ipoe_queue_work);
	skb_queue_purge(&ipoe_queue);

	del_timer(&ipoe_timer_u);

	down(&ipoe_wlock);
	up(&ipoe_wlock);

	for (i = 0; i <= HASH_BITS; i++)
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

	while (!list_empty(&vlan_devices)) {
		d = list_first_entry(&vlan_devices, typeof(*d), entry);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
		rtnl_lock();
		dev = __dev_get_by_index(&init_net, d->ifindex);
		rtnl_unlock();
#else
		dev = dev_get_by_index(&init_net, d->ifindex);
#endif
		if (dev)
			rcu_assign_pointer(dev->ml_priv, NULL);
		list_del(&d->entry);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,0,0)
		kfree_rcu(d, rcu_head);
#else
		call_rcu(&d->rcu_head, ipoe_kfree_rcu);
#endif
	}

	while (!list_empty(&vlan_notifies)) {
		vn = list_first_entry(&vlan_notifies, typeof(*vn), entry);
		list_del(&vn->entry);
		kfree(vn);
	}

	clean_excl_list();

	synchronize_rcu();
}

module_init(ipoe_init);
module_exit(ipoe_fini);
MODULE_LICENSE("GPL");
