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
#include <linux/rbtree.h>
#include <linux/version.h>
#include <net/genetlink.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "ipoe.h"

#define HASH(addr) (((__force u32)addr^((__force u32)addr>>4))&0xF)
#define HASH_SIZE 16

#define NEED_UPDATE 1
#define UPDATE 2

#ifndef DEFINE_SEMAPHORE
#define DEFINE_SEMAPHORE(name) struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)
#endif

struct ipoe_session
{
	struct rb_node node;

	__be32 addr;
	__be32 peer_addr;
	__u8 hwaddr[ETH_ALEN];

	struct net_device *dev;
	struct net_device *link_dev;

	/*struct tasklet_struct tasklet;
	int tasklet_pending;

	struct u64_status_sync rsync;
	u64 rx_packets;
	u64 rx_bytes;
	struct sk_buff_head rq;

	struct u64_status_sync tsync;
	u64 tx_packets;
	u64 tx_bytes;
	struct sk_buff_head tq;*/

	int drop:1;
};

struct rb_root ipoe_rbt = RB_ROOT;
static atomic_t ipoe_rlock;
static atomic_t ipoe_update;
static DEFINE_SEMAPHORE(ipoe_wlock);

struct sk_buff_head ipoe_rq;
struct tasklet_struct ipoe_rq_tasklet;

static struct ipoe_session *ipoe_lookup(__be32 addr, struct rb_node **r_parent, struct rb_node ***r_p);
static int ipoe_do_nat(struct sk_buff *skb, __be32 new_addr, int to_peer);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static const struct net_device_ops ipoe_netdev_ops;
#endif

static struct genl_family ipoe_nl_family;

static void ipoe_recv_rq(unsigned long arg)
{
	struct sk_buff *skb;
	int upd;
	struct iphdr *iph;
	int noff;
	struct ipoe_session *ses;

	atomic_inc(&ipoe_rlock);
	if (atomic_read(&ipoe_update) == UPDATE) {
		atomic_dec(&ipoe_rlock);
		tasklet_schedule(&ipoe_rq_tasklet);
		return;
	}

	while ((skb = skb_dequeue(&ipoe_rq))) {
		noff = skb_network_offset(skb);
	
		iph = ip_hdr(skb);

		ses = ipoe_lookup(iph->saddr, NULL, NULL);
		if (!ses)
			goto drop;
		
		if (ses->drop)
			goto drop;
		
		if (ses->addr && ipoe_do_nat(skb, ses->addr, 0))
			goto drop;
		
		skb->dev = ses->dev;
		//skb->skb_iif = ses->link_dev->ifindex;

		netif_rx(skb);

		if (atomic_read(&ipoe_update) == NEED_UPDATE)
			break;

		continue;

	drop:
		kfree_skb(skb);
	}

	upd = atomic_read(&ipoe_update);
	if (atomic_dec_and_test(&ipoe_rlock) && upd == NEED_UPDATE)
		atomic_set(&ipoe_update, UPDATE);
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
	/*struct arphdr *arp;
	unsigned char *arp_ptr;
	__be32 tip;*/
	int noff;

	noff = skb_network_offset(skb);

	if (skb->protocol == htons(ETH_P_IP)) {
		if (!pskb_may_pull(skb, sizeof(*iph) + noff))
			goto drop;
		
		iph = ip_hdr(skb);

		//pr_info("ipoe: xmit %08x %08x\n", iph->saddr, iph->daddr);
		
		/*u64_stats_update_begin(&ses->tsync);
		ses->tx_packets++;
		ses->tx_bytes += skb->len;
		u64_stats_update_end(&ses->tsync);*/

		if (iph->daddr == ses->addr) {
			if (ipoe_do_nat(skb, ses->peer_addr, 1))
				goto drop;

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
		
	skb->dev = ses->link_dev;
	skb->skb_iif = dev->ifindex;
	dev_queue_xmit(skb);

	return NETDEV_TX_OK;
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
	int upd;
	struct sk_buff *skb1;

	//pr_info("ipoe: recv arp\n");
	
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;
	
	noff = skb_network_offset(skb);

	if (!pskb_may_pull(skb, arp_hdr_len(dev) + noff))
		goto drop;
	
	arp = arp_hdr(skb);
	arp_ptr = (unsigned char *)(arp + 1);

	if (arp->ar_pro != htons(ETH_P_IP))
		goto drop;
	
	memcpy(&sip, arp_ptr + ETH_ALEN, 4);

	//pr_info("ipoe: recv arp %08x\n", sip);

	atomic_inc(&ipoe_rlock);
	upd = atomic_read(&ipoe_update);
	if (upd)
		goto drop_unlock;

	ses = ipoe_lookup(sip, NULL, NULL);
	if (!ses)
		goto drop_unlock;
	
	if (ses->drop || ses->addr)
		goto drop_unlock;
	
	if (skb->dev == ses->dev)
		goto drop_unlock;
	
	/*if (ses->addr && arp->ar_op == htons(ARPOP_REPLY)) {
		if (skb_cloned(skb) &&
				!skb_clone_writable(skb, arp_hdr_len(dev) + noff) &&
				pskb_expand_head(skb, 0, 0, GFP_ATOMIC))
			goto drop_unlock;

		arp = arp_hdr(skb);
		arp_ptr = (unsigned char *)(arp + 1);
		memcpy(arp_ptr + ETH_ALEN, &ses->addr, 4);
	}*/

	skb1 = skb_clone(skb, GFP_ATOMIC);
	if (!skb1)
		goto drop_unlock;

	skb1->dev = ses->dev;
	skb1->skb_iif = ses->dev->ifindex;

	netif_rx(skb1);
	
drop_unlock:
	upd = atomic_read(&ipoe_update);
	if (atomic_dec_and_test(&ipoe_rlock) && upd == NEED_UPDATE)
		atomic_set(&ipoe_update, UPDATE);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int ipoe_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct ipoe_session *ses = NULL;
	struct iphdr *iph;
	int upd;
	int noff;
	struct sk_buff *skb1;

	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;
	
	noff = skb_network_offset(skb);

	if (!pskb_may_pull(skb, sizeof(*iph) + noff))
		goto drop;
	
	iph = ip_hdr(skb);

	//pr_info("ipoe: recv %08x %08x\n", iph->saddr, iph->daddr);

	atomic_inc(&ipoe_rlock);
	upd = atomic_read(&ipoe_update);
	if (upd == NEED_UPDATE) {
		skb_queue_tail(&ipoe_rq, skb);

		if (atomic_dec_and_test(&ipoe_rlock))
			atomic_set(&ipoe_update, UPDATE);

		return NET_RX_SUCCESS;
	} else if (upd == UPDATE) {
		skb_queue_tail(&ipoe_rq, skb);
		atomic_dec(&ipoe_rlock);
		return NET_RX_SUCCESS;
	}

	ses = ipoe_lookup(iph->saddr, NULL, NULL);
	if (!ses)
		goto drop_unlock;
	
	if (ses->drop)
		goto drop_unlock;
	
	if (skb->dev == ses->dev)
		goto drop_unlock;
	
	if (ses->addr && ipoe_do_nat(skb, ses->addr, 0))
		goto drop_unlock;
	
	skb1 = skb_clone(skb, GFP_ATOMIC);
	if (!skb1)
		goto drop_unlock;

	skb1->dev = ses->dev;
	skb1->skb_iif = ses->dev->ifindex;

	netif_rx(skb1);
	
drop_unlock:
	upd = atomic_read(&ipoe_update);
	if (atomic_dec_and_test(&ipoe_rlock) && upd == NEED_UPDATE)
		atomic_set(&ipoe_update, UPDATE);
	
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

static int ipoe_hard_header(struct sk_buff *skb, struct net_device *dev,
			       unsigned short type, const void *daddr,
			       const void *saddr, unsigned len)
{
	const struct ipoe_session *ses = netdev_priv(dev);

	return dev_hard_header(skb, ses->link_dev, type, daddr,
			       saddr, len);
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
	dev->destructor = free_netdev;

	dev->type = ARPHRD_ETHER;
	dev->hard_header_len = 0;
	dev->mtu = ETH_DATA_LEN;
	dev->flags = 0;//IFF_NOARP | IFF_BROADCAST;
	dev->iflink = 0;
	dev->addr_len = ETH_ALEN;
	dev->features  = 0;//|= NETIF_F_NETNS_LOCAL;
	dev->header_ops		= &ipoe_hard_header_ops,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
#endif
}

static int ipoe_create(__be32 peer_addr, __be32 addr, const char *link_ifname, const __u8 *hwaddr)
{
	struct ipoe_session *ses;
	struct net_device *dev, *link_dev;
	char name[IFNAMSIZ];
	int r = 0;
	struct rb_node **p;
	struct rb_node *parent;
		
	link_dev = dev_get_by_name(&init_net, link_ifname);
	if (!link_dev)
		return -EINVAL;

	sprintf(name, "%s.ipoe%%d", link_ifname);

	dev = alloc_netdev(sizeof(*ses), name, ipoe_netdev_setup);
	if (dev == NULL)
		goto failed;

	dev_net_set(dev, &init_net);

	r = dev_alloc_name(dev, name);
	if (r < 0)
		goto failed_free;
	
	ses = netdev_priv(dev);
	ses->dev = dev;
	ses->addr = addr;
	ses->peer_addr = peer_addr;
	ses->link_dev = link_dev;
	memcpy(ses->hwaddr, hwaddr, ETH_ALEN);
	dev->features = link_dev->features;
	memcpy(dev->dev_addr, link_dev->dev_addr, ETH_ALEN);
	memcpy(dev->broadcast, link_dev->broadcast, ETH_ALEN);
	if (addr)
		dev->flags = IFF_NOARP;
	else
		dev->flags = IFF_BROADCAST;

	rtnl_lock();
	r = register_netdevice(dev);
	rtnl_unlock();
	if (r < 0)
		goto failed_free;

	down(&ipoe_wlock);
	atomic_inc(&ipoe_rlock);
	atomic_set(&ipoe_update, NEED_UPDATE);
	if (atomic_dec_and_test(&ipoe_rlock))
		atomic_set(&ipoe_update, UPDATE);
	else {
		while (atomic_read(&ipoe_update) != UPDATE)
			schedule_timeout_uninterruptible(1);
	}

	if (ipoe_lookup(peer_addr, &parent, &p))
		r = -EEXIST;
	else {
		rb_link_node(&ses->node, parent, p);
		rb_insert_color(&ses->node, &ipoe_rbt);
	}

	up(&ipoe_wlock);

	atomic_set(&ipoe_update, 0);

	tasklet_schedule(&ipoe_rq_tasklet);

	return r;

failed_free:
	free_netdev(dev);
failed:
	dev_put(link_dev);
	return r;
}

static struct ipoe_session *ipoe_lookup(__be32 addr, struct rb_node **r_parent, struct rb_node ***r_p)
{
	struct ipoe_session *ses;
	struct rb_node **p = &ipoe_rbt.rb_node;
	struct rb_node *parent = NULL;

	while (*p) {
		parent = *p;
		ses = rb_entry(parent, typeof(*ses), node);
		if (addr < ses->peer_addr)
			p = &(*p)->rb_left;
		else if (addr > ses->peer_addr)
			p = &(*p)->rb_right;
		else
			return ses;
	}

	if (r_parent) {
		*r_parent = parent;
		*r_p = p;
	}

	return NULL;
}



static int ipoe_delete(__be32 addr)
{
	struct ipoe_session *ses;

	down(&ipoe_wlock);

	atomic_inc(&ipoe_rlock);
	atomic_set(&ipoe_update, NEED_UPDATE);
	if (atomic_dec_and_test(&ipoe_rlock))
		atomic_set(&ipoe_update, UPDATE);
	else {
		while (atomic_read(&ipoe_update) != UPDATE)
			schedule_timeout_uninterruptible(1);
	}

	ses = ipoe_lookup(addr, NULL, NULL);
	if (ses)
		rb_erase(&ses->node, &ipoe_rbt);

	up(&ipoe_wlock);

	atomic_set(&ipoe_update, 0);

	tasklet_schedule(&ipoe_rq_tasklet);

	if (!ses)
		return -EINVAL;

	dev_put(ses->link_dev);
	unregister_netdev(ses->dev);
	
	return 0;
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
	__be32 peer_addr, addr  = 0;
	int ret = 0;
	char ifname[IFNAMSIZ];
	__u8 hwaddr[ETH_ALEN];
	//struct net *net = genl_info_net(info);

	if (!info->attrs[IPOE_ATTR_PEER_ADDR] || !info->attrs[IPOE_ATTR_IFNAME]) {
		ret = -EINVAL;
		goto out;
	}

	peer_addr = nla_get_be32(info->attrs[IPOE_ATTR_PEER_ADDR]);
	if (info->attrs[IPOE_ATTR_ADDR])
		addr = nla_get_be32(info->attrs[IPOE_ATTR_ADDR]);
	nla_strlcpy(ifname, info->attrs[IPOE_ATTR_IFNAME], IFNAMSIZ - 1);
	if (info->attrs[IPOE_ATTR_HWADDR])
		nla_memcpy(hwaddr, info->attrs[IPOE_ATTR_HWADDR], ETH_ALEN);
	else
		memset(hwaddr, 0, sizeof(hwaddr));

	pr_info("ipoe: create %08x %08x %s\n", peer_addr, addr, ifname);
	
	ret = ipoe_create(peer_addr, addr, ifname, hwaddr);

out:
	return ret;
}

static int ipoe_nl_cmd_delete(struct sk_buff *skb, struct genl_info *info)
{
	__be32 addr;
	//struct net *net = genl_info_net(info);


	if (!info->attrs[IPOE_ATTR_PEER_ADDR])
		return -EINVAL;
	
	addr = nla_get_u32(info->attrs[IPOE_ATTR_PEER_ADDR]);

	pr_info("ipoe: delete %08x\n", addr);
	
	return ipoe_delete(addr);
}

static struct nla_policy ipoe_nl_policy[IPOE_ATTR_MAX + 1] = {
	[IPOE_ATTR_NONE]		    = { .type = NLA_UNSPEC,                     },
	[IPOE_ATTR_ADDR]	      = { .type = NLA_U32,                        },
	[IPOE_ATTR_PEER_ADDR]	= { .type = NLA_U32,                          },
	[IPOE_ATTR_IFNAME]	    = { .type = NLA_STRING, .len = IFNAMSIZ - 1 },
	[IPOE_ATTR_HWADDR]	    = { .type = NLA_U64                         },
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
};

static struct genl_family ipoe_nl_family = {
	.id		= GENL_ID_GENERATE,
	.name		= IPOE_GENL_NAME,
	.version	= IPOE_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= IPOE_ATTR_MAX,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static const struct net_device_ops ipoe_netdev_ops = {
	.ndo_start_xmit	= ipoe_xmit,
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
	int err;

	printk("IPoE session driver v0.1\n");

	/*err = register_pernet_device(&ipoe_net_ops);
	if (err < 0)
		return err;*/

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
#endif
	if (err < 0) {
		printk(KERN_INFO "ipoe: can't register netlink interface\n");
		goto out;
	}

	tasklet_init(&ipoe_rq_tasklet, ipoe_recv_rq, 0);

	skb_queue_head_init(&ipoe_rq);

	dev_add_pack(&ip_packet_type);
	dev_add_pack(&arp_packet_type);

	return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
out_unreg:
#endif
	genl_unregister_family(&ipoe_nl_family);
out:
	return err;
}

static void __exit ipoe_fini(void)
{
	dev_remove_pack(&ip_packet_type);
	dev_remove_pack(&arp_packet_type);
	genl_unregister_family(&ipoe_nl_family);
}

module_init(ipoe_init);
module_exit(ipoe_fini);
MODULE_LICENSE("GPL");
