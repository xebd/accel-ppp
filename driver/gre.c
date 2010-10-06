#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <net/protocol.h>

#include "gre.h"


struct gre_protocol *gre_proto[GREPROTO_MAX] ____cacheline_aligned_in_smp;
static DEFINE_RWLOCK(gre_proto_lock);

int gre_add_protocol(struct gre_protocol *proto, u8 version)
{
	int ret;

	if (version >= GREPROTO_MAX)
		return -1;
	
	write_lock_bh(&gre_proto_lock);
	if (gre_proto[version]) {
		ret = -1;
	} else {
		gre_proto[version]=proto;
		ret = 0;
	}
	write_unlock_bh(&gre_proto_lock);

	return ret;
}
int gre_del_protocol(struct gre_protocol *proto, u8 version)
{
	int ret;

	if (version >= GREPROTO_MAX)
		return -1;

	write_lock_bh(&gre_proto_lock);
	if (gre_proto[version] == proto) {
		gre_proto[version] = NULL;
		ret = 0;
	} else {
		ret = -1;
	}
	write_unlock_bh(&gre_proto_lock);

	return ret;
}
static int gre_rcv(struct sk_buff *skb)
{
	u8 ver;
	int ret;

	if (!pskb_may_pull(skb, 12))
		goto drop_nolock;

	ver = skb->data[1]&0x7f;
	if (ver >= GREPROTO_MAX)
		goto drop_nolock;
	
	read_lock(&gre_proto_lock);
	if (!gre_proto[ver] || !gre_proto[ver]->handler)
		goto drop;

	ret = gre_proto[ver]->handler(skb);
	read_unlock(&gre_proto_lock);

	return ret;

drop:
	read_unlock(&gre_proto_lock);
drop_nolock:
	kfree_skb(skb);
	return NET_RX_DROP;
}
static void gre_err(struct sk_buff *skb, u32 info)
{
	u8 ver;

	printk("err\n");

	if (!pskb_may_pull(skb, 12))
		goto drop_nolock;

	ver=skb->data[1];
	if (ver>=GREPROTO_MAX)
		goto drop_nolock;
		
	read_lock(&gre_proto_lock);
	if (!gre_proto[ver] || !gre_proto[ver]->err_handler)
		goto drop;

	gre_proto[ver]->err_handler(skb,info);
	read_unlock(&gre_proto_lock);

	return;

drop:
	read_unlock(&gre_proto_lock);
drop_nolock:
	kfree_skb(skb);
}


static struct net_protocol net_gre_protocol = {
	.handler	= gre_rcv,
	.err_handler	=	gre_err,
//	.netns_ok=1,
};

static int __init gre_init(void)
{
	printk(KERN_INFO "GRE over IPv4 demultiplexor driver");
	
	if (inet_add_protocol(&net_gre_protocol, IPPROTO_GRE) < 0) {
		printk(KERN_INFO "gre: can't add protocol\n");
		return -EAGAIN;
	}

	return 0;
}

static void __exit gre_exit(void)
{
	inet_del_protocol(&net_gre_protocol, IPPROTO_GRE);
}

module_init(gre_init);
module_exit(gre_exit);

MODULE_DESCRIPTION("GRE over IPv4 demultiplexor driver");
MODULE_AUTHOR("Kozlov D. (xeb@mail.ru)");
MODULE_LICENSE("GPL");
EXPORT_SYMBOL_GPL(gre_add_protocol);
EXPORT_SYMBOL_GPL(gre_del_protocol);

