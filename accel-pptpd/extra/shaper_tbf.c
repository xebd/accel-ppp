#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netlink/netlink.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/sch/tbf.h>
#include <netlink/route/class.h>
#include <netlink/route/cls/u32.h>
#include <netlink/route/cls/police.h>

#include "triton.h"
#include "events.h"
#include "radius.h"
#include "log.h"
#include "ppp.h"
#include "memdebug.h"

#define TIME_UNITS_PER_SEC 1000000

static int conf_verbose = 0;
static int conf_attr_down = 11; //Filter-Id
static int conf_attr_up = 11; //Filter-Id
static double conf_burst_factor = 0.1;
static int conf_latency = 50;
static int conf_mpu = 0;

static double tick_in_usec = 1;
static double clock_factor = 1;

struct shaper_pd_t
{
	struct ppp_pd_t pd;
	int down_speed;
	int up_speed;
};

static void *pd_key;

static unsigned tc_time2tick(unsigned time)
{
	return time*tick_in_usec;
}

/*static unsigned tc_tick2time(unsigned tick)
{
	return tick/tick_in_usec;
}*/

static unsigned tc_calc_xmittime(unsigned rate, unsigned size)
{
	return tc_time2tick(TIME_UNITS_PER_SEC*((double)size/rate));
}

/*static unsigned tc_calc_xmitsize(unsigned rate, unsigned ticks)
{
	return ((double)rate*tc_tick2time(ticks))/TIME_UNITS_PER_SEC;
}*/

static void tc_calc_rtable(struct tc_ratespec *r, uint32_t *rtab, int cell_log, unsigned mtu)
{
	int i;
	unsigned sz;
	unsigned bps = r->rate;
	unsigned mpu = r->mpu;

	if (mtu == 0)
		mtu = 2047;

	if (cell_log <= 0) {
		cell_log = 0;
		while ((mtu >> cell_log) > 255)
			cell_log++;
	}

	for (i=0; i<256; i++) {
		//sz = tc_adjust_size((i + 1) << cell_log, mpu, linklayer);
		sz = (i + 1) << cell_log;
		if (sz < mpu)
			sz = mpu;
		rtab[i] = tc_calc_xmittime(bps, sz);
	}

	r->cell_align=-1; // Due to the sz calc
	r->cell_log=cell_log;
}

static int install_tbf(struct nl_handle *h, int ifindex, int speed)
{
	struct tc_tbf_qopt opt;
	struct nl_msg *msg;
	struct nl_msg *pmsg = NULL;
	uint32_t rtab[RTNL_TC_RTABLE_SIZE];
	double rate = speed*1000/8;
	double bucket = rate*conf_burst_factor;

	struct tcmsg tchdr = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = ifindex,
		.tcm_handle = 0x00010000,
		.tcm_parent = TC_H_ROOT,
	};

	memset(&opt, 0, sizeof(opt));

	opt.rate.rate = rate;
	opt.rate.mpu = conf_mpu;
	opt.limit = rate*conf_latency/1000 + bucket;
	opt.buffer = tc_calc_xmittime(rate, bucket);

	tc_calc_rtable(&opt.rate, rtab, 0, 0);

	msg = nlmsg_alloc();
	if (!msg)
		goto out_err;

	NLA_PUT(msg, TCA_TBF_PARMS, sizeof(opt), &opt);
	NLA_PUT(msg, TCA_TBF_RTAB, sizeof(rtab), rtab);

	pmsg = nlmsg_alloc_simple(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE);
	if (!pmsg)
		goto out_err;

	if (nlmsg_append(pmsg, &tchdr, sizeof(tchdr), NLMSG_ALIGNTO) < 0)
		goto out_err;

	NLA_PUT_STRING(pmsg, TCA_KIND, "tbf");
	nla_put_nested(pmsg, TCA_OPTIONS, msg);

	if (nl_send_auto_complete(h, pmsg) < 0)
		goto out_err;
	
	if (nl_wait_for_ack(h) < 0)
		goto out_err;

	nlmsg_free(msg);
	nlmsg_free(pmsg);

	return 0;

out_err:
nla_put_failure:

	if (msg)
		nlmsg_free(msg);

	if (pmsg)
		nlmsg_free(pmsg);

	log_ppp_error("tbf: error occured, tbf is not installed\n");

	return -1;
}

static int install_ingress(struct nl_handle *h, int ifindex)
{
	struct nl_msg *pmsg;

	struct tcmsg tchdr = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = ifindex,
		.tcm_handle = 0xffff0000,
		.tcm_parent = TC_H_INGRESS,
	};

	pmsg = nlmsg_alloc_simple(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_REPLACE);
	if (!pmsg)
		goto out_err;

	if (nlmsg_append(pmsg, &tchdr, sizeof(tchdr), NLMSG_ALIGNTO) < 0)
		goto out_err;

	NLA_PUT_STRING(pmsg, TCA_KIND, "ingress");

	if (nl_send_auto_complete(h, pmsg) < 0)
		goto out_err;
	
	if (nl_wait_for_ack(h) < 0)
		goto out_err;

	nlmsg_free(pmsg);

	return 0;

out_err:
nla_put_failure:

	if (pmsg)
		nlmsg_free(pmsg);

	log_ppp_error("tbf: error occured, ingress is not installed\n");

	return -1;
}

static int install_filter(struct nl_handle *h, int ifindex, int speed)
{
	double rate = speed*1000/8;
	double bucket = rate*conf_burst_factor;
	struct nl_msg *pmsg = NULL;
	struct nl_msg *msg = NULL;
	struct nl_msg *msg1 = NULL;
	struct nl_msg *msg2 = NULL;
	struct nl_msg *msg3 = NULL;
	uint32_t rtab[RTNL_TC_RTABLE_SIZE];
	
	struct tcmsg tchdr = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = ifindex,
		.tcm_handle = 1,
		.tcm_parent = 0xffff0000,
		.tcm_info = TC_H_MAKE(10 << 16, ntohs(ETH_P_IP)),
	};

	struct sel_t {
		struct tc_u32_sel sel;
		struct tc_u32_key key;
	} sel = {
		.sel.nkeys = 1,
		.sel.flags = TC_U32_TERMINAL,
		.key.off = 12,
	};
	
	struct tc_police police = {
		.action = TC_POLICE_SHOT,
		.rate.rate = rate,
		.rate.mpu = conf_mpu,
		.limit = rate*conf_latency/1000 + bucket,
		.burst = tc_calc_xmittime(rate, bucket),
	};

	tc_calc_rtable(&police.rate, rtab, 0, 0);

	pmsg = nlmsg_alloc_simple(RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_REPLACE);
	if (!pmsg)
		goto out_err;
	
	msg = nlmsg_alloc();
	if (!msg)
		goto out_err;

	msg1 = nlmsg_alloc();
	if (!msg1)
		goto out_err;

	msg2 = nlmsg_alloc();
	if (!msg2)
		goto out_err;

	msg3 = nlmsg_alloc();
	if (!msg3)
		goto out_err;

	if (nlmsg_append(pmsg, &tchdr, sizeof(tchdr), NLMSG_ALIGNTO) < 0)
		goto out_err;

	NLA_PUT_STRING(pmsg, TCA_KIND, "u32");

	NLA_PUT_U32(msg, TCA_U32_CLASSID, 1);
	NLA_PUT(msg, TCA_U32_SEL, sizeof(sel), &sel);

	NLA_PUT_STRING(msg3, TCA_ACT_KIND, "police");

	NLA_PUT(msg2, TCA_POLICE_TBF, sizeof(police), &police);
	NLA_PUT(msg2, TCA_POLICE_RATE, sizeof(rtab), rtab);

	if (nla_put_nested(msg3, TCA_ACT_OPTIONS, msg2) < 0)
		goto out_err;

	if (nla_put_nested(msg1, 1, msg3) < 0)
		goto out_err;

	if (nla_put_nested(msg, TCA_U32_ACT, msg1))
		goto out_err;

	if (nla_put_nested(pmsg, TCA_OPTIONS, msg))
		goto out_err;
	
	if (nl_send_auto_complete(h, pmsg) < 0)
		goto out_err;
	
	if (nl_wait_for_ack(h) < 0)
		goto out_err;

	nlmsg_free(pmsg);
	nlmsg_free(msg);
	nlmsg_free(msg1);
	nlmsg_free(msg2);
	nlmsg_free(msg3);

	return 0;

out_err:
nla_put_failure:

	if (pmsg)
		nlmsg_free(pmsg);

	if (msg)
		nlmsg_free(msg);

	if (msg1)
		nlmsg_free(msg1);

	if (msg2)
		nlmsg_free(msg1);

	if (msg3)
		nlmsg_free(msg1);

	log_ppp_error("tbf: error occured, filter is not installed\n");

	return -1;
}


static int install_shaper(const char *ifname, int down_speed, int up_speed)
{
	struct nl_handle *h;
	struct ifreq ifr;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_ppp_error("tbf: ioctl(SIOCGIFINDEX)", strerror(errno));
		return -1;
	}

	h = nl_handle_alloc();
	if (!h) {
		log_ppp_error("tbf: nl_handle_alloc failed\n");
		return -1;
	}

	err = nl_connect(h, NETLINK_ROUTE);
	if (err < 0) {
		log_ppp_error("tbf: nl_connect: %s", strerror(errno));
		goto out;
	}

	if (down_speed)
		if (install_tbf(h, ifr.ifr_ifindex, down_speed))
			return -1;
	
	if (up_speed) {
		if (install_ingress(h, ifr.ifr_ifindex))
			return -1;
		if (install_filter(h, ifr.ifr_ifindex, up_speed))
			return -1;
	}

	nl_close(h);
out:
	nl_handle_destroy(h);

	return 0;
}

static struct shaper_pd_t *find_pd(struct ppp_t *ppp, int create)
{
	struct ppp_pd_t *pd;
	struct shaper_pd_t *spd;

	list_for_each_entry(pd, &ppp->pd_list, entry) {
		if (pd->key == &pd_key) {
			spd = container_of(pd, typeof(*spd), pd);
			return spd;
		}
	}

	if (create) {
		spd = _malloc(sizeof(*spd));
		if (!spd) {
			log_emerg("tbf: out of memory\n");
			return NULL;
		}

		memset(spd, 0, sizeof(*spd));
		list_add_tail(&spd->pd.entry, &ppp->pd_list);
		spd->pd.key = &pd_key;
		return spd;
	}

	return NULL;
}

static int remove_shaper(const char *ifname)
{
	struct nl_handle *h;
	struct ifreq ifr;
	struct nl_msg *pmsg;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_ppp_error("tbf: ioctl(SIOCGIFINDEX)", strerror(errno));
		return -1;
	}

	struct tcmsg tchdr1 = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = ifr.ifr_ifindex,
		.tcm_handle = 0x00010000,
		.tcm_parent = TC_H_ROOT,
	};

	struct tcmsg tchdr2 = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = ifr.ifr_ifindex,
		.tcm_handle = 0xffff0000,
		.tcm_parent = TC_H_INGRESS,
	};

	h = nl_handle_alloc();
	if (!h) {
		log_ppp_error("tbf: nl_handle_alloc failed\n");
		return -1;
	}

	err = nl_connect(h, NETLINK_ROUTE);
	if (err < 0) {
		log_ppp_error("tbf: nl_connect: %s", strerror(errno));
		nl_handle_destroy(h);
		return -1;
	}

	pmsg = nlmsg_alloc_simple(RTM_DELQDISC, NLM_F_CREATE | NLM_F_REPLACE);
	if (!pmsg)
		goto out_err;

	if (nlmsg_append(pmsg, &tchdr1, sizeof(tchdr1), NLMSG_ALIGNTO) < 0)
		goto out_err;

	if (nl_send_auto_complete(h, pmsg) < 0)
		goto out_err;
	
	if (nl_wait_for_ack(h) < 0)
		goto out_err;

	nlmsg_free(pmsg);

	pmsg = nlmsg_alloc_simple(RTM_DELQDISC, NLM_F_CREATE | NLM_F_REPLACE);
	if (!pmsg)
		goto out_err;

	if (nlmsg_append(pmsg, &tchdr2, sizeof(tchdr2), NLMSG_ALIGNTO) < 0)
		goto out_err;

	if (nl_send_auto_complete(h, pmsg) < 0)
		goto out_err;
	
	if (nl_wait_for_ack(h) < 0)
		goto out_err;

	nlmsg_free(pmsg);

	nl_close(h);
	nl_handle_destroy(h);
	return 0;

out_err:
	log_ppp_error("tbf: failed to remove shaper\n");

	if (pmsg)
		nlmsg_free(pmsg);

	nl_close(h);
	nl_handle_destroy(h);

	return -1;
}

static int parse_attr(struct rad_attr_t *attr)
{
	if (attr->attr->type == ATTR_TYPE_STRING)
		return atoi(attr->val.string);
	else if (attr->attr->type == ATTR_TYPE_INTEGER)
		return attr->val.integer;
	
	return 0;
}

static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct rad_attr_t *attr;
	int down_speed = 0;
	int up_speed = 0;
	struct shaper_pd_t *pd = find_pd(ev->ppp, 1);

	if (!pd)
		return;

	list_for_each_entry(attr, &ev->reply->attrs, entry) {
		if (attr->attr->id == conf_attr_down)
			down_speed = parse_attr(attr);
		if (attr->attr->id == conf_attr_up)
			up_speed = parse_attr(attr);
	}

	if (down_speed > 0 && up_speed > 0) {
		pd->down_speed = down_speed;
		pd->up_speed = up_speed;
		if (!install_shaper(ev->ppp->ifname, down_speed, up_speed)) {
			if (conf_verbose)
				log_ppp_info("tbf: installed shaper %i/%i (Kbit)\n", down_speed, up_speed);
		}
	}
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	struct rad_attr_t *attr;
	int down_speed = 0;
	int up_speed = 0;
	struct shaper_pd_t *pd = find_pd(ev->ppp, 1);

	if (!pd) {
		ev->res = -1;
		return;
	}

	list_for_each_entry(attr, &ev->request->attrs, entry) {
		if (attr->attr->id == conf_attr_down)
			down_speed = parse_attr(attr);
		if (attr->attr->id == conf_attr_up)
			up_speed = parse_attr(attr);
	}
	
	if (pd->down_speed != down_speed || pd->up_speed != up_speed) {
		pd->down_speed = down_speed;
		pd->up_speed = up_speed;

		if (remove_shaper(ev->ppp->ifname)) {
			ev->res = -1;
			return;
		}
		
		if (down_speed > 0 || up_speed > 0) {
			if (install_shaper(ev->ppp->ifname, down_speed, up_speed)) {
				ev->res= -1;
				return;
			} else {
				if (conf_verbose)
					log_ppp_info("tbf: changed shaper %i/%i (Kbit)\n", down_speed, up_speed);
			}
		} else {
			if (conf_verbose)
				log_ppp_info("tbf: removed shaper\n");
		}
	}
}

static void ev_ctrl_finished(struct ppp_t *ppp)
{
	struct shaper_pd_t *pd = find_pd(ppp, 0);

	if (pd) {
		list_del(&pd->pd.entry);
		_free(pd);
	}
}

static int clock_init(void)
{
	FILE *fp;
	uint32_t clock_res;
	uint32_t t2us;
	uint32_t us2t;

	fp = fopen("/proc/net/psched", "r");

	if (!fp) {
		log_emerg("tbf: failed to open /proc/net/psched: %s\n", strerror(errno));
		return -1;
	}

	if (fscanf(fp, "%08x%08x%08x", &t2us, &us2t, &clock_res) != 3) {
		log_emerg("tbf: failed to parse /proc/net/psched\n");
		fclose(fp);
		return -1;
	}

	fclose(fp);

	/* compatibility hack: for old iproute binaries (ignoring
	* the kernel clock resolution) the kernel advertises a
	* tick multiplier of 1000 in case of nano-second resolution,
	* which really is 1. */
	if (clock_res == 1000000000)
		t2us = us2t;

	clock_factor  = (double)clock_res / TIME_UNITS_PER_SEC;
	tick_in_usec = (double)t2us / us2t * clock_factor;

	return 0;
}

static int parse_attr_opt(const char *opt)
{
	struct rad_dict_attr_t *attr;

	attr = rad_dict_find_attr(opt);
	if (attr)
		return attr->id;

	return atoi(opt);
}

static void __init init(void)
{
	const char *opt;

	if (clock_init())
		return;

	opt = conf_get_opt("tbf", "attr");
	if (opt) {
		conf_attr_down = parse_attr_opt(opt);
		conf_attr_up = parse_attr_opt(opt);
	}

	opt = conf_get_opt("tbf", "attr-down");
	if (opt)
		conf_attr_down = parse_attr_opt(opt);
	
	opt = conf_get_opt("tbf", "attr-up");
	if (opt)
		conf_attr_up = parse_attr_opt(opt);
	
	opt = conf_get_opt("tbf", "burst-factor");
	if (opt)
		conf_burst_factor = strtod(opt, NULL);
	
	opt = conf_get_opt("tbf", "latency");
	if (opt && atoi(opt) > 0)
		conf_latency = atoi(opt);

	opt = conf_get_opt("tbf", "mpu");
	if (opt && atoi(opt) >= 0)
		conf_mpu = atoi(opt);

	opt = conf_get_opt("tbf", "verbose");
	if (opt && atoi(opt) > 0)
		conf_verbose = 1;

	if (conf_attr_up <= 0 || conf_attr_down <= 0) {
		log_emerg("tbf: incorrect attribute(s), tbf disabled...\n");
		return;
	}

	triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
	triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
}

