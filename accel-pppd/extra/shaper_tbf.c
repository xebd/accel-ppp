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
#include <pthread.h>

#include "netlink/netlink.h"
#include "netlink/socket.h"
#include "netlink/msg.h"

#include "triton.h"
#include "events.h"
#include "log.h"
#include "ppp.h"
#include "cli.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "memdebug.h"

#define RTNL_TC_RTABLE_SIZE 256
#define TIME_UNITS_PER_SEC 1000000

#define ATTR_UP 1
#define ATTR_DOWN 2

static int conf_verbose = 0;
#ifdef RADIUS
static int conf_attr_down = 11; //Filter-Id
static int conf_attr_up = 11; //Filter-Id
static int conf_vendor = 0;
#endif
static double conf_down_burst_factor = 0.1;
static double conf_up_burst_factor = 1;
static int conf_latency = 50;
static int conf_mpu = 0;

static int temp_down_speed;
static int temp_up_speed;

static pthread_rwlock_t shaper_lock = PTHREAD_RWLOCK_INITIALIZER;
static LIST_HEAD(shaper_list);
static pthread_mutex_t nl_lock = PTHREAD_MUTEX_INITIALIZER;

static double tick_in_usec = 1;
static double clock_factor = 1;

struct time_range_pd_t;
struct shaper_pd_t
{
	struct list_head entry;
	struct ppp_t *ppp;
	struct ap_private pd;
	int temp_down_speed;
	int temp_up_speed;
	int down_speed;
	int up_speed;
	struct list_head tr_list;
	struct time_range_pd_t *cur_tr;
};

struct time_range_pd_t
{
	struct list_head entry;
	int id;
	int down_speed;
	int down_burst;
	int up_speed;
	int up_burst;
};

struct time_range_t
{
	struct list_head entry;
	int id;
	struct triton_timer_t begin;
	struct triton_timer_t end;
};

static void *pd_key;

static LIST_HEAD(time_range_list);
static int time_range_id = 0;

static void shaper_ctx_close(struct triton_context_t *);
static struct triton_context_t shaper_ctx = {
	.close = shaper_ctx_close,
	.before_switch = log_switch,
};

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

static int install_tbf(struct nl_sock *h, int ifindex, int speed, int burst)
{
	struct tc_tbf_qopt opt;
	struct nl_msg *msg;
	struct nl_msg *pmsg = NULL;
	uint32_t rtab[RTNL_TC_RTABLE_SIZE];
	double rate = speed * 1000 / 8;
	double bucket = burst ? burst : rate * conf_down_burst_factor;

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

static int install_ingress(struct nl_sock *h, int ifindex)
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

static int install_filter(struct nl_sock *h, int ifindex, int speed, int burst)
{
	//double rate = speed*1000/8;
	//double bucket = rate*conf_burst_factor;
	double rate = speed * 1000 / 8;
	double bucket = burst ? burst : rate * conf_up_burst_factor;
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


static int install_shaper(const char *ifname, int down_speed, int down_burst, int up_speed, int up_burst)
{
	struct nl_sock *h;
	struct ifreq ifr;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_ppp_error("tbf: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		return -1;
	}

	pthread_mutex_lock(&nl_lock);
	h = nl_socket_alloc();
	pthread_mutex_unlock(&nl_lock);

	if (!h) {
		log_ppp_error("tbf: nl_socket_alloc failed\n");
		return -1;
	}

	err = nl_connect(h, NETLINK_ROUTE);
	if (err < 0) {
		log_ppp_error("tbf: nl_connect: %s\n", strerror(errno));
		goto out;
	}

	if (down_speed)
		if (install_tbf(h, ifr.ifr_ifindex, down_speed, down_burst))
			return -1;
	
	if (up_speed) {
		if (install_ingress(h, ifr.ifr_ifindex))
			return -1;
		if (install_filter(h, ifr.ifr_ifindex, up_speed, up_burst))
			return -1;
	}

	nl_close(h);
out:

	pthread_mutex_lock(&nl_lock);
	nl_socket_free(h);
	pthread_mutex_unlock(&nl_lock);

	return 0;
}

static struct shaper_pd_t *find_pd(struct ppp_t *ppp, int create)
{
	struct ap_private *pd;
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
		spd->ppp = ppp;
		list_add_tail(&spd->pd.entry, &ppp->pd_list);
		spd->pd.key = &pd_key;
		INIT_LIST_HEAD(&spd->tr_list);

		pthread_rwlock_wrlock(&shaper_lock);
		list_add_tail(&spd->entry, &shaper_list);
		pthread_rwlock_unlock(&shaper_lock);
		return spd;
	}

	return NULL;
}

static int remove_shaper(const char *ifname)
{
	struct nl_sock *h;
	struct ifreq ifr;
	struct nl_msg *pmsg;
	int err;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_ppp_error("tbf: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
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

	pthread_mutex_lock(&nl_lock);
	h = nl_socket_alloc();
	pthread_mutex_unlock(&nl_lock);

	if (!h) {
		log_ppp_error("tbf: nl_socket_alloc failed\n");
		return -1;
	}

	err = nl_connect(h, NETLINK_ROUTE);
	if (err < 0) {
		log_ppp_error("tbf: nl_connect: %s\n", strerror(errno));
		goto out_err1;
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

	pthread_mutex_lock(&nl_lock);
	nl_socket_free(h);
	pthread_mutex_unlock(&nl_lock);

	return 0;

out_err:
	if (pmsg)
		nlmsg_free(pmsg);

	nl_close(h);

out_err1:
	pthread_mutex_lock(&nl_lock);
	nl_socket_free(h);
	pthread_mutex_unlock(&nl_lock);

	log_ppp_error("tbf: failed to remove shaper\n");

	return -1;
}

static void parse_string(const char *str, int dir, int *speed, int *burst, int *tr_id)
{
	char *endptr;
	long int val;
	unsigned int n1, n2, n3;

	if (strstr(str, "lcp:interface-config#1=rate-limit output access-group") == str) {
		if (dir == ATTR_DOWN) {
			val = sscanf(str, "lcp:interface-config#1=rate-limit output access-group %i %u %u %u conform-action transmit exceed-action drop", tr_id, &n1, &n2, &n3);
			if (val == 4) {
				*speed = n1/1000;
				*burst = n2;
			}
		}
		return;
	} else if (strstr(str, "lcp:interface-config#1=rate-limit input access-group") == str) {
		if (dir == ATTR_UP) {
			val = sscanf(str, "lcp:interface-config#1=rate-limit input access-group %i %u %u %u conform-action transmit exceed-action drop", tr_id, &n1, &n2, &n3);
			if (val == 4) {
				*speed = n1/1000;
				*burst = n2;
			}
		}
		return;
	}	else if (strstr(str, "lcp:interface-config#1=rate-limit output") == str) {
		if (dir == ATTR_DOWN) {
			val = sscanf(str, "lcp:interface-config#1=rate-limit output %u %u %u conform-action transmit exceed-action drop", &n1, &n2, &n3);
			if (val == 3) {
				*speed = n1/1000;
				*burst = n2;
			}
		}
		return;
	}	else if (strstr(str, "lcp:interface-config#1=rate-limit input") == str) {
		if (dir == ATTR_UP) {
			val = sscanf(str, "lcp:interface-config#1=rate-limit input %u %u %u conform-action transmit exceed-action drop", &n1, &n2, &n3);
			if (val == 3) {
				*speed = n1/1000;
				*burst = n2;
			}
		}
		return;
	}

	val = strtol(str, &endptr, 10);
	if (*endptr == 0) {
		*speed = val;
		return;
	}
	if (*endptr == ',') {
		*tr_id = val;
		val = strtol(endptr + 1, &endptr, 10);
	}
	if (*endptr == 0) {
		*speed = val;
		return;
	} else {
		if (*endptr == '/' || *endptr == '\\' || *endptr == ':') {
			if (dir == ATTR_DOWN)
				*speed = val;
			else
				*speed = strtol(endptr + 1, &endptr, 10);
		}
	}
}

static struct time_range_pd_t *get_tr_pd(struct shaper_pd_t *pd, int id)
{
	struct time_range_pd_t *tr_pd;
	
	list_for_each_entry(tr_pd, &pd->tr_list, entry) {
		if (tr_pd->id == id)
			return tr_pd;
	}

	tr_pd = _malloc(sizeof(*tr_pd));
	memset(tr_pd, 0, sizeof(*tr_pd));
	tr_pd->id = id;

	if (id == time_range_id || id == 0)
		pd->cur_tr = tr_pd;
	
	list_add_tail(&tr_pd->entry, &pd->tr_list);

	return tr_pd;
}

static void clear_tr_pd(struct shaper_pd_t *pd)
{
	struct time_range_pd_t *tr_pd;

	while (!list_empty(&pd->tr_list)) {
		tr_pd = list_entry(pd->tr_list.next, typeof(*tr_pd), entry);
		list_del(&tr_pd->entry);
		_free(tr_pd);
	}
}

#ifdef RADIUS
static void parse_attr(struct rad_attr_t *attr, int dir, int *speed, int *burst, int *tr_id)
{
	if (attr->attr->type == ATTR_TYPE_STRING)
		parse_string(attr->val.string, dir, speed, burst, tr_id);
	else if (attr->attr->type == ATTR_TYPE_INTEGER)
		*speed = attr->val.integer;
}

static void check_radius_attrs(struct shaper_pd_t *pd, struct rad_packet_t *pack)
{
	struct rad_attr_t *attr;
	int down_speed, down_burst;
	int up_speed, up_burst;
	int tr_id;
	struct time_range_pd_t *tr_pd;

	list_for_each_entry(attr, &pack->attrs, entry) {
		if (attr->vendor && attr->vendor->id != conf_vendor)
			continue;
		if (!attr->vendor && conf_vendor)
			continue;
		if (attr->attr->id != conf_attr_down && attr->attr->id != conf_attr_up)
			continue;
		tr_id = 0;
		down_speed = 0;
		down_burst = 0;
		up_speed = 0;
		up_burst = 0;
		if (attr->attr->id == conf_attr_down)
			parse_attr(attr, ATTR_DOWN, &down_speed, &down_burst, &tr_id);
		if (attr->attr->id == conf_attr_up)
			parse_attr(attr, ATTR_UP, &up_speed, &up_burst, &tr_id);
		tr_pd = get_tr_pd(pd, tr_id);
		if (down_speed)
			tr_pd->down_speed = down_speed;
		if (down_burst)
			tr_pd->down_burst = down_burst;
		if (up_speed)
			tr_pd->up_speed = up_speed;
		if (up_burst)
			tr_pd->up_burst = up_burst;
	}
}

static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	int down_speed, down_burst;
	int up_speed, up_burst;
	struct shaper_pd_t *pd = find_pd(ev->ppp, 1);

	if (!pd)
		return;

	check_radius_attrs(pd, ev->reply);

	if (temp_down_speed || temp_up_speed) {
		pd->temp_down_speed = temp_down_speed;
		pd->temp_up_speed = temp_up_speed;
		pd->down_speed = temp_down_speed;
		pd->up_speed = temp_up_speed;
		down_speed = temp_down_speed;
		up_speed = temp_up_speed;
		down_burst = 0;
		up_burst = 0;
	} else {
		if (!pd->cur_tr)
			return;
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		down_speed = pd->cur_tr->down_speed;
		up_speed = pd->cur_tr->up_speed;
		down_burst = pd->cur_tr->down_burst;
		up_burst = pd->cur_tr->up_burst;
	}

	if (down_speed > 0 && up_speed > 0) {
		if (!install_shaper(ev->ppp->ses.ifname, down_speed, down_burst, up_speed, up_burst)) {
			if (conf_verbose)
				log_ppp_info2("tbf: installed shaper %i/%i (Kbit)\n", down_speed, up_speed);
		}
	}
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	struct shaper_pd_t *pd = find_pd(ev->ppp, 0);

	if (!pd) {
		ev->res = -1;
		return;
	}
	
	clear_tr_pd(pd);
	check_radius_attrs(pd, ev->request);
		
	if (pd->temp_down_speed || pd->temp_up_speed)
		return;
	
	if (!pd->cur_tr) {
		if (pd->down_speed || pd->up_speed) {
			pd->down_speed = 0;
			pd->up_speed = 0;
			if (conf_verbose)
				log_ppp_info2("tbf: removed shaper\n");
			remove_shaper(ev->ppp->ses.ifname);
		}
		return;
	}

	if (pd->down_speed != pd->cur_tr->down_speed || pd->up_speed != pd->cur_tr->up_speed) {
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;

		if (remove_shaper(ev->ppp->ses.ifname)) {
			ev->res = -1;
			return;
		}
		
		if (pd->down_speed > 0 || pd->up_speed > 0) {
			if (install_shaper(ev->ppp->ses.ifname, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst)) {
				ev->res= -1;
				return;
			} else {
				if (conf_verbose)
					log_ppp_info2("tbf: changed shaper %i/%i (Kbit)\n", pd->down_speed, pd->up_speed);
			}
		} else {
			if (conf_verbose)
				log_ppp_info2("tbf: removed shaper\n");
		}
	}
}
#endif

static void ev_shaper(struct ev_shaper_t *ev)
{
	struct shaper_pd_t *pd = find_pd(ev->ppp, 1);
	int down_speed = 0, down_burst = 0;
	int up_speed = 0, up_burst = 0;
	int tr_id = 0;
	struct time_range_pd_t *tr_pd;

	if (!pd)
		return;

	parse_string(ev->val, ATTR_DOWN, &down_speed, &down_burst, &tr_id);
	parse_string(ev->val, ATTR_UP, &up_speed, &up_burst, &tr_id);

	tr_pd = get_tr_pd(pd, tr_id);
	tr_pd->down_speed = down_speed;
	tr_pd->down_burst = down_burst;
	tr_pd->up_speed = up_speed;
	tr_pd->up_burst = up_burst;

	if (temp_down_speed || temp_up_speed) {
		pd->temp_down_speed = temp_down_speed;
		pd->temp_up_speed = temp_up_speed;
		pd->down_speed = temp_down_speed;
		pd->up_speed = temp_up_speed;
		down_speed = temp_down_speed;
		up_speed = temp_up_speed;
		down_burst = 0;
		up_burst = 0;
	} else {
		if (!pd->cur_tr)
			return;
		pd->down_speed = down_speed;
		pd->up_speed = up_speed;
	}

	if (pd->down_speed > 0 && pd->up_speed > 0) {
		if (!install_shaper(ev->ppp->ses.ifname, down_speed, down_burst, up_speed, up_burst)) {
			if (conf_verbose)
				log_ppp_info2("tbf: installed shaper %i/%i (Kbit)\n", down_speed, up_speed);
		}
	}
}

static void ev_ppp_pre_up(struct ppp_t *ppp)
{
	struct shaper_pd_t *pd = find_pd(ppp, 1);
	if (!pd)
		return;
	
	if (temp_down_speed || temp_up_speed) {
		pd->temp_down_speed = temp_down_speed;
		pd->temp_up_speed = temp_up_speed;
		pd->down_speed = temp_down_speed;
		pd->up_speed = temp_up_speed;
		if (!install_shaper(ppp->ses.ifname, temp_down_speed, 0, temp_up_speed, 0)) {
			if (conf_verbose)
				log_ppp_info2("tbf: installed shaper %i/%i (Kbit)\n", temp_down_speed, temp_up_speed);
		}
	}
}

static void ev_ctrl_finished(struct ppp_t *ppp)
{
	struct shaper_pd_t *pd = find_pd(ppp, 0);

	if (pd) {
		clear_tr_pd(pd);
		pthread_rwlock_wrlock(&shaper_lock);
		list_del(&pd->entry);
		pthread_rwlock_unlock(&shaper_lock);
		list_del(&pd->pd.entry);
		_free(pd);
	}
}

static void shaper_change_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "shaper change <interface> <value> [temp] - change shaper on specified interface, if temp is set then previous settings may be restored later by 'shaper restore'\r\n");
	cli_send(cli, "shaper change all <value> [temp] - change shaper on all interfaces, if temp is set also new interfaces will have specified shaper value\r\n");
}

static void shaper_change(struct shaper_pd_t *pd)
{
	if (pd->down_speed || pd->up_speed)
		remove_shaper(pd->ppp->ses.ifname);

	if (pd->temp_down_speed || pd->temp_up_speed) {
		pd->down_speed = pd->temp_down_speed;
		pd->up_speed = pd->temp_up_speed;
		install_shaper(pd->ppp->ses.ifname, pd->temp_down_speed, 0, pd->temp_up_speed, 0);
	} else if (pd->cur_tr->down_speed || pd->cur_tr->up_speed) {
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		install_shaper(pd->ppp->ses.ifname, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst);
	}
}

static int shaper_change_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	struct shaper_pd_t *pd;
	int down_speed = 0, up_speed = 0, down_burst = 0, up_burst = 0;
	int all = 0, temp = 0, found = 0;
	int tr_id;

	if (f_cnt < 4)
		return CLI_CMD_SYNTAX;

	parse_string(f[3], ATTR_DOWN, &down_speed, &down_burst, &tr_id);
	parse_string(f[3], ATTR_UP, &up_speed, &up_burst, &tr_id);

	if (down_speed == 0 || up_speed == 0)
		return CLI_CMD_INVAL;
	
	if (!strcmp(f[2], "all"))
		all = 1;
	
	if (f_cnt == 5) {
		if (strcmp(f[4], "temp"))
			return CLI_CMD_SYNTAX;
		else
			temp = 1;
	}

	if (all && temp) {
		temp_down_speed = down_speed;
		temp_up_speed = up_speed;
	}

	pthread_rwlock_rdlock(&shaper_lock);
	list_for_each_entry(pd, &shaper_list, entry) {
		if (all || !strcmp(f[2], pd->ppp->ses.ifname)) {
			if (temp) {
				pd->temp_down_speed = down_speed;
				pd->temp_up_speed = up_speed;
			} else {
				pd->temp_down_speed = 0;
				pd->temp_up_speed = 0;
				if (!pd->cur_tr)
					pd->cur_tr = get_tr_pd(pd, 0);
				pd->cur_tr->down_speed = down_speed;
				pd->cur_tr->down_burst = down_burst;
				pd->cur_tr->up_speed = up_speed;
				pd->cur_tr->up_burst = up_burst;
			}
			triton_context_call(pd->ppp->ses.ctrl->ctx, (triton_event_func)shaper_change, pd);
			if (!all) {
				found = 1;
				break;
			}
		}
	}
	pthread_rwlock_unlock(&shaper_lock);

	if (!all && !found)
		cli_send(cli, "not found\r\n");

	return CLI_CMD_OK;
}

static void shaper_restore_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "shaper restore <interface> - restores shaper settings on specified interface made by 'shaper change' command with 'temp' flag\r\n");
	cli_send(cli, "shaper restore all - restores shaper settings on all interfaces made by 'shaper change' command with 'temp' flag\r\n");
}

static void shaper_restore(struct shaper_pd_t *pd)
{
	remove_shaper(pd->ppp->ses.ifname);

	if (pd->cur_tr) {
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		install_shaper(pd->ppp->ses.ifname, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst);
	} else {
		pd->down_speed = 0;
		pd->up_speed = 0;
	}
}

static int shaper_restore_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	struct shaper_pd_t *pd;
	int all, found = 0;;

	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;
	
	if (strcmp(f[2], "all"))
		all = 0;
	else
		all = 1;
	
	pthread_rwlock_rdlock(&shaper_lock);
	if (all) {
		temp_down_speed = 0;
		temp_up_speed = 0;
	}
	list_for_each_entry(pd, &shaper_list, entry) {
		if (!pd->temp_down_speed)
			continue;
		if (all || !strcmp(f[2], pd->ppp->ses.ifname)) {
			pd->temp_down_speed = 0;
			pd->temp_up_speed = 0;
			triton_context_call(pd->ppp->ses.ctrl->ctx, (triton_event_func)shaper_restore, pd);
			if (!all) {
				found = 1;
				break;
			}
		}
	}
	pthread_rwlock_unlock(&shaper_lock);

	if (!all && !found)
		cli_send(cli, "not found\r\n");
	
	return CLI_CMD_OK;
}

static void print_rate(const struct ppp_t *ppp, char *buf)
{
	struct shaper_pd_t *pd = find_pd((struct ppp_t *)ppp, 0);

	if (pd && (pd->down_speed || pd->up_speed))
		sprintf(buf, "%i/%i", pd->down_speed, pd->up_speed);
	else
		*buf = 0;
}

static void shaper_ctx_close(struct triton_context_t *ctx)
{
	struct time_range_t *r;

	while (!list_empty(&time_range_list)) {
		r = list_entry(time_range_list.next, typeof(*r), entry);
		list_del(&r->entry);
		if (r->begin.tpd)
			triton_timer_del(&r->begin);
		if (r->end.tpd)
			triton_timer_del(&r->end);
		_free(r);
	}

	triton_context_unregister(ctx);
}

static void update_shaper_tr(struct shaper_pd_t *pd)
{
	struct time_range_pd_t *tr;

	if (pd->ppp->terminating)
		return;

	list_for_each_entry(tr, &pd->tr_list, entry) {
		if (tr->id != time_range_id)
			continue;
		pd->cur_tr = tr;
		break;
	}

	if (pd->temp_down_speed || pd->temp_up_speed)
		return;

	if (pd->down_speed || pd->up_speed) {
		if (pd->cur_tr && pd->down_speed == pd->cur_tr->down_speed && pd->up_speed == pd->cur_tr->up_speed)
			return;
		remove_shaper(pd->ppp->ses.ifname);
	}
	
	if (pd->cur_tr && (pd->cur_tr->down_speed || pd->cur_tr->up_speed)) {
		pd->down_speed = pd->cur_tr->down_speed;
		pd->up_speed = pd->cur_tr->up_speed;
		if (!install_shaper(pd->ppp->ses.ifname, pd->cur_tr->down_speed, pd->cur_tr->down_burst, pd->cur_tr->up_speed, pd->cur_tr->up_burst)) {
			if (conf_verbose)
				log_ppp_info2("tbf: changed shaper %i/%i (Kbit)\n", pd->cur_tr->down_speed, pd->cur_tr->up_speed);
		}
	} else
		if (conf_verbose)
			log_ppp_info2("tbf: removed shaper\n");	
}

static void time_range_begin_timer(struct triton_timer_t *t)
{
	struct time_range_t *tr = container_of(t, typeof(*tr), begin);
	struct shaper_pd_t *pd;

	time_range_id = tr->id;

	log_debug("tbf: time_range_begin_timer: id=%i\n", time_range_id);

	pthread_rwlock_rdlock(&shaper_lock);
	list_for_each_entry(pd, &shaper_list, entry)
		triton_context_call(pd->ppp->ses.ctrl->ctx, (triton_event_func)update_shaper_tr, pd);
	pthread_rwlock_unlock(&shaper_lock);
}

static void time_range_end_timer(struct triton_timer_t *t)
{
	struct shaper_pd_t *pd;

	time_range_id = 0;
	
	log_debug("tbf: time_range_end_timer\n");

	pthread_rwlock_rdlock(&shaper_lock);
	list_for_each_entry(pd, &shaper_list, entry)
		triton_context_call(pd->ppp->ses.ctrl->ctx, (triton_event_func)update_shaper_tr, pd);
	pthread_rwlock_unlock(&shaper_lock);
}

static struct time_range_t *parse_range(const char *val)
{
	char *endptr;
	int id;
	time_t t;
	struct tm begin_tm, end_tm;
	struct time_range_t *r;

	id = strtol(val, &endptr, 10);
	if (*endptr != ',')
		return NULL;
	if (id <= 0)
		return NULL;
	
	time(&t);
	localtime_r(&t, &begin_tm);
	begin_tm.tm_sec = 1;
	end_tm = begin_tm;
	end_tm.tm_sec = 0;

	endptr = strptime(endptr + 1, "%H:%M", &begin_tm);
	if (*endptr != '-')
		return NULL;
	
	endptr = strptime(endptr + 1, "%H:%M", &end_tm);
	if (*endptr)
		return NULL;
	
	r = _malloc(sizeof(*r));
	memset(r, 0, sizeof(*r));

	r->id = id;
	r->begin.expire_tv.tv_sec = mktime(&begin_tm);
	r->begin.period = 24 * 60 * 60 * 1000;
	r->begin.expire = time_range_begin_timer;
	r->end.expire_tv.tv_sec = mktime(&end_tm);
	r->end.period = 24 * 60 * 60 * 1000;
	r->end.expire = time_range_end_timer;

	return r;
}

static void load_time_ranges(void)
{
	struct conf_sect_t *s = conf_get_section("tbf");
	struct conf_option_t *opt;
	struct time_range_t *r;
	time_t ts;

	if (!s)
		return;
	
	time(&ts);

	while (!list_empty(&time_range_list)) {
		r = list_entry(time_range_list.next, typeof(*r), entry);
		list_del(&r->entry);
		if (r->begin.tpd)
			triton_timer_del(&r->begin);
		if (r->end.tpd)
			triton_timer_del(&r->end);
		_free(r);
	}

	list_for_each_entry(opt, &s->items, entry) {
		if (strcmp(opt->name, "time-range"))
			continue;
		r = parse_range(opt->val);
		if (r) {
			list_add_tail(&r->entry, &time_range_list);
			if (r->begin.expire_tv.tv_sec > r->end.expire_tv.tv_sec) {
				if (ts >= r->begin.expire_tv.tv_sec && ts <= r->end.expire_tv.tv_sec + 24*60*60)
					time_range_begin_timer(&r->begin);
			} else {
				if (ts >= r->begin.expire_tv.tv_sec && ts <= r->end.expire_tv.tv_sec)
					time_range_begin_timer(&r->begin);
			}
			if (r->begin.expire_tv.tv_sec < ts)
				r->begin.expire_tv.tv_sec += 24 * 60 * 60;
			if (r->end.expire_tv.tv_sec < ts)
				r->end.expire_tv.tv_sec += 24 * 60 * 60;
			triton_timer_add(&shaper_ctx, &r->begin, 1);
			triton_timer_add(&shaper_ctx, &r->end, 1);
		} else
			log_emerg("tbf: failed to parse time-range '%s'\n", opt->val);
	}
}

#ifdef RADIUS
static int parse_attr_opt(const char *opt)
{
	struct rad_dict_attr_t *attr;
	struct rad_dict_vendor_t *vendor;

	if (conf_vendor)
		vendor = rad_dict_find_vendor_id(conf_vendor);
	else
		vendor = NULL;

	if (conf_vendor) {
		if (vendor)
			attr = rad_dict_find_vendor_attr(vendor, opt);
		else
			attr = NULL;
	}else
		attr = rad_dict_find_attr(opt);

	if (attr)
		return attr->id;

	return atoi(opt);
}

static int parse_vendor_opt(const char *opt)
{
	struct rad_dict_vendor_t *vendor;

	vendor = rad_dict_find_vendor_name(opt);
	if (vendor)
		return vendor->id;
	
	return atoi(opt);
}
#endif

static void load_config(void)
{
	const char *opt;

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		opt = conf_get_opt("tbf", "vendor");
		if (opt)
			conf_vendor = parse_vendor_opt(opt);

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

		if (conf_attr_up <= 0 || conf_attr_down <= 0) {
			log_emerg("tbf: incorrect attribute(s), tbf disabled...\n");
			return;
		}
	}
#endif
	
	opt = conf_get_opt("tbf", "burst-factor");
	if (opt) {
		conf_down_burst_factor = strtod(opt, NULL);
		conf_up_burst_factor = conf_down_burst_factor * 10;
	}
	
	opt = conf_get_opt("tbf", "down-burst-factor");
	if (opt)
		conf_down_burst_factor = strtod(opt, NULL);

	opt = conf_get_opt("tbf", "up-burst-factor");
	if (opt)
		conf_up_burst_factor = strtod(opt, NULL);

	opt = conf_get_opt("tbf", "latency");
	if (opt && atoi(opt) > 0)
		conf_latency = atoi(opt);

	opt = conf_get_opt("tbf", "mpu");
	if (opt && atoi(opt) >= 0)
		conf_mpu = atoi(opt);

	opt = conf_get_opt("tbf", "verbose");
	if (opt && atoi(opt) > 0)
		conf_verbose = 1;
	
	triton_context_call(&shaper_ctx, (triton_event_func)load_time_ranges, NULL);
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

static void init(void)
{
	if (clock_init())
		return;

	triton_context_register(&shaper_ctx, NULL);
	triton_context_wakeup(&shaper_ctx);

	load_config();

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif
	triton_event_register_handler(EV_SES_PRE_UP, (triton_event_func)ev_ppp_pre_up);
	triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
	triton_event_register_handler(EV_SHAPER, (triton_event_func)ev_shaper);
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	cli_register_simple_cmd2(shaper_change_exec, shaper_change_help, 2, "shaper", "change");
	cli_register_simple_cmd2(shaper_restore_exec, shaper_restore_help, 2, "shaper", "restore");
	cli_show_ses_register("rate-limit", "rate limit down-stream/up-stream (Kbit)", print_rate);
}

DEFINE_INIT(100, init);
