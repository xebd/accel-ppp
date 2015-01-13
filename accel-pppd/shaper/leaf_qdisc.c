#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_mirred.h>
#include <linux/tc_act/tc_skbedit.h>

#include "log.h"
#include "ppp.h"

#include "shaper.h"
#include "tc_core.h"
#include "libnetlink.h"

static int parse_size(const char *str, int *r)
{
	double sz;
	char *endptr;

	sz = strtod(str, &endptr);

	if (endptr == str)
		return -1;

	if (*endptr == 0) {
		*r = sz;
		return 0;
	}

	if (strcmp(endptr, "kb") == 0 || strcmp(endptr, "k") == 0)
		*r = sz * 1024;
	else if (strcmp(endptr, "mb") == 0 || strcmp(endptr, "m") == 0)
		*r = sz * 1024 * 1024;
	else if (strcmp(endptr, "gb") == 0 || strcmp(endptr, "g") == 0)
		*r = sz * 1024 * 1024 * 1024;
	else if (strcmp(endptr, "kbit") == 0)
		*r = sz * 1024  / 8;
	else if (strcmp(endptr, "mbit") == 0)
		*r = sz * 1024 * 1024 / 8;
	else if (strcmp(endptr, "gbit") == 0)
		*r = sz * 1024 * 1024 * 1024 / 8;
	else if (strcmp(endptr, "b") == 0)
		*r = sz;
	else
		return -1;

	return 0;
}

#ifdef TCA_FQ_CODEL_MAX
static int parse_time(const char *str, int *r)
{
	double t;
	char *endptr;

	t = strtod(str, &endptr);

	if (endptr == str)
		return -1;

	if (*endptr == 0) {
		*r = t;
		return 0;
	}

	if (strcmp(endptr, "s") == 0 || strcmp(endptr, "sec") == 0)
		*r = t * TIME_UNITS_PER_SEC;
	else if (strcmp(endptr, "ms") == 0 || strcmp(endptr, "msec") == 0)
		*r = t * TIME_UNITS_PER_SEC/1000;
	else if (strcmp(endptr, "us") == 0 || strcmp(endptr, "usec") == 0)
		*r = t * TIME_UNITS_PER_SEC/1000000;
	else
		return -1;

	return 0;
}
#endif

static int parse_int(const char *str, int *r)
{
	char *endptr;

	*r = strtol(str, &endptr, 10);

	return *endptr != 0;
}

static int parse_u32(const char *str, int *r)
{
	char *endptr;

	*r = strtol(str, &endptr, 10);

	return *endptr != 0 || *r < 0;
}

static int parse_sfq(char *str)
{
	char *ptr1, *ptr2;

	if (!*str)
		goto out;

	while (1) {
		for (ptr1 = str + 1; *ptr1 && *ptr1 != ' '; ptr1++);

		if (!*ptr1)
			return -1;

		*ptr1 = 0;

		for (ptr1++; *ptr1 && *ptr1 == ' '; ptr1++);

		if (!*ptr1)
			return -1;

		for (ptr2 = ptr1 + 1; *ptr2 && *ptr2 != ' '; ptr2++);

		if (*ptr2) {
			*ptr2 = 0;
			for (ptr2++; *ptr2 && *ptr2 == ' '; ptr2++);
		}

		if (strcmp(str, "quantum") == 0) {
			if (parse_size(ptr1, &conf_lq_arg1))
				return -1;
		} else if (strcmp(str, "perturb") == 0) {
			if (parse_int(ptr1, &conf_lq_arg2))
				return -1;
		} else if (strcmp(str, "limit") == 0) {
			if (parse_u32(ptr1, &conf_lq_arg3))
				return -1;
		} else
			return -1;

		if (*ptr2 == 0)
			break;

		str = ptr2;
	}

out:
	conf_leaf_qdisc = LEAF_QDISC_SFQ;

	return 0;
}

#ifdef TCA_FQ_CODEL_MAX
static int parse_fq_codel(char *str)
{
	char *ptr1, *ptr2;

	conf_lq_arg6 = -1;

	if (!*str)
		goto out;

	while (1) {
		for (ptr1 = str + 1; *ptr1 && *ptr1 != ' '; ptr1++);

		if (!*ptr1) {
			if (strcmp(str, "ecn") == 0)
				conf_lq_arg6 = 1;
			else if (strcmp(str, "noecn") == 0)
				conf_lq_arg6 = 0;
			else
				return -1;
			break;
		}

		*ptr1 = 0;

		for (ptr1++; *ptr1 && *ptr1 == ' '; ptr1++);

		if (!*ptr1)
			return -1;

		for (ptr2 = ptr1 + 1; *ptr2 && *ptr2 != ' '; ptr2++);

		if (*ptr2) {
			*ptr2 = 0;
			for (ptr2++; *ptr2 && *ptr2 == ' '; ptr2++);
		}

		if (strcmp(str, "limit") == 0) {
			if (parse_u32(ptr1, &conf_lq_arg1))
				return -1;
		} else if (strcmp(str, "flows") == 0) {
			if (parse_u32(ptr1, &conf_lq_arg2))
				return -1;
		} else if (strcmp(str, "quantum") == 0) {
			if (parse_u32(ptr1, &conf_lq_arg3))
				return -1;
		} else if (strcmp(str, "target") == 0) {
			if (parse_time(ptr1, &conf_lq_arg4))
				return -1;
		} else if (strcmp(str, "interval") == 0) {
			if (parse_time(ptr1, &conf_lq_arg5))
				return -1;
		} else
			return -1;

		if (*ptr2 == 0)
			break;

		str = ptr2;
	}

out:
	conf_leaf_qdisc = LEAF_QDISC_FQ_CODEL;

	return 0;
}
#endif

void leaf_qdisc_parse(const char *opt)
{
	char *ptr1;
	char *str = strdup(opt);

	for (ptr1 = str; *ptr1 && *ptr1 != ' '; ptr1++);

	if (*ptr1) {
		*ptr1 = 0;
		for (ptr1++; *ptr1 && *ptr1 == ' '; ptr1++);
	}

	if (strcmp(str, "sfq") == 0) {
		if (parse_sfq(ptr1))
			goto out_err;
#ifdef TCA_FQ_CODEL_MAX
	} else if (strcmp(str, "fq_codel") == 0) {
		if (parse_fq_codel(ptr1))
			goto out_err;
#endif
	} else
		log_emerg("shaper: unknown leaf-qdisc '%s'\n", str);

	free(str);

	return;
out_err:
	log_emerg("shaper: failed to parse '%s'\n", opt);
}

static int qdisc_sfq(struct qdisc_opt *qopt, struct nlmsghdr *n)
{
	struct tc_sfq_qopt opt = {
		.quantum = conf_lq_arg1,
		.perturb_period = conf_lq_arg2,
		.limit = conf_lq_arg3,
	};

	addattr_l(n, 1024, TCA_OPTIONS, &opt, sizeof(opt));

	return 0;
}

static int install_sfq(struct rtnl_handle *rth, int ifindex, int parent, int handle)
{
	struct qdisc_opt opt = {
		.kind = "sfq",
		.handle = handle,
		.parent = parent,
		.qdisc = qdisc_sfq,
	};

	return tc_qdisc_modify(rth, ifindex, RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, &opt);
}

#ifdef TCA_FQ_CODEL_MAX
static int qdisc_fq_codel(struct qdisc_opt *qopt, struct nlmsghdr *n)
{
	struct rtattr *tail = NLMSG_TAIL(n);

	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);

	if (conf_lq_arg1)
		addattr_l(n, 1024, TCA_FQ_CODEL_LIMIT, &conf_lq_arg1, sizeof(conf_lq_arg1));
	if (conf_lq_arg2)
		addattr_l(n, 1024, TCA_FQ_CODEL_FLOWS, &conf_lq_arg2, sizeof(conf_lq_arg2));
	if (conf_lq_arg3)
		addattr_l(n, 1024, TCA_FQ_CODEL_QUANTUM, &conf_lq_arg3, sizeof(conf_lq_arg3));
	if (conf_lq_arg4)
		addattr_l(n, 1024, TCA_FQ_CODEL_INTERVAL, &conf_lq_arg4, sizeof(conf_lq_arg4));
	if (conf_lq_arg5)
		addattr_l(n, 1024, TCA_FQ_CODEL_TARGET, &conf_lq_arg5, sizeof(conf_lq_arg5));
	if (conf_lq_arg6 != -1)
		addattr_l(n, 1024, TCA_FQ_CODEL_ECN, &conf_lq_arg6, sizeof(conf_lq_arg6));

	tail->rta_len = (void *)NLMSG_TAIL(n) - (void *)tail;

	return 0;
}

static int install_fq_codel(struct rtnl_handle *rth, int ifindex, int parent, int handle)
{
	struct qdisc_opt opt = {
		.kind = "fq_codel",
		.handle = handle,
		.parent = parent,
		.qdisc = qdisc_fq_codel,
	};

	return tc_qdisc_modify(rth, ifindex, RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, &opt);
}
#endif

int install_leaf_qdisc(struct rtnl_handle *rth, int ifindex, int parent, int handle)
{
	if (conf_leaf_qdisc == LEAF_QDISC_SFQ)
		return install_sfq(rth, ifindex, parent, handle);

#ifdef TCA_FQ_CODEL_MAX
	else if (conf_leaf_qdisc == LEAF_QDISC_FQ_CODEL)
		return install_fq_codel(rth, ifindex, parent, handle);
#endif

	return 0;
}

