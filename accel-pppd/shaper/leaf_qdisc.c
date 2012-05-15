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


int install_leaf_qdisc(struct rtnl_handle *rth, int ifindex, int parent, int handle)
{
	if (conf_leaf_qdisc == LEAF_QDISC_SFQ)
		return install_sfq(rth, ifindex, parent, handle);
	
	return 0;
}

