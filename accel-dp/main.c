#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <rte_config.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <rte_debug.h>

#include "init.h"
#include "conf_file.h"
#include "event.h"

#define RTE_LOGTYPE_INIT RTE_LOGTYPE_USER1
#define MBUF_CACHE_SIZE 128

int sock_fd;

static struct rte_mempool *mbuf_pool;

static LIST_HEAD(init_list);

struct init {
	struct list_head entry;

	int order;
	void (*func)(void);
};

void register_init(int order, void (*func)(void))
{
	struct init *i1, *i = malloc(sizeof(*i));
	struct list_head *p = init_list.next;

	i->order = order;
	i->func = func;

	while (p != &init_list) {
		i1 = list_entry(p, typeof(*i1), entry);
		if (order < i1->order)
			break;
		p = p->next;
	}
	list_add_tail(&i->entry, p);
}

static void run_init(void)
{
	struct init *i;

	list_for_each_entry(i, &init_list, entry)
		i->func();
}

static void change_limits(void)
{
	FILE *f;
	struct rlimit lim;
	unsigned int nr_open = 1024*1024;

	f = fopen("/proc/sys/fs/nr_open", "r");
	if (f) {
		fscanf(f, "%d", &nr_open);
		fclose(f);
	}

	lim.rlim_cur = nr_open;
	lim.rlim_max = nr_open;
	setrlimit(RLIMIT_NOFILE, &lim);
}

static int bind_driver(const char *opt, char **val)
{
	char *ptr = strchr(opt, ':');
	char drv[128];
	int fd, r;
	char fname[1024];
	char bus_id[64];
	struct stat st;
	char vendor[16], device[16];

	if (!ptr)
		return -1;

	if (strchr(ptr + 1, ':')) {
		memcpy(drv, opt, ptr - opt);
		drv[ptr - opt] = 0;
		opt = ptr + 1;
	} else
		strcpy(drv, "uio_pci_generic");

	sprintf(bus_id, "0000:%s", opt);

	sprintf(fname, "/sys/bus/pci/devices/%s", bus_id);
	if (stat(fname, &st)) {
		fprintf(stderr, "%s: device not found\n", opt);
		return -1;
	}

	sprintf(fname, "/sys/bus/pci/devices/%s/vendor", bus_id);
	fd = open(fname, O_RDONLY);
	r = read(fd, vendor, sizeof(vendor));
	if (r <= 0) {
		fprintf(stderr, "%s: failed to read vendor\n", opt);
		close(fd);
		return -1;
	}
	vendor[r - 1] = 0;
	close(fd);

	sprintf(fname, "/sys/bus/pci/devices/%s/device", bus_id);
	fd = open(fname, O_RDONLY);
	r = read(fd, device, sizeof(device));
	if (r <= 0) {
		fprintf(stderr, "%s: failed to read device\n", opt);
		close(fd);
		return -1;
	}
	device[r - 1] = 0;
	close(fd);

	sprintf(fname, "modprobe -q %s", drv);
	system(fname);

	sprintf(fname, "/sys/bus/pci/drivers/%s", drv);
	if (stat(fname, &st)) {
		fprintf(stderr, "%s: driver '%s' is not loaded\n", opt, drv);
		return -1;
	}

	sprintf(fname, "/sys/bus/pci/devices/%s/driver", bus_id);

	r = readlink(fname, fname, sizeof(fname));
	if (r > 0) {
		fname[r] = 0;
		ptr = fname + r - 1;
		while (*ptr != '/')
			ptr--;

		if (strcmp(ptr + 1, drv)) {
			fprintf(stderr, "%s: unbind driver: %s\n", opt, ptr + 1);

			sprintf(fname, "/sys/bus/pci/devices/%s/driver/unbind", bus_id);

			fd = open(fname, O_WRONLY);
			if (fd < 0) {
				fprintf(stderr, "%s: failed to unbind driver: %s\n", opt, strerror(errno));
				return -1;
			}

			if (write(fd, bus_id, strlen(bus_id)) < 0) {
				fprintf(stderr, "%s: failed to unbind driver: %s\n", opt, strerror(errno));
				close(fd);
				return -1;
			}
			close(fd);
		} else
			goto out;
	}

	sprintf(fname, "/sys/bus/pci/drivers/%s/new_id", drv);
	fd = open(fname, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: failed to bind driver %s: %s\n", opt, drv, strerror(errno));
		return -1;
	}

	sprintf(fname, "%s %s", vendor, device);
	if (write(fd, fname, strlen(fname)) < 0) {
		fprintf(stderr, "%s: failed to bind driver %s: %s\n", opt, drv, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);

	/*sprintf(fname, "/sys/bus/pci/drivers/%s/bind", drv);
	fd = open(fname, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: failed to bind driver %s: %s\n", opt, drv, strerror(errno));
		close(fd);
		return -1;
	}

	if (write(fd, bus_id, strlen(bus_id)) < 0) {
		fprintf(stderr, "%s: failed to bind driver %s: %s\n", opt, drv, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);*/

out:
	*val = (char *)opt;
	return 0;
}

static int build_rte_args(char **argv)
{
	int i = 0;
	struct conf_sect *s = conf_get_sect("core");
	struct conf_opt *opt;

	if (!s)
		return 0;

	for (opt = s->opt; opt; opt = opt->next) {
		if (!strcmp(opt->name, "coremask")) {
			argv[i++] = "-c";
			argv[i++] = opt->val;
		} else if (!strcmp(opt->name, "corelist")) {
			argv[i++] = "-l";
			argv[i++] = opt->val;
		} else if (!strcmp(opt->name, "coremap")) {
			argv[i++] = "--lcores";
			argv[i++] = opt->val;
		} else if (!strcmp(opt->name, "master-lcore")) {
			argv[i++] = "--master-lcore";
			argv[i++] = opt->val;
		} else if (!strcmp(opt->name, "mem-channels")) {
			argv[i++] = "-n";
			argv[i++] = opt->val;
		} else if (!strcmp(opt->name, "mem-ranks")) {
			argv[i++] = "-r";
			argv[i++] = opt->val;
		} else if (!strcmp(opt->name, "socket-mem")) {
			argv[i++] = "-m";
			argv[i++] = opt->val;
		} else if (!strcmp(opt->name, "huge-dir")) {
			argv[i++] = "--huge-dir";
			argv[i++] = opt->val;
		}
	}

	s = conf_get_sect("interface");

	for (opt = s->opt; opt; opt = opt->next) {
		const char *busid = conf_get_subopt(opt, "busid");
		if (!busid) {
			fprintf(stderr, "%s: busid not specified\n", opt->name);
			return -1;
		}

		if (strcmp(busid, "kni")) {
			if (bind_driver(busid, &argv[i + 1]))
				return -1;
			argv[i++] = "-w";
			i++;
		}
	}

	return i;
}

static int init_pktmbuf_pool()
{
	int mbuf_cnt = 16*1024;
	const char *opt = conf_get_opt("core", "mbuf-count");

	if (opt)
		mbuf_cnt = atoi(opt);

	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", mbuf_cnt, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (!mbuf_pool) {
		fprintf(stderr, "%s\n", rte_strerror(rte_errno));
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	unsigned lcore_id;
	int i;
	char *cf = NULL;
	char *pid_file = NULL;
	int goto_daemon = 0;
	int rte_argc;
	char *rte_argv[256];
	const char *opt;
	int dist_lcore;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-c") && i + 1 < argc)
			cf = argv[++i];
		else if (!strcmp(argv[i], "-p") && i + 1 < argc)
			pid_file = argv[++i];
		else if (!strcmp(argv[i], "-d"))
			goto_daemon = 1;
	}

	if (!cf) {
		printf("usage: accel-dpdk [-d] [-p <pid file>] -c <config file>\n");
		return 1;
	}

	if (conf_load(cf))
		return 1;

	rte_argv[0] = argv[0];
	rte_argc = build_rte_args(rte_argv + 1) + 1;
	if (rte_argc == 0)
		return 1;

	if (rte_eal_init(rte_argc, rte_argv) < 0) {
		fprintf(stderr, "Cannot init EAL\n");
		return 1;
	}

	if (init_pktmbuf_pool())
		return -1;

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

	run_init();

	if (ctrl_init())
		return 1;

	if (eth_dev_init(mbuf_pool))
		return -1;

	if (kni_dev_init(mbuf_pool))
		return -1;

	opt = conf_get_opt("core", "distributor-lcore");
	if (opt)
		dist_lcore = atoi(opt);
	else
		dist_lcore = -1;

	if (distributor_init(dist_lcore != -1))
		return -1;

	if (goto_daemon)
		daemon(0, 0);

	change_limits();

	if (pid_file) {
		FILE *f = fopen(pid_file, "w");
		if (f) {
			fprintf(f, "%i", getpid());
			fclose(f);
		}
	}

	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		printf("%i\n", lcore_id);
		if (lcore_id == dist_lcore)
			rte_eal_remote_launch(lcore_distributor, NULL, lcore_id);
		else
			rte_eal_remote_launch(lcore_worker, NULL, lcore_id);
	}

	if (dist_lcore == -1)
		distributor_loop(1);
	else
		event_loop();

	rte_eal_mp_wait_lcore();
	return 0;
}
