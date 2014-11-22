#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <malloc.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>

#ifdef CRYPTO_OPENSSL
#include <openssl/ssl.h>
#endif

#include "triton/triton.h"

#include "memdebug.h"
#include "log.h"
#include "events.h"
#include "backup.h"

#ifndef ARG_MAX
#define ARG_MAX 128*1024
#endif

static char *pid_file;
static char *conf_file;
static char *conf_dump;
static sigset_t orig_set;
static char **argv;
static int argc;

#ifdef CRYPTO_OPENSSL
#include <openssl/ssl.h>

static pthread_mutex_t *ssl_lock_cs;

static unsigned long ssl_thread_id(void)
{
	return (unsigned long)pthread_self();
}

static void ssl_lock(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&ssl_lock_cs[type]);
	else
		pthread_mutex_unlock(&ssl_lock_cs[type]);
}

static void openssl_init(void)
{
	int i;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();

	ssl_lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

	for (i = 0; i < CRYPTO_num_locks(); i++)
		pthread_mutex_init(&ssl_lock_cs[i], NULL);

	CRYPTO_set_id_callback(ssl_thread_id);
	CRYPTO_set_locking_callback(ssl_lock);
}
#endif

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
	if (setrlimit(RLIMIT_NOFILE, &lim))
		log_emerg("main: setrlimit: %s\n", strerror(errno));
}

static void config_reload_notify(int r)
{
	if (!r)
		triton_event_fire(EV_CONFIG_RELOAD, NULL);
}

static void config_reload(int num)
{
	triton_conf_reload(config_reload_notify);
}

static void close_all_fd(void)
{
	DIR *dirp;
	struct dirent ent, *res;
	char path[128];
	int fd;

	sprintf(path, "/proc/%u/fd", getpid());

	dirp = opendir(path);
	if (!dirp)
		return;

	while (1) {
		if (readdir_r(dirp, &ent, &res))
			return;
		if (!res)
			break;

		fd = atol(ent.d_name);
		if (fd > 2)
			close(fd);
	}

	closedir(dirp);
}

void core_restart(int soft)
{
	char exe[PATH_MAX];

	pthread_sigmask(SIG_SETMASK, &orig_set, NULL);

#ifdef USE_BACKUP
	if (soft)
		backup_restore_fd();
	else
#endif
		close_all_fd();

	sprintf(exe, "/proc/%u/exe", getpid());
	readlink(exe, exe, PATH_MAX);

	while (1) {
		execv(exe, argv);
		sleep(3);
	}
}

static void sigsegv(int num)
{
	char cmd[PATH_MAX];
	char fname[128];
	char exec_file[PATH_MAX];
	struct rlimit lim;
	pid_t pid;
	int status;

	pthread_sigmask(SIG_SETMASK, &orig_set, NULL);

	if (conf_dump) {
		FILE *f;
		unsigned int t = time(NULL);

		chdir(conf_dump);

		sprintf(fname, "cmd-%u", t);
		f = fopen(fname, "w");
		if (!f)
			goto out;
		fprintf(f, "thread apply all bt full\ndetach\nquit\n");
		fclose(f);

		sprintf(exec_file, "/proc/%u/exe", getpid());
		readlink(exec_file, exec_file, PATH_MAX);

		sprintf(cmd, "gdb -x %s %s %d > dump-%u", fname, exec_file, getpid(), t);

		system(cmd);

		unlink(fname);
	}

out:
	pid = fork();
	if (pid) {
		waitpid(pid, &status, 0);
		core_restart(1);
	}

	if (conf_dump) {
		lim.rlim_cur = RLIM_INFINITY;
		lim.rlim_max = RLIM_INFINITY;

		setrlimit(RLIMIT_CORE, &lim);
	}

	abort();
}

int main(int _argc, char **_argv)
{
	sigset_t set;
	int i, sig, goto_daemon = 0, len;
	pid_t pid = 0;
	struct sigaction sa;
	int pagesize = sysconf(_SC_PAGE_SIZE);
	int internal = 0;

	argc = _argc;
	argv = _argv;

	if (argc < 2)
		goto usage;

	for(i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d"))
			goto_daemon = 1;
		else if (!strcmp(argv[i], "-p")) {
			if (i == argc - 1)
				goto usage;
			pid_file = argv[++i];
		} else if (!strcmp(argv[i], "-c")) {
			if (i == argc - 1)
				goto usage;
			conf_file = argv[++i];
		} else if (!strcmp(argv[i], "--dump")) {
			if (i == argc - 1)
				goto usage;
			len = (strlen(argv[i + 1]) / pagesize + 1) * pagesize;
			conf_dump = memalign(pagesize, len);
			strcpy(conf_dump, argv[++i]);
			mprotect(conf_dump, len, PROT_READ);
		} else if (!strcmp(argv[i], "--internal"))
			internal = 1;
	}

	if (!conf_file)
		goto usage;

	if (internal) {
		while (getppid() != 1)
			sleep(1);
	}

	if (triton_init(conf_file))
		_exit(EXIT_FAILURE);

	if (goto_daemon && pid != getpid()) {
		/*pid_t pid = fork();
		if (pid > 0)
			_exit(EXIT_SUCCESS);
		if (pid < 0) {
			perror("fork");
			return EXIT_FAILURE;
		}
		if (setsid() < 0)
			_exit(EXIT_FAILURE);
		pid = fork();
		if (pid)
			_exit(0);
		umask(0);
		chdir("/");
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);*/
		daemon(0, 0);
	}

	if (pid_file) {
		FILE *f = fopen(pid_file, "w");
		if (f) {
			fprintf(f, "%i", getpid());
			fclose(f);
		}
	}

	change_limits();

#ifdef CRYPTO_OPENSSL
	openssl_init();
#endif

	if (triton_load_modules("modules"))
		return EXIT_FAILURE;

	log_msg("accel-ppp version %s\n", ACCEL_PPP_VERSION);

	triton_run();


	sigfillset(&set);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = config_reload;
	sa.sa_mask = set;
	sigaction(SIGUSR1, &sa, NULL);

	sa.sa_handler = sigsegv;
	sa.sa_mask = set;
	sigaction(SIGSEGV, &sa, NULL);


	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	sigdelset(&set, SIGSEGV);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGBUS);
	sigdelset(&set, SIGHUP);
	sigdelset(&set, SIGIO);
	sigdelset(&set, SIGINT);
	sigdelset(&set, SIGUSR1);
	sigdelset(&set, 35);
	sigdelset(&set, 36);
	pthread_sigmask(SIG_SETMASK, &set, &orig_set);

	sigemptyset(&set);
	//sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGSEGV);
	sigaddset(&set, SIGILL);
	sigaddset(&set, SIGFPE);
	sigaddset(&set, SIGBUS);

#ifdef USE_BACKUP
	backup_restore(internal);
#endif

	sigwait(&set, &sig);
	log_info1("terminate, sig = %i\n", sig);

	triton_terminate();

	return EXIT_SUCCESS;

usage:
	printf("usage: accel-pppd [-d] [-p <file>] -c <file>\n\
	where:\n\
		-d - daemon mode\n\
		-p - write pid to <file>\n\
		-c - config file\n");
	_exit(EXIT_FAILURE);
}

