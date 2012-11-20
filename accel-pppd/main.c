#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "triton/triton.h"

#include "memdebug.h"
#include "log.h"
#include "events.h"

static char *pid_file;
static char *conf_file;

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
	unsigned int file_max = 1024*1024;
	unsigned int nr_open = 1024*1024;

	f = fopen("/proc/sys/fs/nr_open", "r");
	if (f) {
		fscanf(f, "%d", &nr_open);
		fclose(f);
	}

	f = fopen("/proc/sys/fs/file-max", "r");
	if (f) {
		fscanf(f, "%d", &file_max);
		fclose(f);
	}

	if (file_max > nr_open)
		file_max = nr_open;

	lim.rlim_cur = file_max;
	lim.rlim_max = file_max;
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

int main(int argc, char **argv)
{
	sigset_t set;
	int i, sig, goto_daemon = 0;

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
		}
	}

	if (!conf_file)
		goto usage;

	if (triton_init(conf_file))
		_exit(EXIT_FAILURE);

	if (goto_daemon) {
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

	struct sigaction sa = {
		.sa_handler = config_reload,
		.sa_mask = set,
	};

	sigaction(SIGUSR1, &sa, NULL);

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
	pthread_sigmask(SIG_SETMASK, &set, NULL);

	sigemptyset(&set);
	//sigaddset(&set, SIGINT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGSEGV);
	sigaddset(&set, SIGILL);
	sigaddset(&set, SIGFPE);
	sigaddset(&set, SIGBUS);
	
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

