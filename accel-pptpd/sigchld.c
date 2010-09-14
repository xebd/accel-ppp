#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

#include "triton.h"
#include "spinlock.h"
#include "log.h"

#include "sigchld.h"

static LIST_HEAD(handlers);
static int refs;
static int sleeping = 1;
static pthread_mutex_t handlers_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t refs_lock = PTHREAD_MUTEX_INITIALIZER;

static struct triton_context_t sigchld_ctx;

static void sigchld_handler(void *arg)
{
	struct sigchld_handler_t *h, *h0;
	pid_t pid;
	int status;

	while (1) {	
		pid = waitpid(0, &status, WNOHANG);
		pthread_mutex_lock(&handlers_lock);
		if (pid == 0 || (pid == -1 && errno == ECHILD)) {
			sleeping = 1;
			pthread_mutex_unlock(&handlers_lock);
			return;
		} else if (pid < 0) {
			pthread_mutex_unlock(&handlers_lock);
			log_error("sigchld: waitpid: %s\n", strerror(errno));
			return;
		}
		h0 = NULL;
		list_for_each_entry(h, &handlers, entry) {
			if (h->pid == pid) {
				h0 = h;
				pthread_mutex_lock(&h0->lock);
				break;
			}
		}
		pthread_mutex_unlock(&handlers_lock);
		if (h0) {
			h0->handler(h0, WEXITSTATUS(status));
			list_del(&h0->entry);
			h0->pid = 0;
			pthread_mutex_unlock(&h0->lock);
		}
	}
}

void __export sigchld_register_handler(struct sigchld_handler_t *h)
{
	pthread_mutex_init(&h->lock, NULL);

	pthread_mutex_lock(&handlers_lock);
	list_add_tail(&h->entry, &handlers);
	pthread_mutex_unlock(&handlers_lock);
}

void __export sigchld_unregister_handler(struct sigchld_handler_t *h)
{
	pthread_mutex_lock(&handlers_lock);
	pthread_mutex_lock(&h->lock);
	if (h->pid) {
		list_del(&h->entry);
		h->pid = 0;
	}
	pthread_mutex_unlock(&h->lock);
	pthread_mutex_unlock(&handlers_lock);
}

void __export sigchld_lock()
{
	sigset_t set;

	pthread_mutex_lock(&refs_lock);
	if (refs == 0) {
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &set, NULL);
	}
	++refs;
	pthread_mutex_unlock(&refs_lock);
}

void __export sigchld_unlock()
{
	sigset_t set;

	pthread_mutex_lock(&refs_lock);
	if (refs == 1) {
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_UNBLOCK, &set, NULL);
	}
	--refs;
	pthread_mutex_unlock(&refs_lock);

}

static void sigchld(int num)
{
	int s;
	
	pthread_mutex_lock(&handlers_lock);
	s = sleeping;
	sleeping = 0;
	pthread_mutex_unlock(&handlers_lock);

	if (s)
		triton_context_call(&sigchld_ctx, sigchld_handler, NULL);
}

static void __init init(void)
{
	struct sigaction sa_sigchld = {
		.sa_handler = sigchld,
		.sa_flags = SA_NOCLDSTOP,
	};

	if (sigaction(SIGCHLD, &sa_sigchld, NULL)) {
		fprintf(stderr, "sigchld: sigaction: %s\n", strerror(errno));
		return;
	}

	triton_context_register(&sigchld_ctx, NULL);
}
