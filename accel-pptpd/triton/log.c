#include <stdio.h>
#include <stdarg.h>

#include "triton_p.h"

static FILE *f_error;
static FILE *f_debug;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int log_init(void)
{
	char *log_error = conf_get_opt("core","log_error");
	char *log_debug = conf_get_opt("core","log_debug");

	if (log_error) {
		f_error = fopen(log_error, "a");
		if (!f_error) {
			perror("log:log_error:open");
			return -1;
		}
	}
	if (log_debug) {
		f_debug = fopen(log_debug, "a");
		if (!f_debug)	{
			perror("log:log_debug:open");
			return -1;
		}
	}

	return 0;
}

static void do_log(FILE *f, const char *fmt, va_list ap)
{
	struct timeval tv;
	struct tm tm;
	char date[64];

	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	strftime(date, sizeof(date), "%F %H:%M:%S", &tm);

	pthread_mutex_lock(&lock);
	fprintf(f, "[%s.%i]", date, (int)tv.tv_usec / 1000);
	vfprintf(f, fmt,ap);
	pthread_mutex_unlock(&lock);
}
void triton_log_error(const char *fmt,...)
{
	va_list ap;
	if (!f_error)
		return;
	va_start(ap, fmt);
	do_log(f_error, fmt, ap);
}

void triton_log_debug(const char *fmt,...)
{
	va_list ap;
	if (!f_debug)
		return;
	va_start(ap, fmt);
	do_log(f_debug, fmt, ap);
}

