#ifndef __LOG_H__
#define __LOG_H__

#ifdef MINIMAL
#define log_error(...) fprintf(stderr, __VA_ARGS__)
#define log_warn(...) fprintf(stderr, __VA_ARGS__)
#define log_info1(...) fprintf(stderr, __VA_ARGS__)
#define log_info2(...) fprintf(stderr, __VA_ARGS__)
#define log_debug(...) fprintf(stderr, __VA_ARGS__)
#define log_msg(...) fprintf(stderr, __VA_ARGS__)
#define log_append(...) fprintf(stderr, __VA_ARGS__)
#define log_emerg(...) fprintf(stderr, __VA_ARGS__)
#else

#include <stdarg.h>
#include <sys/time.h>
#include "list.h"

#define LOG_MAX_SIZE 4096
#define LOG_CHUNK_SIZE 128

struct log_msg {
	struct list_head entry;
	struct timeval timestamp;
	void *lpd;
	int level;
	struct log_chunk *hdr;
	struct list_head *chunks;
};

struct log_chunk {
	struct list_head entry;
	int len;
	char msg[0];
};

struct log_target {
	struct list_head entry;

	void (*log)(struct log_msg *);
	void (*reopen)(void);
};

void log_free_msg(struct log_msg *msg);

void log_emerg(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));

void log_error(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_warn(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_info1(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_info2(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_debug(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_msg(const char *fmt, ...) __attribute__((format(gnu_printf, 1, 2)));
void log_append(const char *str, int len);

#define log_ppp_error(...) log_error(__VA_ARGS__)

void log_register_target(struct log_target *t);
#endif

#endif
