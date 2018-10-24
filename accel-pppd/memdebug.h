#ifndef __MEMDEBUG_H
#define __MEMDEBUG_H

#ifdef MEMDEBUG

#include <sys/types.h>

#define _malloc(size) md_malloc(size, __FILE__, __LINE__)
#define _realloc(ptr, size) md_realloc(ptr, size, __FILE__, __LINE__)
#define _free(ptr) md_free(ptr, __FILE__, __LINE__)
#define _strdup(str) md_strdup(str, __FILE__, __LINE__)
#define _strndup(str, size) md_strndup(str, size, __FILE__, __LINE__)
#define _asprintf(strp, fmt, ...) md_asprintf(__FILE__, __LINE__, strp, fmt, ##__VA_ARGS__)

void *md_malloc(size_t size, const char *fname, int line);
void *md_realloc(void *ptr, size_t size, const char *fname, int line);
void md_free(void *ptr, const char *fname, int line);
char* md_strdup(const char *ptr, const char *fname, int line);
char* md_strndup(const char *ptr, size_t size, const char *fname, int line);
int md_asprintf(const char *fname, int line, char **strp, const char *fmt, ...) __attribute__((format(gnu_printf, 4, 5)));
void md_check(void *ptr);

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define _malloc(size) malloc(size)
#define _realloc(ptr, size) realloc(ptr, size)
#define _free(ptr) free(ptr)
#define _strdup(str) strdup(str)
#define _strndup(str, size) strndup(str, size)
#define _asprintf(strp, fmt, ...) asprintf(strp, fmt, ##__VA_ARGS__)
#endif

#endif
