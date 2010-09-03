/*
*  C Implementation: log
*
* Description:
*
*
* Author:  <xeb@mail.ru>, (C) 2009
*
* Copyright: See COPYING file that comes with this distribution
*
*/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include "triton/triton.h"
#include "log.h"

#define RED_COLOR     "\033[1;31m"
#define GREEN_COLOR   "\033[1;32m"
#define YELLOW_COLOR  "\033[1;33m"
#define BLUE_COLOR  	"\033[1;34m"
#define NORMAL_COLOR  "\033[0;39m"

#define LOG_ERROR 0
#define LOG_WARN  1
#define LOG_INFO  2
#define LOG_DEBUG 3

static FILE *log_file;
static int log_level=10;
static int log_color=1;
static const char* level_name[]={"error","warning","info","debug"};
static const char* level_color[]={RED_COLOR,YELLOW_COLOR,GREEN_COLOR,BLUE_COLOR};
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;

static int msg_completed=1;

static void do_log(int level,const char *fmt,va_list ap)
{
	struct timeval tv;

	//pthread_mutex_lock(&lock);
	if (!log_file)
		log_file=stdout;
	if (msg_completed)
	{
		gettimeofday(&tv,NULL);
		if (log_color) fprintf(log_file,"[%s%li.%03li] [%s]%s ",level_color[level],tv.tv_sec,tv.tv_usec/1000,NORMAL_COLOR,level_name[level]);
		else fprintf(log_file,"[%li.%03li] [%s] ",tv.tv_sec,tv.tv_usec/1000,level_name[level]);
	}

	vfprintf(log_file,fmt,ap);

	msg_completed=fmt[strlen(fmt)-1]=='\n';
	//if (msg_completed) pthread_mutex_unlock(&lock);
}
void __export log_error(const char *fmt,...)
{
	if (log_level>=1)
	{
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_ERROR,fmt,ap);
	}
}
void __export log_warn(const char *fmt,...)
{
	if (log_level>=2)
	{
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_WARN,fmt,ap);
	}
}
void __export log_info(const char *fmt,...)
{
	if (log_level>=3)
	{
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_INFO,fmt,ap);
	}
}
void __export log_debug(const char *fmt,...)
{
	if (log_level>=4)
	{
		va_list ap;
		va_start(ap,fmt);
		do_log(LOG_DEBUG,fmt,ap);
	}
}

void __export log_msg(const char *fmt,...)
{
	va_list ap;
	if (msg_completed) return;
	va_start(ap,fmt);
	vfprintf(log_file,fmt,ap);
	msg_completed=fmt[strlen(fmt)-1]=='\n';
	if (msg_completed) pthread_mutex_unlock(&lock);
}

void __export log_init(FILE *f,int level,int color)
{
	log_file=f;
	log_level=level;
	log_color=color;
}

