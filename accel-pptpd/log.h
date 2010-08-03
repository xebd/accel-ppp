//
// C++ Interface: log
//
// Description:
//
//
// Author:  <xeb@mail.ru>, (C) 2009
//
// Copyright: See COPYING file that comes with this distribution
//
//

#ifndef LOG_H
#define LOG_H

#include <stdio.h>

void log_init(FILE *f,int level,int color);
void log_error(const char *fmt,...);
void log_warn(const char *fmt,...);
void log_info(const char *fmt,...);
void log_debug(const char *fmt,...);
void log_msg(const char *fmt,...);

#endif
