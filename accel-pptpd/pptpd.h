//
// C++ Interface: pptpd
//
// Description:
//
//
// Author:  <xeb@mail.ru>, (C) 2009
//
// Copyright: See COPYING file that comes with this distribution
//
//

#ifndef PPTPD_H
#define PPTPD_H

struct ctrl_thread_t
{
	pthread_t thr;
	pthread_mutex_t lock;
	int count;
	int pipe_fd[2];
};

int ctrl_init(struct ctrl_thread_t*);

#endif
