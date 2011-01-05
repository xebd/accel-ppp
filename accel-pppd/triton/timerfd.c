#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "timerfd.h"

int timerfd_create (clockid_t __clock_id, int __flags)
{
	return syscall(SYS_timerfd_create, __clock_id, __flags);
}


int timerfd_settime (int __ufd, int __flags,
			    __const struct itimerspec *__utmr,
			    struct itimerspec *__otmr)
{
	return syscall(SYS_timerfd_settime, __ufd, __flags, __utmr, __otmr);
}

