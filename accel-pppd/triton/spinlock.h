#ifndef __TRITON_SPINLOCK_H
#define __TRITON_SPINLOCK_H

#if defined(FUTEX_SPINLOCK)

/*#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>
typedef volatile int __attribute__((aligned)) spinlock_t;
static inline void _spin_lock(spinlock_t *l)
{
			syscall(SYS_futex, l, FUTEX_WAIT, r, NULL, NULL, 0);
}
static inline void _spin_unlock(spinlock_t *l)
{
		syscall(SYS_futex, l, FUTEX_WAKE, 2, NULL, NULL, 0);
}
#define spin_lock(l) _spin_lock(l)
#define spin_unlock(l) _spin_unlock(l)
#define SPINLOCK_INITIALIZER 1
#define spinlock_init(l) {*(l)=1;}*/

#elif defined(GCC_SPINLOCK)

typedef volatile int __attribute__((aligned)) spinlock_t;
#define spin_lock(l) {while(__sync_lock_test_and_set(l,1));}
#define spin_unlock(l) __sync_lock_release(l)
#define SPINLOCK_INITIALIZER 0
#define spinlock_init(l) {*(l)=0;}

#else

#include <pthread.h>
typedef pthread_spinlock_t spinlock_t;
#define spin_lock(l) pthread_spin_lock(l)
#define spin_unlock(l) pthread_spin_unlock(l)
#define SPINLOCK_INITIALIZER 1
#define spinlock_init(l) pthread_spin_init(l, 0)
#endif

#endif

