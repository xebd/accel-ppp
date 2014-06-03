#ifndef __TRITON_SPINLOCK_H
#define __TRITON_SPINLOCK_H

#if defined(GCC_SPINLOCK)

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
#define spinlock_init(l) pthread_spin_init(l, 0)
#endif

#endif

