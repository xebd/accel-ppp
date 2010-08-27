#ifndef __TRITON_SPINLOCK_H
#define __TRITON_SPINLOCK_H

#ifdef USE_SPINLOCK
typedef spinlock_t unsigned char;
#define spin_lock(l) {while(__sync_lock_test_and_set(l,1);}
#define spin_unlock(l) __sync_lock_release(l)
#define SPINLOCK_INITIALIZER 0
#else
typedef spinlock_t pthread_mutex_t;
#define spin_lock(l) pthread_mutex_lock(l)
#define spin_unlock(l) pthread_mutex_unlock(l)
#define SPINLOCK_INITIALIZER PTHREAD_MUTEX_INITIALIZER
#endif

#endif

