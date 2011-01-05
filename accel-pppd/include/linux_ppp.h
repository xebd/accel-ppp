#ifndef __KERNEL_PPP_H
#define __KERNEL_PPP_H

#include <linux/types.h>

#ifndef aligned_u64
#define aligned_u64 __u64 __attribute__((aligned(8)))
#endif

#ifndef __aligned_u64
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif

#include <linux/ppp_defs.h>
#include <linux/if.h>
#include <linux/if_ppp.h>

#endif

