#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "triton.h"
#include "utils.h"

#include "memdebug.h"

void __export u_inet_ntoa(in_addr_t addr, char *str)
{
	sprintf(str, "%i.%i.%i.%i", addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff);
}

int __export u_readlong(long int *dst, const char *src,
                        long int min, long int max)
{
        char *src_stop = NULL;
        long int rv;

        if (dst == NULL || src == NULL || src[0] == '\0')
                return -1;

        errno = 0;
        rv = strtol(src, &src_stop, 0);
        if (errno != 0 || *src_stop != '\0' || rv < min || rv > max) {
                return -1;
        } else {
                *dst = rv;
                return 0;
        }
}
