#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "triton.h"
#include "utils.h"

#include "memdebug.h"

extern int urandom_fd;

void __export u_inet_ntoa(in_addr_t addr, char *str)
{
	addr = ntohl(addr);
	sprintf(str, "%i.%i.%i.%i", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
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

int __export u_randbuf(void *buf, size_t buf_len, int *err)
{
	uint8_t *u8buf = buf;
	ssize_t rd_len;

	while (buf_len) {
		rd_len = read(urandom_fd, u8buf, buf_len);
		if (rd_len < 0) {
			if (errno == EINTR)
				rd_len = 0;
			else {
				if (err)
					*err = errno;
				return -1;
			}
		} else if (rd_len == 0) {
			if (err)
				*err = 0;
			return -1;
		}
		u8buf += rd_len;
		buf_len -= rd_len;
	}

	return 0;
}
