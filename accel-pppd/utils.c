#include <stdio.h>

#include "triton.h"
#include "utils.h"

#include "memdebug.h"

void __export u_inet_ntoa(in_addr_t addr, char *str)
{
	addr = ntohl(addr);
	sprintf(str, "%i.%i.%i.%i", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff);
}
