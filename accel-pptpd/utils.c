#include <stdio.h>

#include "triton.h"
#include "utils.h"


void __export u_inet_ntoa(in_addr_t addr, char *str)
{
	sprintf(str, "%i.%i.%i.%i", addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff);
}
