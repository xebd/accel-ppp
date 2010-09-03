#include "triton.h"
#include "ipdb.h"

int __export ipdb_get(in_addr_t *addr, in_addr_t *peer_addr)
{
	*addr=inet_addr("192.168.200.100");
	*peer_addr=inet_addr("192.168.200.200");

	return 0;
}

