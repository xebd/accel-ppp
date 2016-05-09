#ifndef __IPRANGE_H
#define __IPRANGE_H

#include <netinet/in.h>


#define IPRANGE_CONF_SECTION "client-ip-range"

enum iprange_status {
	IPRANGE_DISABLED,
	IPRANGE_NO_RANGE,
	IPRANGE_ACTIVE,
};

enum iprange_status iprange_check_activation(void);
int iprange_client_check(in_addr_t ipaddr);
int iprange_tunnel_check(in_addr_t ipaddr);

#endif

