#ifndef __RADIUS_H
#define __RADIUS_H

#include <netinet/in.h>

#define ATTR_TYPE_INTEGER 0
#define ATTR_TYPE_STRING  1
#define ATTR_TYPE_DATE    2
#define ATTR_TYPE_IPADDR  3

typedef union
{
		int integer;
		const char *string;
		time_t date;
		in_addr_t ipaddr;
} rad_value_t;

struct rad_dict_t
{
	struct list_head items;
};

void *rad_load_dict(const char *fname);
void rad_free_dict(struct rad_dict_t *dict);

#endif

