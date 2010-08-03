#ifndef CONF_FILE_H
#define CONF_FILE_H

#include "list.h"

struct conf_file_sect_t
{
	const char *name;
	
	struct list_head items;
};

void conf_file_load(const char *fname);
struct conf_file_sect_t *conf_file_get_section(const char *name);

#endif
