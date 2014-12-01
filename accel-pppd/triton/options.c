#include <stdlib.h>
#include <string.h>

#include "triton_p.h"
#include "conf_file.h"

#include "memdebug.h"

static struct conf_file_sect_t *sect=NULL;

static const char* find_option(const char *name)
{
	struct option_t *opt;

	if (!sect)
	{
		sect=conf_file_get_section("options");
		if (!sect) return 0;
	}

	list_for_each_entry(opt,&sect->items,entry)
	{
		if (strcmp(opt->name,name)==0)
			return opt->val;
	}

	return NULL;
}
int triton_get_int_option(const char *str)
{
	const char *val=find_option(str);
	if (!val) return 0;

	return atoi(val);
}
const char* triton_get_str_option(const char *str)
{
	const char *val=find_option(str);

	return val;
}
double triton_get_double_option(const char *str)
{
	const char *val=find_option(str);
	if (!val) return 0;

	return atof(val);
}
