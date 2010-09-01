#include <stdio.h>

#include "triton_p.h"

static FILE *f_error;
static FILE *f_debug;

int log_init(void)
{
	char *log_error=conf_get_opt("core","log_error");
	char *log_debug=conf_get_opt("core","log_debug");

	if (log_error)
	{
		f_error=fopen(log_error,"a");
		if (!f_error)
		{
			perror("log:log_error:open");
			return -1;
		}
	}
	if (log_debug)
	{
		f_debug=fopen(log_debug,"a");
		if (!f_debug)
		{
			perror("log:log_debug:open");
			return -1;
		}
	}

	return 0;
}

