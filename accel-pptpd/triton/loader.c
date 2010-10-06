#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <limits.h>

#include "triton_p.h"

#include "memdebug.h"

int load_modules(const char *name)
{
	struct conf_sect_t *sect;
	struct conf_option_t *opt;
	char *fname;
	char *path = MODULE_PATH;

	sect = conf_get_section(name);
	if (!sect) {
		fprintf(stderr, "loader: section '%s' not found\n", name);
		return -1;
	}

	fname = _malloc(PATH_MAX);

	list_for_each_entry(opt, &sect->items, entry) {
		if (!strcmp(opt->name,"path") && opt->val) {
			path = opt->val;
			continue;
		}

		strcpy(fname, path);
		strcat(fname, "/");
		strcat(fname, opt->name);
		if (access(fname, F_OK)) {
			strcpy(fname, path);
			strcat(fname, "/lib");
			strcat(fname, opt->name);
			strcat(fname, ".so");
			if (access(fname, F_OK)) {
				strcpy(fname, opt->name);
				if (access(opt->name, F_OK)) {
					triton_log_error("loader: '%s' not found\n", opt->name);
					continue;
				}
			}
		}

		if (!dlopen(fname, RTLD_NOW | RTLD_GLOBAL)) {
			triton_log_error("loader: failed to load '%s': %s\n", opt->name, dlerror());
			_free(fname);
			return -1;
		}
	}

	_free(fname);

	return 0;
}

