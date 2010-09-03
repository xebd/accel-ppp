#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>

#include "triton_p.h"

int load_modules(const char *name)
{
	struct conf_sect_t *sect;
	struct conf_option_t *opt;

	sect = conf_get_section(name);
	if (!sect) {
		fprintf(stderr, "loader: section '%s' not found\n", name);
		return -1;
	}

	char *cwd = getcwd(NULL,0);

	list_for_each_entry(opt, &sect->items, entry) {
		if (!strcmp(opt->name,"path") && opt->val) {
			if (chdir(opt->val)) {
				fprintf(stderr,"loader: chdir '%s': %s\n", opt->val, strerror(errno));
				goto out_err;
			}
			continue;
		}
		if (!dlopen(opt->name, RTLD_NOW | RTLD_GLOBAL)) {
			fprintf(stderr,"loader: failed to load module '%s': %s\n",opt->name, dlerror());
			goto out_err;
		}
	}

	chdir(cwd);
	free(cwd);
	return 0;

out_err:
	chdir(cwd);
	free(cwd);
	return -1;
}

