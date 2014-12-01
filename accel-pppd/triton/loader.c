#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <limits.h>

#include "triton_p.h"

#include "memdebug.h"

struct module_t
{
	struct list_head entry;
	char *name;
	void *handle;
};

static LIST_HEAD(modules);

int load_modules(const char *name)
{
	struct conf_sect_t *sect;
	struct conf_option_t *opt;
	char *fname;
	char *path = MODULE_PATH;
	char *ptr1, *ptr2;
	struct module_t *m;
	void *h;

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
					triton_log_error("loader: '%s' not found", opt->name);
					continue;
				}
			}
		}

		h = dlopen(fname, RTLD_LAZY | RTLD_GLOBAL);
		if (!h) {
			triton_log_error("loader: failed to load '%s': %s", opt->name, dlerror());
			_free(fname);
			return -1;
		}

		ptr1 = fname;
		while (1) {
			ptr2 = strchr(ptr1, '/');
			if (!ptr2)
				break;
			ptr1 = ptr2 + 1;
		}

		if (!strncmp(ptr1, "lib", 3))
			ptr1 += 3;

		ptr2 = strstr(ptr1, ".so\x0");
		if (ptr2)
			*ptr2 = 0;

		m = _malloc(sizeof(*m));
		m->name = _strdup(ptr1);
		m->handle = h;
		list_add_tail(&m->entry, &modules);
	}

	_free(fname);

	return 0;
}

int __export triton_module_loaded(const char *name)
{
	struct module_t *m;

	list_for_each_entry(m, &modules, entry) {
		if (strcmp(m->name, name))
			continue;
		return 1;
	}

	return 0;
}

