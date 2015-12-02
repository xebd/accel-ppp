#ifndef __CONF_FILE_H
#define __CONF_FILE_H

struct conf_opt {
	struct conf_opt *next;
	char *name;
	char *val;
	char *raw;
	struct conf_opt *child;
};

struct conf_sect {
	struct conf_sect *next;
	char *name;
	struct conf_opt *opt;
};

struct conf_sect *conf_get_sect(const char *name);
const char *conf_get_opt(const char *sect, const char *name);
const char *conf_get_subopt(const struct conf_opt *opt, const char *name);

int conf_load(const char *fname);

#endif
