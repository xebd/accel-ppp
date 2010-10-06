#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "triton_p.h"

#include "memdebug.h"

struct sect_t
{
	struct list_head entry;
	
	struct conf_sect_t *sect;
};

static LIST_HEAD(sections);

static char* skip_space(char *str);
static char* skip_word(char *str);

static struct conf_sect_t *find_sect(const char *name);
static struct conf_sect_t *create_sect(const char *name);
static void sect_add_item(struct conf_sect_t *sect, const char *name, const char *val);
static struct conf_option_t *find_item(struct conf_sect_t *, const char *name);

int conf_load(const char *fname)
{
	char *buf,*str,*str2;
	char *path0,*path;
	int cur_line = 0;
	static struct conf_sect_t *cur_sect = NULL;

	FILE *f = fopen(fname, "r");
	if (!f) {
		perror("conf_file:open");
		return -1;
	}
	
	buf = _malloc(1024);
	path0 = _malloc(4096);
	path = _malloc(4096);
	
	getcwd(path0, 1024);
	
	while(!feof(f)) {
		if (!fgets(buf, 1024, f))
			break;
		++cur_line;
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = 0;
		
		str = skip_space(buf);
		if (*str == '#' || *str == 0)
			continue;
		if (strncmp(str, "$include", 8) == 0)	{
			str = skip_word(str);
			str = skip_space(str);
			conf_load(str);
			continue;
		}
		if (*str == '[') {
			for (str2 = ++str; *str2 && *str2 != ']'; str2++);
			if (*str2 != ']') {
				fprintf(stderr, "conf_file:%s:%i: sintax error\n", fname, cur_line);
				return -1;
			}
			*str2 = 0;
			cur_sect = find_sect(str);
			if (!cur_sect)
				cur_sect = create_sect(str);	
			continue;
		}
		if (!cur_sect) {
			fprintf(stderr, "conf_file:%s:%i: no section opened\n", fname, cur_line);
			return -1;
		}
		str2 = skip_word(str);
		if (*str2 == ' ') {
			*str2 = 0;
			++str2;
		}
		str2 = skip_space(str2);
		if (*str2 == '=' || *str2 == ',') {
			*str2 = 0;
			str2 = skip_space(str2 + 1);
			if (*str2 && *(str2 + 1) && *str2 == '$' && *(str2 + 1) == '{') {
				char *s;
				struct conf_option_t *opt;
				for (s = str2+2; *s && *s != '}'; s++);
				if (*s == '}') {
					*s = 0;
					str2 += 2;
				}
				opt = find_item(cur_sect, str2);
				if (!opt) {
					fprintf(stderr, "conf_file:%s:%i: parent option not found\n", fname, cur_line);
					return -1;
				}
				str2 = opt->val;
			}
		} else
			str2 = NULL;
		sect_add_item(cur_sect, str, str2);
	}
	
	_free(buf);
	_free(path);
	_free(path0);
	fclose(f);

	return 0;
}

static char* skip_space(char *str)
{
	for (; *str && *str == ' '; str++);
	return str;
}
static char* skip_word(char *str)
{
	for (; *str && (*str != ' ' && *str != '='); str++);
	return str;
}

static struct conf_sect_t *find_sect(const char *name)
{
	struct sect_t *s;
	list_for_each_entry(s, &sections, entry)
		if (strcmp(s->sect->name, name) == 0) return s->sect;
	return NULL;
}

static struct conf_sect_t *create_sect(const char *name)
{
	struct sect_t *s = _malloc(sizeof(struct sect_t));
	
	s->sect = _malloc(sizeof(struct conf_sect_t));
	s->sect->name = (char*)strdup(name);
	INIT_LIST_HEAD(&s->sect->items);
	
	list_add_tail(&s->entry, &sections);
	
	return s->sect;
}

static void sect_add_item(struct conf_sect_t *sect, const char *name, const char *val)
{
	struct conf_option_t *opt = _malloc(sizeof(struct conf_option_t));
	
	opt->name = _strdup(name);
	opt->val = val ? _strdup(val) : NULL;
	
	list_add_tail(&opt->entry, &sect->items);
}

static struct conf_option_t *find_item(struct conf_sect_t *sect, const char *name)
{
	struct conf_option_t *opt;
	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, name) == 0)
			return opt;
	}
	
	return NULL;
}

__export struct conf_sect_t * conf_get_section(const char *name)
{
	return find_sect(name);
}

__export char * conf_get_opt(const char *sect, const char *name)
{
	struct conf_option_t *opt;
	struct conf_sect_t *s = conf_get_section(sect);

	if (!s)
		return NULL;
	
	opt = find_item(s, name);
	if (!opt)
		return NULL;

	return opt->val;
}

