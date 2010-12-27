#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include "triton_p.h"

#include "memdebug.h"

struct sect_t
{
	struct list_head entry;
	
	struct conf_sect_t *sect;
};

static pthread_mutex_t conf_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(sections);
static char *conf_fname;

static char* skip_space(char *str);
static char* skip_word(char *str);

static struct conf_sect_t *find_sect(const char *name);
static struct conf_sect_t *create_sect(const char *name);
static void sect_add_item(struct conf_sect_t *sect, const char *name, const char *val);
static struct conf_option_t *find_item(struct conf_sect_t *, const char *name);

static char *buf;

int __conf_load(const char *fname, struct conf_sect_t *cur_sect)
{
	char *str,*str2;
	int cur_line = 0;

	FILE *f = fopen(fname, "r");
	if (!f) {
		perror("conf_file:open");
		return -1;
	}
	
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
			if (__conf_load(str, cur_sect));
				break;
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
	
	fclose(f);

	return 0;
}

int conf_load(const char *fname)
{
	int r;

	if (fname) {
		if (conf_fname)
			_free(conf_fname);
		conf_fname = _strdup(fname);
	} else
		fname = conf_fname;

	buf = _malloc(1024);

	r = __conf_load(fname, NULL);
	
	_free(buf);

	return r;
}

int conf_reload(const char *fname)
{
	struct sect_t *sect;
	struct conf_option_t *opt;
	int r;
	LIST_HEAD(sections_bak);

	pthread_mutex_lock(&conf_lock);

	while (!list_empty(&sections)) {
		sect = list_entry(sections.next, typeof(*sect), entry);
		list_del(&sect->entry);
		list_add_tail(&sect->entry, &sections_bak);
	}

	r = conf_load(fname);

	if (r) {
		while (!list_empty(&sections_bak)) {
			sect = list_entry(sections_bak.next, typeof(*sect), entry);
			list_del(&sect->entry);
			list_add_tail(&sect->entry, &sections);
		}
		pthread_mutex_unlock(&conf_lock);
	} else {
		pthread_mutex_unlock(&conf_lock);
		while (!list_empty(&sections_bak)) {
			sect = list_entry(sections_bak.next, typeof(*sect), entry);
			list_del(&sect->entry);
			while (!list_empty(&sect->sect->items)) {
				opt = list_entry(sect->sect->items.next, typeof(*opt), entry);
				list_del(&opt->entry);
				if (opt->val)
					_free(opt->val);
				_free(opt->name);
				_free(opt);
			}
			_free((char *)sect->sect->name);
			_free(sect->sect);
			_free(sect);
		}
	}

	return r;
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
	s->sect->name = (char*)_strdup(name);
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

