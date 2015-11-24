#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "conf_file.h"

struct conf_ctx {
	const char *fname;
	FILE *file;
	int line;
	struct conf_opt **list;
	int options:1;
};

static struct conf_sect *sect_head;
static struct conf_sect *sect_tail;

static char* skip_space(char *str);
static char* skip_word(char *str);

static struct conf_sect *find_sect(const char *name);
static struct conf_sect *create_sect(const char *name);
static int sect_add_item(struct conf_ctx *ctx, const char *name, char *val, char *raw);
static struct conf_opt *find_item(struct conf_sect *, const char *name);
static int load_file(struct conf_ctx *ctx);

static char *buf;
static struct conf_sect *cur_sect;

static int open_ctx(struct conf_ctx *ctx, const char *fname, struct conf_opt **list)
{
	ctx->file = fopen(fname, "r");
	if (!ctx->file)
		return -1;

	ctx->fname = fname;
	ctx->line = 0;
	ctx->list = ctx->list;
	ctx->options = 0;

	return 0;
}

static void close_ctx(struct conf_ctx *ctx)
{
	fclose(ctx->file);
}

static int load_file(struct conf_ctx *ctx)
{
	char *str, *str2, *raw;
	int len;

	while(1) {
		if (!fgets(buf, 1024, ctx->file))
			break;
		ctx->line++;

		len = strlen(buf);
		if (buf[len - 1] == '\n')
			buf[--len] = 0;

		while (len && (buf[len - 1] == ' ' || buf[len - 1] == '\t'))
			buf[--len] = 0;

		str = skip_space(buf);
		if (*str == '#' || *str == 0)
			continue;

		if (strncmp(str, "$include", 8) == 0)	{
			struct conf_ctx ctx1;
			int r;
			str = skip_word(str);
			str = skip_space(str);

			if (open_ctx(&ctx1, str, ctx->list))
				break;

			r = load_file(&ctx1);

			close_ctx(&ctx1);

			if (r)
				break;

			ctx->list = ctx1.list;

			continue;
		}

		if (*str == '[') {
			for (str2 = ++str; *str2 && *str2 != ']'; str2++);
			if (*str2 != ']') {
				fprintf(stderr, "conf_file:%s:%i: sintax error\n", ctx->fname, ctx->line);
				return -1;
			}

			if (ctx->options) {
				fprintf(stderr, "conf_file:%s:%i: cann't open section inside option\n", ctx->fname, ctx->line);
				return -1;
			}

			*str2 = 0;
			cur_sect = find_sect(str);
			if (!cur_sect)
				cur_sect = create_sect(str);
			ctx->list = (struct conf_opt **)&cur_sect->opt;
			continue;
		}

		if (!cur_sect) {
			fprintf(stderr, "conf_file:%s:%i: no section opened\n", ctx->fname, ctx->line);
			return -1;
		}

		if (*str == '}') {
			if (ctx->options)
				return 0;

			fprintf(stderr, "conf_file:%s:%i: sintax error\n", ctx->fname, ctx->line);
			return -1;
		}

		raw = strdup(str);
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
				struct conf_opt *opt;
				for (s = str2 + 2; *s && *s != '}'; s++);
				if (*s == '}') {
					*s = 0;
					str2 += 2;
				}
				opt = find_item(cur_sect, str2);
				if (!opt) {
					fprintf(stderr, "conf_file:%s:%i: parent option not found\n", ctx->fname, ctx->line);
					return -1;
				}
				str2 = (char *)opt->val;
			}
		} else
			str2 = NULL;

		if (sect_add_item(ctx, str, str2, raw))
			return -1;
	}

	return 0;
}

/*static void print_items(struct list_head *items, int dep)
{
	struct conf_option_t *opt;
	int i;

	list_for_each_entry(opt, items, entry) {
		for (i = 0; i < dep; i++)
			printf("\t");
		printf("%s=%s\n", opt->name, opt->val);
		print_items(&opt->items, dep + 1);
	}
}

static void print_conf()
{
	struct sect_t *s;

	list_for_each_entry(s, &sections, entry) {
		printf("[%s]\n", s->sect->name);
		print_items(&s->sect->items, 0);
	}
}*/

static void free_items(struct conf_opt *opt)
{
	struct conf_opt *next;

	for (next = opt->next; opt; opt = next) {
		if (opt->child)
			free_items(opt->child);
		free(opt->name);
		free(opt->raw);
		if (opt->val)
			free(opt->val);
		free((void *)opt);
	}
}

static void conf_clear(struct conf_sect *s)
{
	struct conf_sect *next;

	for (next = s->next; s; s = next) {
		if (s->opt)
			free_items(s->opt);
		free(s->name);
		free((void *)s);
	}
}

int conf_file_load(const char *fname)
{
	struct conf_sect *head = sect_head;
	struct conf_ctx ctx;
	int r;

	if (open_ctx(&ctx, fname, NULL))
		return -1;

	cur_sect = NULL;
	sect_head = NULL;

	buf = malloc(1024);

	r = load_file(&ctx);

	free(buf);

	close_ctx(&ctx);

	if (r)
		sect_head = head;
	else
		conf_clear(head);

	return r;
}

static char* skip_space(char *str)
{
	for (; *str && (*str == ' ' || *str == '\t'); str++);
	return str;
}

static char* skip_word(char *str)
{
	for (; *str && (*str != ' ' && *str != '\t' && *str != '='); str++);
	return str;
}

static struct conf_sect *find_sect(const char *name)
{
	struct conf_sect *s;

	for (s = sect_head; s; s = s->next) {
		if (strcmp(s->name, name) == 0)
			return s;
	}

	return NULL;
}

static struct conf_sect *create_sect(const char *name)
{
	struct conf_sect *s = malloc(sizeof(struct conf_sect));

	s->name = strdup(name);
	s->next = NULL;
	s->opt = NULL;

	if (!sect_head)
		sect_head = s;
	else
		sect_tail->next = s;

	sect_tail = s;

	return s;
}

static int sect_add_item(struct conf_ctx *ctx, const char *name, char *val, char *raw)
{
	struct conf_opt *opt = malloc(sizeof(struct conf_opt));
	int r = 0;
	int chld = 0;

	if (val) {
		int len = strlen(val);
		if (val[len - 1] == '{') {
			chld = 1;
			val[--len] = 0;

			while (--len >= 0 && (val[len] == ' ' || val[len] == '\t'));

			if (len >= 0)
				val[len + 1] = 0;
			else
				val = NULL;
		}
	}

	opt->name = strdup(name);
	opt->val = val ? strdup(val) : NULL;
	opt->raw = raw;
	opt->next = NULL;
	opt->child = NULL;

	*ctx->list = opt;
	ctx->list = &opt->next;

	if (chld) {
		struct conf_opt **list = ctx->list;
		ctx->list = &opt->child;
		ctx->options = 1;
		r = load_file(ctx);
		ctx->options = 0;
		ctx->list = list;
	}

	return r;
}

static struct conf_opt *find_item(struct conf_sect *sect, const char *name)
{
	struct conf_opt *opt;

	for (opt = sect->opt; opt; opt = opt->next) {
		if (strcmp(opt->name, name) == 0)
			return opt;
	}

	return NULL;
}

struct conf_sect* conf_get_sect(const char *name)
{
	return find_sect(name);
}

const char *conf_get_opt(const char *sect, const char *name)
{
	struct conf_opt *opt;
	struct conf_sect *s = conf_get_sect(sect);

	if (!s)
		return NULL;

	opt = find_item(s, name);
	if (!opt)
		return NULL;

	return opt->val;
}

