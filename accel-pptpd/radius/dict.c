#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "list.h"
#include "radius.h"
#include "log.h"


struct dict_value_t
{
	struct list_head entry;
	rad_value_t val;
	const char *name;
};

struct dict_attr_t
{
	struct list_head entry;
	const char *name;
	int id;
	int type;
	rad_value_t val;
	struct list_head values;
};

static char *skip_word(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr == ' ' || *ptr == '\t' || *ptr == '\n') 
			break;
	return ptr;
}
static char *skip_space(char *ptr)
{
	for(; *ptr; ptr++)
		if (*ptr != ' ' && *ptr != '\t')
			break;
	return ptr;
}
static int split(char *buf, char **ptr)
{
	int i;

	for (i = 0; i < 3; i++) {
		buf = skip_word(buf);
		if (!*buf)
			return -1;
		
		*buf = 0;
		
		buf = skip_space(buf + 1);
		if (!*buf)
			return -1;

		ptr[i] = buf;
	}

	buf = skip_word(buf);
	if (*buf == '\n')
		*buf = 0;
	else if (*buf)
		return -1;

	return 0;
}

struct dict_attr_t *find_attr(struct rad_dict_t *dict, const char *name)
{
	struct dict_attr_t *attr;

	list_for_each_entry(attr, &dict->items, entry)
		if (!strcmp(attr->name, name))
			return attr;

	return NULL;
}

#define BUF_SIZE 1024
void *rad_load_dict(const char *fname)
{
	FILE *f;
	char *buf, *ptr[3], *endptr;
	int n = 0;
	struct rad_dict_t *dict;
	struct dict_attr_t *attr;
	struct dict_value_t *val;
	
	f = fopen(fname, "r");
	if (!f) {
		log_error("radius: open dictioanary '%s': %s\n", fname, strerror(errno));
		return NULL;
	}
	
	buf = malloc(BUF_SIZE);
	if (!buf) {
		log_error("radius: out of memory\n");
		fclose(f);
		return NULL;
	}

	dict = malloc(sizeof(*dict));
	if (!dict) {
		log_error("radius: out of memory\n");
		fclose(f);
		free(buf);
		return NULL;
	}

	INIT_LIST_HEAD(&dict->items);
	
	while (fgets(buf, BUF_SIZE, f)) {
		n++;
		if (buf[0] == '#' || buf[0] == '\n' || buf[0] == 0)
			continue;
		if (split(buf, ptr)) {
			log_error("radius:%s:%i: syntaxis error\n", fname, n);
			goto out_err;
		}
		if (!strcmp(buf, "ATTRIBUTE")) {
			attr = malloc(sizeof(*attr));
			if (!attr) {
				log_error("radius: out of memory\n");
				goto out_err;
			}
			memset(attr, 0, sizeof(*attr));
			INIT_LIST_HEAD(&attr->values);
			list_add_tail(&attr->entry, &dict->items);
			attr->name = strdup(ptr[0]);
			attr->id = strtol(ptr[1], &endptr, 10);
			if (*endptr != 0) {
				log_error("radius:%s:%i: syntaxis error\n", fname, n);
				goto out_err;
			}
			if (!strcmp(ptr[2], "integer"))
				attr->type = ATTR_TYPE_INTEGER;
			else if (!strcmp(ptr[2], "string"))
				attr->type = ATTR_TYPE_STRING;
			else if (!strcmp(ptr[2], "date"))
				attr->type = ATTR_TYPE_DATE;
			else if (!strcmp(ptr[2], "ipaddr"))
				attr->type = ATTR_TYPE_IPADDR;
			else {
				log_error("radius:%s:%i: unknown attribute type\n", fname, n);
				goto out_err;
			}
		} else if (!strcmp(buf, "VALUE")) {
			attr = find_attr(dict, ptr[0]);
			if (!attr) {
				log_error("radius:%s:%i: unknown attribute\n", fname, n);
				goto out_err;
			}
			val = malloc(sizeof(*val));
			if (!val) {
				log_error("radius: out of memory\n");
				goto out_err;
			}
			memset(val, 0, sizeof(*val));
			list_add_tail(&val->entry, &attr->values);
			val->name = strdup(ptr[1]);
			switch (attr->type) {
				case ATTR_TYPE_INTEGER:
					val->val.integer = strtol(ptr[2], &endptr, 10);
					if (*endptr != 0) {
						log_error("radius:%s:%i: syntaxis error\n", fname, n);
						goto out_err;
					}
					break;
				case ATTR_TYPE_STRING:
					val->val.string = strdup(ptr[2]);
					break;
				case ATTR_TYPE_DATE:
					log_warn("radius:%s:%i: VALUE of type 'date' is not implemented yet\n", fname, n);
					break;
				case ATTR_TYPE_IPADDR:
					log_warn("radius:%s:%i: VALUE of type 'ipaddr' is not implemented yet\n", fname, n);
					break;
			}
		} else {
			log_error("radius:%s:%i: syntaxis error\n");
			goto out_err;
		}
	}

	free(buf);
	fclose(f);

	return dict;

out_err:
	rad_free_dict(dict);
	free(buf);
	fclose(f);
	return NULL;
}

void rad_free_dict(struct rad_dict_t *dict)
{
	struct dict_attr_t *attr;
	struct dict_value_t *val;

	while (!list_empty(&dict->items)) {
		attr = list_entry(dict->items.next, typeof(*attr), entry);
		while (!list_empty(&attr->values)) {
			val = list_entry(attr->values.next, typeof(*val), entry);
			list_del(&val->entry);
			free((char*)val->name);
			if (attr->type == ATTR_TYPE_STRING)
				free((char*)val->val.string);
			free(val);
		}
		list_del(&attr->entry);
		free((char*)attr->name);
		free(attr);
	}
	free(dict);
}

