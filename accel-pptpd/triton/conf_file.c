#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "conf_file.h"
#include "triton_p.h"

struct sect_t
{
	struct list_head entry;
	
	struct conf_file_sect_t *sect;
};

static LIST_HEAD(sections);

static char* skip_space(char *str);
static char* skip_word(char *str);

static struct conf_file_sect_t *find_sect(const char *name);
static struct conf_file_sect_t *create_sect(const char *name);
static void sect_add_item(struct conf_file_sect_t *sect,const char *name,const char *val);
static struct option_t *find_item(struct conf_file_sect_t *,const char *name);

void conf_file_load(const char *fname)
{
	char *buf,*str,*str2;
	char *path0,*path;
	int cur_line=0;
	static struct conf_file_sect_t *cur_sect=NULL;
	FILE *f=fopen(fname,"r");
	if (!f)
	{
		perror("triton: open conf file");
		return;
	}
	
	buf=(char*)malloc(1024);
	path0=(char*)malloc(4096);
	path=(char*)malloc(4096);
	
	getcwd(path0,1024);
	
	while(!feof(f))
	{
		buf=fgets(buf,1024,f);
		if (!buf) break;
		++cur_line;
		if (buf[strlen(buf)-1]=='\n')
			buf[strlen(buf)-1]=0;
		
		str=skip_space(buf);
		if (*str=='#' || *str==0) continue;
		if (strncmp(str,"$include",8)==0)
		{
			str=skip_word(str);
			str=skip_space(str);
			/*if (*str=='.')
			{
				strcpy(path,path0);
				strcat(path,str+1);
				str=path;
			}*/
			conf_file_load(str);
			continue;
		}
		if (*str=='[')
		{
			for (str2=++str; *str2 && *str2!=']'; str2++);
			if (*str2!=']')
			{
//L1:
				printf("triton: sintax error in conf file %s line %i\n",fname,cur_line);
				return;
			}
			*str2=0;
			cur_sect=find_sect(str);
			if (!cur_sect) cur_sect=create_sect(str);	
			continue;
		}
		if (!cur_sect)
		{
			printf("triton: no section opened in conf file %s line %i\n",fname,cur_line);
			return;
		}
		str2=skip_word(str);
		if (*str2==' ')
		{
			*str2=0;
			++str2;
		}
		str2=skip_space(str2);
		if (*str2=='=' || *str2==',')
		{
			*str2=0;
			str2=skip_space(str2+1);
			if (*str2 && *(str2+1) && *str2=='$' && *(str2+1)=='{')
			{
				char *s;
				struct option_t *opt;
				for (s=str2+2; *s && *s!='}'; s++);
				if (*s=='}')
				{
					*s=0;
					str2+=2;
				}
				opt=find_item(cur_sect,str2);
				if (!opt)
				{
					printf("triton: parent option not found int conf file %s line %i\n",fname,cur_line);
					return;
				}
				str2=opt->val;
			}
		}else str2=NULL;
		sect_add_item(cur_sect,str,str2);
	}
	
	free(buf);
	free(path);
	free(path0);
	fclose(f);
}

static char* skip_space(char *str)
{
	for (; *str && *str==' '; str++);
	return str;
}
static char* skip_word(char *str)
{
	for (; *str && (*str!=' ' && *str!='='); str++);
	return str;
}

static struct conf_file_sect_t *find_sect(const char *name)
{
	struct sect_t *s;
	list_for_each_entry(s,&sections,entry)
	{
		if (strcmp(s->sect->name,name)==0) return s->sect;
	}
	return NULL;
}

static struct conf_file_sect_t *create_sect(const char *name)
{
	struct sect_t *s=(struct sect_t *)malloc(sizeof(struct sect_t));
	
	s->sect=(struct conf_file_sect_t*)malloc(sizeof(struct conf_file_sect_t));
	s->sect->name=(char*)strdup(name);
	INIT_LIST_HEAD(&s->sect->items);
	
	list_add_tail(&s->entry,&sections);
	
	return s->sect;
}

static void sect_add_item(struct conf_file_sect_t *sect,const char *name,const char *val)
{
	struct option_t *opt=(struct option_t *)malloc(sizeof(struct option_t));
	
	opt->name=(char*)strdup(name);
	opt->val=val?(char*)strdup(val):NULL;
	
	list_add_tail(&opt->entry,&sect->items);
}

static struct option_t *find_item(struct conf_file_sect_t *sect,const char *name)
{
	struct option_t *opt;
	list_for_each_entry(opt,&sect->items,entry)
	{
		if (strcmp(opt->name,name)==0)
			return opt;
	}
	
	return NULL;
}

struct conf_file_sect_t *conf_file_get_section(const char *name)
{
	return find_sect(name);
}
