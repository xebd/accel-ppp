#ifndef __CLI_H
#define __CLI_H

#include <pcre.h>
#include <list.h>

#define CLI_CMD_OK 0
#define CLI_CMD_FAILED -1
#define CLI_CMD_EXIT -2
#define CLI_CMD_SYNTAX 1
#define CLI_CMD_INVAL 2

struct cli_simple_cmd_t
{
	struct list_head entry;
	int hdr_len;
	const char **hdr;
	int (*exec)(const char *cmd, char * const *fields, int fields_cnt, void *client);
	void (*help)(char * const *fields, int field_cnt, void *client);
};

struct cli_regexp_cmd_t
{
	struct list_head entry;
	pcre *re;
	const char *pattern;
	int options;
	int (*exec)(const char *cmd, void *client);
	int (*help)(char * const *fields, int field_cnt, void *client);
};

void cli_register_simple_cmd(struct cli_simple_cmd_t *cmd);
void cli_register_simple_cmd2(
	int (*exec)(const char *cmd, char * const *fields, int fields_cnt, void *client),
	void (*help)(char * const *fields, int fields_cnt, void *client),
	int hdr_len,
	...
	);
void cli_register_regexp_cmd(struct cli_regexp_cmd_t *cmd);

int cli_send(void *client, const char *data);
int cli_sendv(void *client, const char *fmt, ...);

#endif

