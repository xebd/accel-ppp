#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include "triton.h"

#include "cli.h"
#include "cli_p.h"
#include "log.h"
#include "events.h"

#include "memdebug.h"

#define MAX_CMD_ITEMS 100
#define MSG_SYNTAX_ERROR "syntax error\r\n"
#define MSG_INVAL_ERROR "invalid argument\r\n"
#define MSG_UNKNOWN_CMD "command unknown\r\n"

char *conf_cli_passwd;
static const char *def_cli_prompt = "accel-ppp";
char *conf_cli_prompt;

static LIST_HEAD(simple_cmd_list);
static LIST_HEAD(regexp_cmd_list);

void __export cli_register_simple_cmd(struct cli_simple_cmd_t *cmd)
{
	list_add_tail(&cmd->entry, &simple_cmd_list);
}

void __export cli_register_simple_cmd2(
	int (*exec)(const char *cmd, char * const *fields, int fields_cnt, void *client),
	void (*help)(char * const *fields, int fields_cnt, void *client),
	int hdr_len,
	...
	)
{
	struct cli_simple_cmd_t *c;
	int i;
	va_list ap;

	va_start(ap, hdr_len);

	c = malloc(sizeof(*c));
	memset(c, 0, sizeof(*c));
	
	c->exec = exec;
	c->help = help;
	c->hdr_len = hdr_len;
	c->hdr = malloc(hdr_len * sizeof(void*));

	for (i = 0; i < hdr_len; i++)
		c->hdr[i] = va_arg(ap, char *);
	
	list_add_tail(&c->entry, &simple_cmd_list);

	va_end(ap);
}

void __export cli_register_regexp_cmd(struct cli_regexp_cmd_t *cmd)
{
	int err;
	cmd->re = pcre_compile2(cmd->pattern, cmd->options, &err, NULL, NULL, NULL);
	if (!cmd->re) {
		log_emerg("cli: failed to compile regexp %s: %i\n", cmd->pattern, err);
		_exit(EXIT_FAILURE);
	}
	list_add_tail(&cmd->entry, &simple_cmd_list);
}

int __export cli_send(void *client, const char *data)
{
	struct cli_client_t *cln = (struct cli_client_t *)client;

	return cln->send(cln, data, strlen(data));
}

int __export cli_sendv(void *client, const char *fmt, ...)
{
	struct cli_client_t *cln = (struct cli_client_t *)client;
	int r;

	va_list ap;
	va_start(ap, fmt);
	r = cln->sendv(cln, fmt, ap);
	va_end(ap);

	return r;
}


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

	ptr[0] = buf;

	for (i = 1; i <= MAX_CMD_ITEMS; i++) {
		buf = skip_word(buf);
		if (!*buf)
			return i;
		
		*buf = 0;
		
		buf = skip_space(buf + 1);
		if (!*buf)
			return i;

		ptr[i] = buf;
	}

	buf = skip_word(buf);
	*buf = 0;

	return i;
}

int __export cli_process_cmd(struct cli_client_t *cln)
{
	struct cli_simple_cmd_t *cmd1;
	struct cli_regexp_cmd_t *cmd2;
	char *f[MAX_CMD_ITEMS];
	int r, i, n, found = 0;

	n = split((char *)cln->cmdline, f);

	if (n >= 1 && !strcmp(f[0], "help")) {
		list_for_each_entry(cmd1, &simple_cmd_list, entry)
			if (cmd1->help)
				cmd1->help(f, n, cln);

		list_for_each_entry(cmd2, &regexp_cmd_list, entry)
			if (cmd2->help)
				cmd1->help(f, n, cln);

		return 0;
	}

	list_for_each_entry(cmd1, &simple_cmd_list, entry) {
		if (cmd1->hdr_len && n >= cmd1->hdr_len) {
			for (i = 0; i < cmd1->hdr_len; i++) {
				if (strcmp(cmd1->hdr[i], f[i]))
					break;
			}
			if (i < cmd1->hdr_len)
				continue;
			r = cmd1->exec((char *)cln->cmdline, f, n, cln);
			switch (r) {
				case CLI_CMD_EXIT:
					cln->disconnect(cln);
				case CLI_CMD_FAILED:
					return -1;
				case CLI_CMD_SYNTAX:
					cli_send(cln, MSG_SYNTAX_ERROR);
					return 0;
				case CLI_CMD_INVAL:
					cli_send(cln, MSG_INVAL_ERROR);
					return 0;
				case CLI_CMD_OK:
					found = 1;
			}
		}
	}

	list_for_each_entry(cmd2, &regexp_cmd_list, entry) {
		r = cmd2->exec((char *)cln->cmdline, cln);
		switch (r) {
			case CLI_CMD_EXIT:
				cln->disconnect(cln);
			case CLI_CMD_FAILED:
				return 0;
			case CLI_CMD_SYNTAX:
				cli_send(cln, MSG_SYNTAX_ERROR);
				return 0;
			case CLI_CMD_OK:
				found = 1;
		}
	}

	if (!found) {
		if (cli_send(cln, MSG_UNKNOWN_CMD))
			return -1;
	}

	return 0;
}

static void load_config(void)
{
	const char *opt;
	
	if (conf_cli_passwd)
		_free(conf_cli_passwd);
	opt = conf_get_opt("cli", "password");
	if (opt)
		conf_cli_passwd = _strdup(opt);
	else
		conf_cli_passwd = NULL;
	
	if (conf_cli_prompt && conf_cli_prompt != def_cli_prompt)
		_free(conf_cli_prompt);
	opt = conf_get_opt("cli", "prompt");
	if (opt)
		conf_cli_prompt = _strdup(opt);
	else
		conf_cli_prompt = (char *)def_cli_prompt;
}

static void init(void)
{
	load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);
}

DEFINE_INIT(10, init);
