#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <postgresql/libpq-fe.h>

#include "triton.h"
#include "spinlock.h"
#include "log.h"
#include "list.h"
#include "ppp.h"

static char *conf_conninfo;
static int conf_queue_max = 1000;
static char *conf_query;
#define QUERY_TEMPLATE "insert into %s (timestamp, username, sessionid, msg) values ($1, $2, $3, $4)"

static void start_connect(void);
static void start_connect_timer(struct triton_timer_t *);

static struct triton_context_t pgsql_ctx;
static struct triton_md_handler_t pgsql_hnd;
static struct triton_timer_t connect_timer = {
	.period = 5000,
	.expire = start_connect_timer,
};

static PGconn *conn;

static LIST_HEAD(msg_queue);
static int queue_size;
static int sleeping = 0;
static spinlock_t queue_lock = SPINLOCK_INITIALIZER;
static char *log_buf;

static void unpack_msg(struct log_msg_t *msg)
{
	struct log_chunk_t *chunk;
	int pos = 0;

	list_for_each_entry(chunk, msg->chunks, entry) {
		memcpy(log_buf + pos, chunk->msg, chunk->len);
		pos += chunk->len;
	}
	if (pos > 1)
		log_buf[pos - 1] = 0;
	else
		log_buf[0] = 0;
}

static void set_hdr(struct log_msg_t *msg)
{
	struct tm tm;

	localtime_r(&msg->timestamp.tv_sec, &tm);

	strftime(msg->hdr->msg, LOG_CHUNK_SIZE, "%Y-%m-%d %H:%M:%S", &tm);
	msg->hdr->len = strlen(msg->hdr->msg);
}

static void write_next_msg(void)
{
	struct log_msg_t *msg;
	struct ppp_t *ppp;
	const char *paramValues[4];
	int paramFormats[4] = {0, 0, 0, 0};

	spin_lock(&queue_lock);
	if (!list_empty(&msg_queue)) {
		msg = list_entry(msg_queue.next, typeof(*msg), entry);
		list_del(&msg->entry);
		--queue_size;
		spin_unlock(&queue_lock);

		set_hdr(msg);
		unpack_msg(msg);

		ppp = msg->tpd;
		if (ppp) {
			paramValues[1] = ppp->username;
			paramValues[2] = ppp->sessionid;
		} else {
			paramValues[1] = NULL;
			paramValues[2] = NULL;
		}
		
		paramValues[0] = msg->hdr->msg;
		paramValues[3] = log_buf;

		PQsendQueryParams(conn, conf_query, 4, NULL, paramValues, NULL, paramFormats, 0);
		PQflush(conn);
		log_free_msg(msg);
		return;
	}
	sleeping = 1;
	spin_unlock(&queue_lock);
}

static int pgsql_check_ready(struct triton_md_handler_t *h)
{
	PGresult *res;

	if (!PQconsumeInput(conn)) {
		log_emerg("log_pgsql: %s\n", PQerrorMessage(conn));
		if (PQstatus(conn) == CONNECTION_BAD) {
			PQfinish(conn);
			start_connect();
		}
	}

	if (PQisBusy(conn))
		return 0;

	while (1) {
		res = PQgetResult(conn);
		if (!res)
			break;
		if (PQresultStatus(res) != PGRES_COMMAND_OK)
			log_emerg("log_pgsql: %s\n", PQerrorMessage(conn));
		PQclear(res);
	}

	write_next_msg();

	return 0;
}

static int pgsql_flush(struct triton_md_handler_t *h)
{
	PQflush(conn);
	return 0;
}

static void wakeup_log(void)
{
	write_next_msg();
}

static void queue_log(struct log_msg_t *msg)
{
	int r = 0;
	spin_lock(&queue_lock);
	if (queue_size < conf_queue_max) {
		list_add_tail(&msg->entry, &msg_queue);
		++queue_size;
		r = sleeping;
		sleeping = 0;
	}
	spin_unlock(&queue_lock);

	if (r)
		triton_context_call(&pgsql_ctx, (void (*)(void*))wakeup_log, NULL);
}


static void general_log(struct log_msg_t *msg)
{
	msg->tpd = NULL;
	queue_log(msg);
}

static void session_log(struct ppp_t *ppp, struct log_msg_t *msg)
{
	msg->tpd = ppp;
	queue_log(msg);
}

static int wait_connect(struct triton_md_handler_t *h)
{
	PostgresPollingStatusType status = PQconnectPoll(conn);
	char *err_msg;

	switch(status) {
		case PGRES_POLLING_READING:
			triton_md_enable_handler(h, MD_MODE_READ);
			triton_md_disable_handler(h, MD_MODE_WRITE);
			break;
		case PGRES_POLLING_WRITING:
			triton_md_enable_handler(h, MD_MODE_WRITE);
			triton_md_disable_handler(h, MD_MODE_READ);
			break;
		case PGRES_POLLING_FAILED:
			err_msg = PQerrorMessage(conn);
			log_emerg("log_pgsql: %s\n", err_msg);
			triton_md_disable_handler(h, MD_MODE_READ | MD_MODE_WRITE);
			PQfinish(conn);
			h->read = NULL;
			h->write = NULL;
			if (!connect_timer.tpd)
				triton_timer_add(&pgsql_ctx, &connect_timer, 0);
			break;
		case PGRES_POLLING_OK:
			//triton_md_disable_handler(h, MD_MODE_READ | MD_MODE_WRITE);
			PQsetnonblocking(conn, 1);
			h->write = pgsql_flush;
			h->read = pgsql_check_ready;
			triton_md_enable_handler(&pgsql_hnd, MD_MODE_READ | MD_MODE_WRITE);
			wakeup_log();
			break;
		default:
			break;
	}
	return 0;
}

static void start_connect(void)
{
	conn = PQconnectStart(conf_conninfo);
	if (!conn) {
		log_emerg("log_pgsql: out of memory\n");
		return;
	}

	if (PQstatus(conn) == CONNECTION_BAD) {
		log_emerg("log_pgsql: PQconnectStart failed\n");
	}

	pgsql_hnd.fd = PQsocket(conn);
	pgsql_hnd.read = wait_connect;
	pgsql_hnd.write = wait_connect;

	wait_connect(&pgsql_hnd);
}

static void start_connect_timer(struct triton_timer_t *t)
{
	triton_timer_del(t);
	start_connect();
}

static struct log_target_t target = {
	.log = general_log,
	.session_log = session_log,
};

static void __init init(void)
{
	char *opt;

	opt = conf_get_opt("log-pgsql", "conninfo");
	if (!opt)
		return;
	conf_conninfo = opt;

	opt = conf_get_opt("log-pgsql", "connect-inteval");
	if (opt && atoi(opt) > 0)
		connect_timer.period = atoi(opt) * 1000;
	
	opt = conf_get_opt("log-pgsql", "log-query");
	if (opt)
		conf_query = opt;
	else {
		opt = conf_get_opt("log-pgsql", "log-table");
		if (!opt || strlen(opt) > 32)
			opt = "log";
		conf_query = malloc(sizeof(QUERY_TEMPLATE) + strlen(opt));
		sprintf(conf_query, QUERY_TEMPLATE, opt);
	}

	log_buf = malloc(LOG_MAX_SIZE + 1);
	if (!log_buf) {
		log_emerg("log_pgsql: out of memory\n");
		return;
	}

	triton_context_register(&pgsql_ctx, NULL);
	triton_md_register_handler(&pgsql_ctx, &pgsql_hnd);

	start_connect();

	log_register_target(&target);
}
