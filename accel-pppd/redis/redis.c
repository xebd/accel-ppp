#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <aio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <hiredis/hiredis.h>
#include <json.h>

#include "log.h"
#include "events.h"
#include "ppp.h"
#include "spinlock.h"
#include "mempool.h"

#include "utils.h"
#include "memdebug.h"
#include "ipdb.h"

extern char** environ;

#define DEFAULT_REDIS_HOST    "localhost"
#define DEFAULT_REDIS_PORT     6379
#define DEFAULT_REDIS_PUBCHAN "accel-ppp"

enum ap_redis_events_t {
	REDIS_EV_SES_STARTING         = 0x00000001,
	REDIS_EV_SES_STARTED          = 0x00000002,
	REDIS_EV_SES_FINISHING        = 0x00000004,
	REDIS_EV_SES_FINISHED         = 0x00000008,
	REDIS_EV_SES_AUTHORIZED       = 0x00000010,
	REDIS_EV_CTRL_STARTING        = 0x00000020,
	REDIS_EV_CTRL_STARTED         = 0x00000040,
	REDIS_EV_CTRL_FINISHED        = 0x00000080,
	REDIS_EV_SES_PRE_UP           = 0x00000100,
	REDIS_EV_SES_ACCT_START       = 0x00000200,
	REDIS_EV_CONFIG_RELOAD        = 0x00000400,
	REDIS_EV_SES_AUTH_FAILED      = 0x00000800,
	REDIS_EV_SES_PRE_FINISHED     = 0x00001000,
	REDIS_EV_IP_CHANGED           = 0x00002000,
	REDIS_EV_SHAPER               = 0x00004000,
	REDIS_EV_MPPE_KEYS            = 0x00008000,
	REDIS_EV_DNS                  = 0x00010000,
	REDIS_EV_WINS                 = 0x00020000,
	REDIS_EV_FORCE_INTERIM_UPDATE = 0x00040000,
	REDIS_EV_RADIUS_ACCESS_ACCEPT = 0x00080000,
	REDIS_EV_RADIUS_COA           = 0x00100000,
};

enum ap_redis_session_t {
	REDIS_SES_CTRL_TYPE_PPTP      = 1,
	REDIS_SES_CTRL_TYPE_L2TP      = 2,
	REDIS_SES_CTRL_TYPE_PPPOE     = 3,
	REDIS_SES_CTRL_TYPE_IPOE      = 4,
	REDIS_SES_CTRL_TYPE_OPENVPN   = 5,
	REDIS_SES_CTRL_TYPE_SSTP      = 6,
};

enum ap_redis_flags_t {
	REDIS_FLAG_KEEP_BG_THREAD_RUNNING = 0x00000001,
	REDIS_FLAG_BG_THREAD_IS_RUNNING   = 0x00000002,
};

struct ap_redis_msg_t {
	struct list_head entry;
	int event;
	int ses_ctrl_type;
	char* calling_station_id;
	char* called_station_id;
	char* name;
	char* chan_name;
	char* username;
	char* ip_addr;
	char* sessionid;
	int pppoe_sessionid;
	char* ctrl_ifname;
};

struct ap_redis_t {
        mempool_t *msg_pool;
	struct list_head entry;
	struct list_head msg_queue;
	spinlock_t msg_queue_lock;
	int need_free:1;
	int queued:1;
	struct ap_redis_pd_t *lpd;

	/* eventfd file descriptor */
	int evfd;

	/* dedicated thread for running redis main loop */
	pthread_t thread;
	/* thread return value */
	int thread_exit_code;
	/* flags */
	uint32_t flags;

	/* redis host */
	char* host;
	/* redis port */
	uint16_t port;
	/* redis channel (publish) */
	char* pubchan;

	char* pathname;
	uint32_t events;
};

struct ap_redis_pd_t {
	struct ap_private pd;
	struct ap_redis_t lf;
	unsigned long tmp;
};


static struct ap_redis_t *ap_redis;

static mempool_t redis_pool;


static void ap_redis_dequeue(struct ap_redis_t* ap_redis, redisContext* ctx)
{
	spin_lock(&ap_redis->msg_queue_lock);

	while (!list_empty(&ap_redis->msg_queue)) {

		struct ap_redis_msg_t* msg = list_first_entry(&(ap_redis->msg_queue), typeof(*msg), entry);
		list_del(&msg->entry);

		json_object* jobj = json_object_new_object();
		json_object* jstring;

		/* event type */
		switch (msg->event) {
		case REDIS_EV_SES_STARTING:             jstring = json_object_new_string("session-starting");       break;
		case REDIS_EV_SES_STARTED:              jstring = json_object_new_string("session-started");        break;
		case REDIS_EV_SES_FINISHING:		jstring = json_object_new_string("session-finishing");      break;
		case REDIS_EV_SES_FINISHED:             jstring = json_object_new_string("session-finished");       break;
		case REDIS_EV_SES_AUTHORIZED:		jstring = json_object_new_string("session-authorized");     break;
		case REDIS_EV_CTRL_STARTING:		jstring = json_object_new_string("control-starting");       break;
		case REDIS_EV_CTRL_STARTED:             jstring = json_object_new_string("control-started");        break;
		case REDIS_EV_CTRL_FINISHED:		jstring = json_object_new_string("control-finished");       break;
		case REDIS_EV_SES_PRE_UP:               jstring = json_object_new_string("session-pre-up");         break;
		case REDIS_EV_SES_ACCT_START:           jstring = json_object_new_string("session-acct-start");     break;
		case REDIS_EV_CONFIG_RELOAD:            jstring = json_object_new_string("config-reload");          break;
		case REDIS_EV_SES_AUTH_FAILED:          jstring = json_object_new_string("session-auth-failed");    break;
		case REDIS_EV_SES_PRE_FINISHED:         jstring = json_object_new_string("session-pre-finished");   break;
		case REDIS_EV_IP_CHANGED:               jstring = json_object_new_string("ip-changed");             break;
		case REDIS_EV_SHAPER:                   jstring = json_object_new_string("shaper");                 break;
		case REDIS_EV_MPPE_KEYS:                jstring = json_object_new_string("mppe-keys");              break;
		case REDIS_EV_DNS:                      jstring = json_object_new_string("dns");                    break;
		case REDIS_EV_WINS:                     jstring = json_object_new_string("wins");                   break;
		case REDIS_EV_FORCE_INTERIM_UPDATE:     jstring = json_object_new_string("force-interim-update");   break;
		case REDIS_EV_RADIUS_ACCESS_ACCEPT:     jstring = json_object_new_string("radius-access-accept");   break;
		case REDIS_EV_RADIUS_COA:               jstring = json_object_new_string("coa");                    break;
		default:                                jstring = json_object_new_string("unknown");                break;
		}
		json_object_object_add(jobj, "event", jstring);

		/* session ctrl type */
		switch (msg->ses_ctrl_type) {
		case REDIS_SES_CTRL_TYPE_PPTP:    jstring = json_object_new_string("pptp");    break;
		case REDIS_SES_CTRL_TYPE_L2TP:    jstring = json_object_new_string("l2tp");    break;
		case REDIS_SES_CTRL_TYPE_PPPOE:   jstring = json_object_new_string("pppoe");   break;
		case REDIS_SES_CTRL_TYPE_IPOE:    jstring = json_object_new_string("ipoe");    break;
		case REDIS_SES_CTRL_TYPE_OPENVPN: jstring = json_object_new_string("openvpn"); break;
		case REDIS_SES_CTRL_TYPE_SSTP:    jstring = json_object_new_string("sstp");    break;
		default: {};
		}
		json_object_object_add(jobj, "ctrl_type", jstring);

		/* session channel name */
		if (msg->chan_name)
			json_object_object_add(jobj, "channel_name", json_object_new_string(msg->chan_name));

		/* session id */
		if (msg->sessionid)
			json_object_object_add(jobj, "session_id", json_object_new_string(msg->sessionid));

		/* called_station_id */
		if (msg->called_station_id)
			json_object_object_add(jobj, "called_station_id", json_object_new_string(msg->called_station_id));

		/* calling_station_id */
		if (msg->calling_station_id)
			json_object_object_add(jobj, "calling_station_id", json_object_new_string(msg->calling_station_id));

		/* name */
		if (msg->name)
			json_object_object_add(jobj, "name", json_object_new_string(msg->name));

		/* username */
		if (msg->username)
			json_object_object_add(jobj, "username", json_object_new_string(msg->username));

		/* ip_addr */
		if (msg->ip_addr)
			json_object_object_add(jobj, "ip_addr", json_object_new_string(msg->ip_addr));

          /* pppoe_sessionid */
		if (msg->pppoe_sessionid)
			json_object_object_add(jobj, "pppoe_sessionid", json_object_new_int(msg->pppoe_sessionid));

		/* ctrl_ifname */
		if (msg->ctrl_ifname)
			json_object_object_add(jobj, "ctrl_ifname", json_object_new_string(msg->ctrl_ifname));

          // TODO: send msg to redis instance
		redisReply* reply;
		reply = redisCommand(ctx, "PUBLISH %s %s", ap_redis->pubchan, json_object_to_json_string(jobj));

		if (reply) {
			// TODO
		}

		/* delete json object */
		json_object_put(jobj);

		/* release strings pointed to by message */
		if (msg->chan_name)
			free(msg->chan_name);
		if (msg->sessionid)
			free(msg->sessionid);
		if (msg->called_station_id)
			free(msg->called_station_id);
		if (msg->calling_station_id)
			free(msg->calling_station_id);
		if (msg->name)
			free(msg->name);
		if (msg->username)
			free(msg->username);
		if (msg->ip_addr)
			free(msg->ip_addr);
		if (msg->ctrl_ifname)
			free(msg->ctrl_ifname);

		mempool_free(msg);
	}

	spin_unlock(&ap_redis->msg_queue_lock);
}


static void* ap_redis_thread(void* arg)
{
	if (!arg) {
	    return NULL;
	}
	struct ap_redis_t* ap_redis = (struct ap_redis_t*)arg;
	ap_redis->thread_exit_code = -1;

	/* establish connection to redis server */
	redisContext *ctx;
	ctx = redisConnect(ap_redis->host, ap_redis->port);
	if ((ctx == NULL) || (ctx->err)) {
		if (ctx) {
			log_error("ap_redis: redisConnect failed: (%s)\n", ctx->errstr);
		} else {
			log_error("ap_redis: failed to allocate redis context\n");
		}
		return &(ap_redis->thread_exit_code);
	}

	/* create epoll device */
	int epfd;
	if ((epfd = epoll_create(1)) < 0) {
		log_error("ap_redis: epoll_create failed: %d (%s)\n", errno, strerror(errno));
		return &(ap_redis->thread_exit_code);
	}

	/* add eventfd to epoll device */
	int rc;
	struct epoll_event epev[32];
	memset(epev, 0, sizeof(epev));
	epev[0].events = EPOLLIN;
	epev[0].data.fd = ap_redis->evfd;
	if ((rc = epoll_ctl(epfd, EPOLL_CTL_ADD, ap_redis->evfd, epev)) < 0) {
		log_error("ap_redis: epoll_ctl failed: %d (%s)\n", errno, strerror(errno));
		return &(ap_redis->thread_exit_code);
	}

	ap_redis->thread_exit_code = 0;
	ap_redis->flags |= REDIS_FLAG_BG_THREAD_IS_RUNNING;
	ap_redis->flags |= REDIS_FLAG_KEEP_BG_THREAD_RUNNING;

	while (ap_redis->flags & REDIS_FLAG_KEEP_BG_THREAD_RUNNING) {

		if ((rc = epoll_pwait(epfd, epev, 32, /*timeout=*/10, NULL)) == 0) {
			/* no events, just loop and continue waiting */
			continue;
		} else if (rc == -1) {
			/* log error event, loop and continue waiting */
			log_error("ap_redis: epoll_ctl failed: %d (%s)\n", errno, strerror(errno));
			continue;
		}

		for (unsigned int i = 0; i < 32; i++) {
			if (epev[i].data.fd == ap_redis->evfd) {
				ap_redis_dequeue(ap_redis, ctx);
			}
		}
	}

	ap_redis->flags &= ~REDIS_FLAG_BG_THREAD_IS_RUNNING;

	/* close epoll device */
	close(epfd);

	/* release redis context */
	redisFree(ctx);

	return &(ap_redis->thread_exit_code);
}


static void ap_redis_init(struct ap_redis_t *ap_redis)
{
	spinlock_init(&ap_redis->msg_queue_lock);
	INIT_LIST_HEAD(&ap_redis->msg_queue);
	ap_redis->thread = (pthread_t)0;
	ap_redis->thread_exit_code = 0;
	ap_redis->flags = 0;
	ap_redis->pathname = NULL;
	ap_redis->events = (REDIS_EV_SES_AUTHORIZED | REDIS_EV_SES_PRE_FINISHED);
	ap_redis->msg_pool = mempool_create(sizeof(struct ap_redis_msg_t));
	if (NULL == ap_redis->msg_pool) {
		log_error("ap_redis: mempool creation failed\n");
		return;
	}
	memset(ap_redis->msg_pool, 0, sizeof(*(ap_redis->msg_pool)));
}

static int ap_redis_open(struct ap_redis_t *ap_redis)
{
	char* opt;

	if ((ap_redis->evfd = eventfd(0, 0)) < 0) {
		log_error("ap_redis: eventfd failed: %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	ap_redis->events = 0;

	if (((opt = conf_get_opt("redis", "host")) != NULL))
		ap_redis->host = _strdup(opt);
	else
		ap_redis->host = _strdup(DEFAULT_REDIS_HOST);
	if (((opt = conf_get_opt("redis", "port")) != NULL))
		ap_redis->port = strtol(opt, NULL, 0);
	else
		ap_redis->port = DEFAULT_REDIS_PORT;
	if (((opt = conf_get_opt("redis", "pubchan")) != NULL))
		ap_redis->pubchan = _strdup(opt);
	else
		ap_redis->pubchan = _strdup(DEFAULT_REDIS_PUBCHAN);

	if (((opt = conf_get_opt("redis", "ev_ses_starting")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_STARTING;
	if (((opt = conf_get_opt("redis", "ev_ses_finishing")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_FINISHING;
	if (((opt = conf_get_opt("redis", "ev_ses_finished")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_FINISHED;
	if (((opt = conf_get_opt("redis", "ev_ses_authorized")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_AUTHORIZED;
	if (((opt = conf_get_opt("redis", "ev_ctrl_starting")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CTRL_STARTING;
	if (((opt = conf_get_opt("redis", "ev_ctrl_started")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CTRL_STARTED;
	if (((opt = conf_get_opt("redis", "ev_ctrl_finished")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CTRL_FINISHED;
	if (((opt = conf_get_opt("redis", "ev_ses_pre_up")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_PRE_UP;
	if (((opt = conf_get_opt("redis", "ev_ses_acct_start")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_ACCT_START;
	if (((opt = conf_get_opt("redis", "ev_config_reload")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_CONFIG_RELOAD;
	if (((opt = conf_get_opt("redis", "ev_ses_auth_failed")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_AUTH_FAILED;
	if (((opt = conf_get_opt("redis", "ev_ses_pre_finished")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SES_PRE_FINISHED;
	if (((opt = conf_get_opt("redis", "ev_ip_changed")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_IP_CHANGED;
	if (((opt = conf_get_opt("redis", "ev_shaper")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_SHAPER;
	if (((opt = conf_get_opt("redis", "ev_mppe_keys")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_MPPE_KEYS;
	if (((opt = conf_get_opt("redis", "ev_dns")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_DNS;
	if (((opt = conf_get_opt("redis", "ev_wins")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_WINS;
	if (((opt = conf_get_opt("redis", "ev_force_interim_update")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_FORCE_INTERIM_UPDATE;
	if (((opt = conf_get_opt("redis", "ev_radius_access_accept")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_RADIUS_ACCESS_ACCEPT;
	if (((opt = conf_get_opt("redis", "ev_radius_coa")) != NULL) && (strcmp(opt, "yes") == 0))
		ap_redis->events |= REDIS_EV_RADIUS_COA;


	if (pthread_create(&(ap_redis->thread), NULL, &ap_redis_thread, ap_redis) < 0) {
		log_emerg("ap_redis: unable to create background thread %d (%s)\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}


static void ap_redis_enqueue(struct ap_session *ses, const int event)
{
	char tmp_addr[128];
	uint64_t num = 1;
	int nbytes;

	/* redis background thread not running? => return */
	if (!(ap_redis->flags & REDIS_FLAG_BG_THREAD_IS_RUNNING)) {
		return;
	}

	switch (event) {
	case REDIS_EV_SES_STARTING:
	case REDIS_EV_SES_STARTED:
	case REDIS_EV_SES_FINISHING:
	case REDIS_EV_SES_FINISHED:
	case REDIS_EV_SES_AUTHORIZED:
	case REDIS_EV_CTRL_STARTING:
	case REDIS_EV_CTRL_STARTED:
	case REDIS_EV_CTRL_FINISHED:
	case REDIS_EV_SES_PRE_UP:
	case REDIS_EV_SES_ACCT_START:
	case REDIS_EV_CONFIG_RELOAD:
	case REDIS_EV_SES_AUTH_FAILED:
	case REDIS_EV_SES_PRE_FINISHED:
	case REDIS_EV_IP_CHANGED:
	case REDIS_EV_SHAPER:
	case REDIS_EV_MPPE_KEYS:
	case REDIS_EV_DNS:
	case REDIS_EV_WINS:
	case REDIS_EV_FORCE_INTERIM_UPDATE:
	case REDIS_EV_RADIUS_ACCESS_ACCEPT:
	case REDIS_EV_RADIUS_COA: {
		/* do nothing */
	} break;
	default: {
		return;
	};
	}

	struct ap_redis_msg_t* msg = mempool_alloc(ap_redis->msg_pool);
	if (!msg) {
		log_error("ap_redis_enqueue: out of memory\n");
		return;
	}
	memset(msg, 0, sizeof(*msg));

	/* get IP address*/
	memset(tmp_addr, 0, sizeof(tmp_addr));
	if (ses && ses->ipv4 && ses->ipv4->peer_addr) {
		u_inet_ntoa(ses->ipv4->peer_addr,tmp_addr);
	}

	msg->event = event;
        if (ses->chan_name)
            msg->chan_name = _strdup(ses->chan_name);
        if (ses->sessionid)
            msg->sessionid = _strdup(ses->sessionid);
        if (ses->ctrl->called_station_id)
            msg->called_station_id = _strdup(ses->ctrl->called_station_id);
        if (ses->ctrl->calling_station_id)
            msg->calling_station_id = _strdup(ses->ctrl->calling_station_id);
        if (ses->ctrl->name)
            msg->name = _strdup(ses->ctrl->name);
        if (ses->username)
            msg->username = _strdup(ses->username);
        if (ses->conn_pppoe_sid)
            msg->pppoe_sessionid = ses->conn_pppoe_sid;
        if (ses->ctrl->ifname)
            msg->ctrl_ifname = ses->ctrl->ifname;

        msg->ip_addr = _strdup(tmp_addr);

	switch(ses->ctrl->type) {
	case CTRL_TYPE_PPTP:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_PPTP;    break;
	case CTRL_TYPE_L2TP:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_L2TP;    break;
	case CTRL_TYPE_PPPOE:   msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_PPPOE;   break;
	case CTRL_TYPE_IPOE:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_IPOE;    break;
	case CTRL_TYPE_OPENVPN: msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_OPENVPN; break;
	case CTRL_TYPE_SSTP:    msg->ses_ctrl_type = REDIS_SES_CTRL_TYPE_SSTP;    break;
	default:{
	}
	}

	spin_lock(&ap_redis->msg_queue_lock);
	list_add_tail(&(msg->entry), &(ap_redis->msg_queue));
	spin_unlock(&ap_redis->msg_queue_lock);

	/* notify redis background thread */
	if ((nbytes = write(ap_redis->evfd, &num, sizeof(num))) != sizeof(num)) {
		log_error("ap_redis_enqueue: failed to send event via eventfd\n");
	}
}


static void ev_ses_starting(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_STARTING);
}

static void ev_ses_started(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_STARTED);
}

static void ev_ses_finishing(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_FINISHING);
}

static void ev_ses_finished(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_FINISHED);
}

static void ev_ses_authorized(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_AUTHORIZED);
}

static void ev_ctrl_starting(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_CTRL_STARTING);
}

static void ev_ctrl_started(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_CTRL_STARTED);
}

static void ev_ctrl_finished(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_CTRL_FINISHED);
}

static void ev_ses_pre_up(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_PRE_UP);
}

static void ev_ses_acct_start(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_ACCT_START);
}

static void ev_ses_auth_failed(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_AUTH_FAILED);
}

static void ev_ses_pre_finished(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_SES_PRE_FINISHED);
}

static void ev_radius_access_accept(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_RADIUS_ACCESS_ACCEPT);
}

static void ev_radius_coa(struct ap_session *ses)
{
	ap_redis_enqueue(ses, REDIS_EV_RADIUS_COA);
}


static void init(void)
{
	redis_pool = mempool_create(sizeof(struct ap_redis_t));

	ap_redis = mempool_alloc(redis_pool);
	if (NULL == ap_redis) {
		log_error("ap_redis_init: out of memory\n");
		return;
	}
	memset(ap_redis, 0, sizeof(struct ap_redis_t));

	ap_redis_init(ap_redis);

	if (ap_redis_open(ap_redis)) {
		free(ap_redis);
		_exit(EXIT_FAILURE);
	}

	if (ap_redis->events & REDIS_EV_SES_STARTING)
		triton_event_register_handler(EV_SES_STARTING, (triton_event_func)ev_ses_starting);
	if (ap_redis->events & REDIS_EV_SES_STARTED)
	        triton_event_register_handler(EV_SES_STARTED, (triton_event_func)ev_ses_started);
	if (ap_redis->events & REDIS_EV_SES_FINISHING)
		triton_event_register_handler(EV_SES_FINISHING, (triton_event_func)ev_ses_finishing);
	if (ap_redis->events & REDIS_EV_SES_FINISHED)
		triton_event_register_handler(EV_SES_FINISHED, (triton_event_func)ev_ses_finished);
	if (ap_redis->events & REDIS_EV_SES_AUTHORIZED)
		triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized);
	if (ap_redis->events & REDIS_EV_CTRL_STARTING)
		triton_event_register_handler(EV_CTRL_STARTING, (triton_event_func)ev_ctrl_starting);
	if (ap_redis->events & REDIS_EV_CTRL_STARTED)
		triton_event_register_handler(EV_CTRL_STARTED, (triton_event_func)ev_ctrl_started);
	if (ap_redis->events & REDIS_EV_CTRL_FINISHED)
		triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);
	if (ap_redis->events & REDIS_EV_SES_PRE_UP)
		triton_event_register_handler(EV_SES_PRE_UP, (triton_event_func)ev_ses_pre_up);
	if (ap_redis->events & REDIS_EV_SES_ACCT_START)
		triton_event_register_handler(EV_SES_ACCT_START, (triton_event_func)ev_ses_acct_start);
	if (ap_redis->events & REDIS_EV_SES_AUTH_FAILED)
		triton_event_register_handler(EV_SES_AUTH_FAILED, (triton_event_func)ev_ses_auth_failed);
	if (ap_redis->events & REDIS_EV_SES_PRE_FINISHED)
		triton_event_register_handler(EV_SES_PRE_FINISHED, (triton_event_func)ev_ses_pre_finished);
	if (ap_redis->events & REDIS_EV_RADIUS_ACCESS_ACCEPT)
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
	if (ap_redis->events & REDIS_EV_RADIUS_COA)
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
}

DEFINE_INIT(1, init);
