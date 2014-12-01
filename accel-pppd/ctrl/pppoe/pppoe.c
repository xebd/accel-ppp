#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <printf.h>

#include "crypto.h"

#include "events.h"
#include "triton.h"
#include "log.h"
#include "ppp.h"
#include "mempool.h"
#include "cli.h"

#ifdef RADIUS
#include "radius.h"
#endif

#include "iputils.h"
#include "connlimit.h"

#include "pppoe.h"

#include "memdebug.h"

#define SID_MAX 65536

struct pppoe_conn_t {
	struct list_head entry;
	struct triton_context_t ctx;
	struct pppoe_serv_t *serv;
	int disc_sock;
	uint16_t sid;
	uint8_t addr[ETH_ALEN];
	int ppp_started:1;

	struct pppoe_tag *relay_sid;
	struct pppoe_tag *host_uniq;
	struct pppoe_tag *service_name;
	struct pppoe_tag *tr101;
	uint8_t cookie[COOKIE_LENGTH - 4];

	struct ap_ctrl ctrl;
	struct ppp_t ppp;
#ifdef RADIUS
	struct rad_plugin_t radius;
#endif
};

struct delayed_pado_t
{
	struct list_head entry;
	struct triton_timer_t timer;
	struct pppoe_serv_t *serv;
	uint8_t addr[ETH_ALEN];
	struct pppoe_tag *host_uniq;
	struct pppoe_tag *relay_sid;
	struct pppoe_tag *service_name;
};

struct padi_t
{
	struct list_head entry;
	struct timespec ts;
	uint8_t addr[ETH_ALEN];
};

struct iplink_arg
{
	pcre *re;
	const char *opt;
	void *cli;
};

int conf_verbose;
char *conf_service_name;
char *conf_ac_name;
int conf_ifname_in_sid;
char *conf_pado_delay;
int conf_tr101 = 1;
int conf_padi_limit = 0;
int conf_mppe = MPPE_UNSET;
int conf_sid_uppercase = 0;
static const char *conf_ip_pool;
enum {CSID_MAC, CSID_IFNAME, CSID_IFNAME_MAC};
static int conf_called_sid;
static int conf_cookie_timeout;

static mempool_t conn_pool;
static mempool_t pado_pool;
static mempool_t padi_pool;

unsigned int stat_starting;
unsigned int stat_active;
unsigned int stat_delayed_pado;
unsigned long stat_PADI_recv;
unsigned long stat_PADI_drop;
unsigned long stat_PADO_sent;
unsigned long stat_PADR_recv;
unsigned long stat_PADR_dup_recv;
unsigned long stat_PADS_sent;
unsigned int total_padi_cnt;
unsigned long stat_filtered;

pthread_rwlock_t serv_lock = PTHREAD_RWLOCK_INITIALIZER;
LIST_HEAD(serv_list);
static int connlimit_loaded;

static pthread_mutex_t sid_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long *sid_map;
static unsigned long *sid_ptr;
static int sid_idx;

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void pppoe_send_PADT(struct pppoe_conn_t *conn);
static void _server_stop(struct pppoe_serv_t *serv);
void pppoe_server_free(struct pppoe_serv_t *serv);
static int init_secret(struct pppoe_serv_t *serv);
static void __pppoe_server_start(const char *ifname, const char *opt, void *cli);

static void disconnect(struct pppoe_conn_t *conn)
{
	if (conn->ppp_started) {
		dpado_check_prev(__sync_fetch_and_sub(&stat_active, 1));
		conn->ppp_started = 0;
		ap_session_terminate(&conn->ppp.ses, TERM_USER_REQUEST, 1);
	}

	pppoe_send_PADT(conn);

	close(conn->disc_sock);

	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp.ses);

	log_ppp_info1("disconnected\n");

	pthread_mutex_lock(&conn->serv->lock);
	list_del(&conn->entry);
	conn->serv->conn_cnt--;
	if (conn->serv->stopping && conn->serv->conn_cnt == 0) {
		pthread_mutex_unlock(&conn->serv->lock);
		pppoe_server_free(conn->serv);
	} else
		pthread_mutex_unlock(&conn->serv->lock);

	pthread_mutex_lock(&sid_lock);
	sid_map[conn->sid/(8*sizeof(long))] |= 1 << (conn->sid % (8*sizeof(long)));
	pthread_mutex_unlock(&sid_lock);

	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);
	_free(conn->service_name);
	if (conn->host_uniq)
		_free(conn->host_uniq);
	if (conn->relay_sid)
		_free(conn->relay_sid);
	if (conn->tr101)
		_free(conn->tr101);

	triton_context_unregister(&conn->ctx);

	mempool_free(conn);
}

static void ppp_started(struct ap_session *ses)
{
	log_ppp_debug("pppoe: ppp started\n");
}

static void ppp_finished(struct ap_session *ses)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct pppoe_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_ppp_debug("pppoe: ppp finished\n");

	if (conn->ppp_started) {
		dpado_check_prev(__sync_fetch_and_sub(&stat_active, 1));
		conn->ppp_started = 0;
		triton_context_call(&conn->ctx, (triton_event_func)disconnect, conn);
	}
}

static void pppoe_conn_close(struct triton_context_t *ctx)
{
	struct pppoe_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	if (conn->ppp_started)
		ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 0);
	else
		disconnect(conn);
}

#ifdef RADIUS
static int pppoe_rad_send_access_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct pppoe_conn_t *conn = container_of(rad, typeof(*conn), radius);

	if (conn->tr101)
		return tr101_send_access_request(conn->tr101, pack);

	return 0;
}

static int pppoe_rad_send_accounting_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct pppoe_conn_t *conn = container_of(rad, typeof(*conn), radius);

	if (conn->tr101)
		return tr101_send_accounting_request(conn->tr101, pack);

	return 0;
}
#endif

static struct pppoe_conn_t *allocate_channel(struct pppoe_serv_t *serv, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name, const struct pppoe_tag *tr101, const uint8_t *cookie)
{
	struct pppoe_conn_t *conn;
	unsigned long *old_sid_ptr;

	conn = mempool_alloc(conn_pool);
	if (!conn) {
		log_error("pppoe: out of memory\n");
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));

	pthread_mutex_lock(&sid_lock);
	old_sid_ptr = sid_ptr;
	while (1) {
		int bit = ffsl(*sid_ptr) - 1;

		if (bit != -1) {
			conn->sid = sid_idx*8*sizeof(long) + bit;
			*sid_ptr &= ~(1lu << bit);
		}

		if (++sid_idx == SID_MAX/8/sizeof(long)) {
			sid_ptr = sid_map;
			sid_idx = 0;
		} else
			sid_ptr++;

		if (bit != -1)
			break;

		if (sid_ptr == old_sid_ptr)
			break;
	}
	pthread_mutex_unlock(&sid_lock);

	if (!conn->sid) {
		log_warn("pppoe: no free sid available\n");
		mempool_free(conn);
		return NULL;
	}

	conn->serv = serv;
	memcpy(conn->addr, addr, ETH_ALEN);

	if (host_uniq) {
		conn->host_uniq = _malloc(sizeof(*host_uniq) + ntohs(host_uniq->tag_len));
		memcpy(conn->host_uniq, host_uniq, sizeof(*host_uniq) + ntohs(host_uniq->tag_len));
	}

	if (relay_sid) {
		conn->relay_sid = _malloc(sizeof(*relay_sid) + ntohs(relay_sid->tag_len));
		memcpy(conn->relay_sid, relay_sid, sizeof(*relay_sid) + ntohs(relay_sid->tag_len));
	}

	if (tr101) {
		conn->tr101 = _malloc(sizeof(*tr101) + ntohs(tr101->tag_len));
		memcpy(conn->tr101, tr101, sizeof(*tr101) + ntohs(tr101->tag_len));
	}

	conn->service_name = _malloc(sizeof(*service_name) + ntohs(service_name->tag_len));
	memcpy(conn->service_name, service_name, sizeof(*service_name) + ntohs(service_name->tag_len));

	memcpy(conn->cookie, cookie, COOKIE_LENGTH - 4);

	conn->ctx.before_switch = log_switch;
	conn->ctx.close = pppoe_conn_close;
	conn->ctrl.ctx = &conn->ctx;
	conn->ctrl.started = ppp_started;
	conn->ctrl.finished = ppp_finished;
	conn->ctrl.terminate = ppp_terminate;
	conn->ctrl.max_mtu = MAX_PPPOE_MTU;
	conn->ctrl.type = CTRL_TYPE_PPPOE;
	conn->ctrl.ppp = 1;
	conn->ctrl.name = "pppoe";
	conn->ctrl.mppe = conf_mppe;

	if (conf_called_sid == CSID_IFNAME)
		conn->ctrl.called_station_id = _strdup(serv->ifname);
	else if (conf_called_sid == CSID_IFNAME_MAC) {
		conn->ctrl.called_station_id = _malloc(IFNAMSIZ + 19);
		if (conf_sid_uppercase)
		    sprintf(conn->ctrl.called_station_id, "%s:%02X:%02X:%02X:%02X:%02X:%02X", serv->ifname,
			serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);
		else
		    sprintf(conn->ctrl.called_station_id, "%s:%02x:%02x:%02x:%02x:%02x:%02x", serv->ifname,
			serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);

	} else {
		conn->ctrl.called_station_id = _malloc(IFNAMSIZ + 19);
		if (conf_ifname_in_sid == 2 || conf_ifname_in_sid == 3)
			if (conf_sid_uppercase)
			    sprintf(conn->ctrl.called_station_id, "%s:%02X:%02X:%02X:%02X:%02X:%02X", serv->ifname,
				serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);
			else
			    sprintf(conn->ctrl.called_station_id, "%s:%02x:%02x:%02x:%02x:%02x:%02x", serv->ifname,
				serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);

		else
			if (conf_sid_uppercase)
			    sprintf(conn->ctrl.called_station_id, "%02X:%02X:%02X:%02X:%02X:%02X",
				serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);
			else
			    sprintf(conn->ctrl.called_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
				serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);

	}

	conn->ctrl.calling_station_id = _malloc(IFNAMSIZ + 19);

	if (conf_ifname_in_sid == 1 || conf_ifname_in_sid == 3)
		if (conf_sid_uppercase)
		    sprintf(conn->ctrl.calling_station_id, "%s:%02X:%02X:%02X:%02X:%02X:%02X", serv->ifname,
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		else
		    sprintf(conn->ctrl.calling_station_id, "%s:%02x:%02x:%02x:%02x:%02x:%02x", serv->ifname,
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	else
		if (conf_sid_uppercase)
		    sprintf(conn->ctrl.calling_station_id, "%02X:%02X:%02X:%02X:%02X:%02X",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		else
		    sprintf(conn->ctrl.calling_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	ppp_init(&conn->ppp);

	conn->ppp.ses.ctrl = &conn->ctrl;
	conn->ppp.ses.chan_name = conn->ctrl.calling_station_id;

	if (conf_ip_pool)
		conn->ppp.ses.ipv4_pool_name = _strdup(conf_ip_pool);

	conn->disc_sock = dup(serv->hnd.fd);

	triton_context_register(&conn->ctx, &conn->ppp.ses);

	pthread_mutex_lock(&serv->lock);
	list_add_tail(&conn->entry, &serv->conn_list);
	serv->conn_cnt++;
	pthread_mutex_unlock(&serv->lock);

	return conn;
}

static void connect_channel(struct pppoe_conn_t *conn)
{
	int sock;
	struct sockaddr_pppox sp;

	triton_event_fire(EV_CTRL_STARTING, &conn->ppp.ses);
	triton_event_fire(EV_CTRL_STARTED, &conn->ppp.ses);

	sock = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
	if (!sock) {
		log_error("pppoe: socket(PPPOX): %s\n", strerror(errno));
		goto out_err;
	}

	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	memset(&sp, 0, sizeof(sp));

	sp.sa_family = AF_PPPOX;
	sp.sa_protocol = PX_PROTO_OE;
	sp.sa_addr.pppoe.sid = htons(conn->sid);
	strcpy(sp.sa_addr.pppoe.dev, conn->serv->ifname);
	memcpy(sp.sa_addr.pppoe.remote, conn->addr, ETH_ALEN);

	if (connect(sock, (struct sockaddr *)&sp, sizeof(sp))) {
		log_error("pppoe: connect: %s\n", strerror(errno));
		goto out_err_close;
	}

	conn->ppp.fd = sock;

	if (establish_ppp(&conn->ppp))
		goto out_err_close;

#ifdef RADIUS
	if (conn->tr101 && triton_module_loaded("radius")) {
		conn->radius.send_access_request = pppoe_rad_send_access_request;
		conn->radius.send_accounting_request = pppoe_rad_send_accounting_request;
		rad_register_plugin(&conn->ppp.ses, &conn->radius);
	}
#endif

	conn->ppp_started = 1;

	dpado_check_next(__sync_add_and_fetch(&stat_active, 1));

	return;

out_err_close:
	close(sock);
out_err:
	disconnect(conn);
}

static struct pppoe_conn_t *find_channel(struct pppoe_serv_t *serv, const uint8_t *cookie)
{
	struct pppoe_conn_t *conn;

	list_for_each_entry(conn, &serv->conn_list, entry) {
		if (!memcmp(conn->cookie, cookie, COOKIE_LENGTH - 4))
			return conn;
	}

	return NULL;
}

static void print_tag_string(struct pppoe_tag *tag)
{
	int i;

	for (i = 0; i < ntohs(tag->tag_len); i++)
		log_info2("%c", tag->tag_data[i]);
}

static void print_tag_octets(struct pppoe_tag *tag)
{
	int i;

	for (i = 0; i < ntohs(tag->tag_len); i++)
		log_info2("%02x", (uint8_t)tag->tag_data[i]);
}

static void print_packet(uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	int n;

	log_info2("[PPPoE ");

	switch (hdr->code) {
		case CODE_PADI:
			log_info2("PADI");
			break;
		case CODE_PADO:
			log_info2("PADO");
			break;
		case CODE_PADR:
			log_info2("PADR");
			break;
		case CODE_PADS:
			log_info2("PADS");
			break;
		case CODE_PADT:
			log_info2("PADT");
			break;
	}

	log_info2(" %02x:%02x:%02x:%02x:%02x:%02x => %02x:%02x:%02x:%02x:%02x:%02x",
		ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2], ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5],
		ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5]);

	log_info2(" sid=%04x", ntohs(hdr->sid));

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				log_info2(" <End-Of-List>");
				break;
			case TAG_SERVICE_NAME:
				log_info2(" <Service-Name ");
				print_tag_string(tag);
				log_info2(">");
				break;
			case TAG_AC_NAME:
				log_info2(" <AC-Name ");
				print_tag_string(tag);
				log_info2(">");
				break;
			case TAG_HOST_UNIQ:
				log_info2(" <Host-Uniq ");
				print_tag_octets(tag);
				log_info2(">");
				break;
			case TAG_AC_COOKIE:
				log_info2(" <AC-Cookie ");
				print_tag_octets(tag);
				log_info2(">");
				break;
			case TAG_VENDOR_SPECIFIC:
				if (ntohs(tag->tag_len) < 4)
					log_info2(" <Vendor-Specific invalid>");
				else
					log_info2(" <Vendor-Specific %x>", ntohl(*(uint32_t *)tag->tag_data));
				break;
			case TAG_RELAY_SESSION_ID:
				log_info2(" <Relay-Session-Id");
				print_tag_octets(tag);
				log_info2(">");
				break;
			case TAG_SERVICE_NAME_ERROR:
				log_info2(" <Service-Name-Error>");
				break;
			case TAG_AC_SYSTEM_ERROR:
				log_info2(" <AC-System-Error>");
				break;
			case TAG_GENERIC_ERROR:
				log_info2(" <Generic-Error>");
				break;
			default:
				log_info2(" <Unknown (%x)>", ntohs(tag->tag_type));
				break;
		}
	}

	log_info2("]\n");
}

static void generate_cookie(struct pppoe_serv_t *serv, const uint8_t *src, uint8_t *cookie, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid)
{
	MD5_CTX ctx;
	DES_cblock key;
	DES_key_schedule ks;
	int i;
	union {
		DES_cblock b[3];
		uint8_t raw[24];
	} u1, u2;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memcpy(key, serv->hwaddr, 6);
	key[6] = src[4];
	key[7] = src[5];
	DES_set_key(&key, &ks);

	MD5_Init(&ctx);
	MD5_Update(&ctx, serv->secret, SECRET_LENGTH);
	MD5_Update(&ctx, serv->hwaddr, ETH_ALEN);
	MD5_Update(&ctx, src, ETH_ALEN);
	if (relay_sid)
		MD5_Update(&ctx, relay_sid->tag_data, ntohs(relay_sid->tag_len));
	MD5_Final(u1.raw, &ctx);

	if (host_uniq) {
		uint8_t buf[16];
		MD5_Init(&ctx);
		MD5_Update(&ctx, serv->secret, SECRET_LENGTH);
		MD5_Update(&ctx, host_uniq->tag_data, ntohs(host_uniq->tag_len));
		MD5_Final(buf, &ctx);
		for (i = 0; i < 4; i++)
			u1.raw[16 + i] = buf[i] ^ buf[i + 4] ^ buf[i + 8] ^ buf[i + 12];
	} else
		memset(u1.raw + 16, 0, 4);

	*(uint32_t *)(u1.raw + 20) = ts.tv_sec + conf_cookie_timeout;

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u1.b[i], &u2.b[i], &ks, DES_ENCRYPT);

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u2.b[i], &u1.b[i], &serv->des_ks, DES_ENCRYPT);

	memcpy(cookie, u1.raw, 24);
}

static int check_cookie(struct pppoe_serv_t *serv, const uint8_t *src, const uint8_t *cookie, const struct pppoe_tag *relay_sid)
{
	MD5_CTX ctx;
	DES_cblock key;
	DES_key_schedule ks;
	int i;
	union {
		DES_cblock b[3];
		uint8_t raw[24];
	} u1, u2;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memcpy(key, serv->hwaddr, 6);
	key[6] = src[4];
	key[7] = src[5];
	DES_set_key(&key, &ks);

	memcpy(u1.raw, cookie, 24);

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u1.b[i], &u2.b[i], &serv->des_ks, DES_DECRYPT);

	for (i = 0; i < 3; i++)
		DES_ecb_encrypt(&u2.b[i], &u1.b[i], &ks, DES_DECRYPT);

	if (*(uint32_t *)(u1.raw + 20) < ts.tv_sec)
		return 1;

	MD5_Init(&ctx);
	MD5_Update(&ctx, serv->secret, SECRET_LENGTH);
	MD5_Update(&ctx, serv->hwaddr, ETH_ALEN);
	MD5_Update(&ctx, src, ETH_ALEN);
	if (relay_sid)
		MD5_Update(&ctx, relay_sid->tag_data, ntohs(relay_sid->tag_len));
	MD5_Final(u2.raw, &ctx);

	return memcmp(u1.raw, u2.raw, 16);
}

static void setup_header(uint8_t *pack, const uint8_t *src, const uint8_t *dst, int code, uint16_t sid)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

	memcpy(ethhdr->h_source, src, ETH_ALEN);
	memcpy(ethhdr->h_dest, dst, ETH_ALEN);
	ethhdr->h_proto = htons(ETH_P_PPP_DISC);

	hdr->ver = 1;
	hdr->type = 1;
	hdr->code = code;
	hdr->sid = htons(sid);
	hdr->length = 0;
}

static void add_tag(uint8_t *pack, int type, const uint8_t *data, int len)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));

	tag->tag_type = htons(type);
	tag->tag_len = htons(len);
	memcpy(tag->tag_data, data, len);

	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + len);
}

static void add_tag2(uint8_t *pack, const struct pppoe_tag *t)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length));

	memcpy(tag, t, sizeof(*t) + ntohs(t->tag_len));

	hdr->length = htons(ntohs(hdr->length) + sizeof(*tag) + ntohs(t->tag_len));
}

static void pppoe_send(int fd, const uint8_t *pack)
{
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n, s;

	s = ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length);
	n = write(fd, pack, s);
	if (n < 0 )
		log_error("pppoe: write: %s\n", strerror(errno));
	else if (n != s) {
		log_warn("pppoe: short write %i/%i\n", n,s);
	}
}

static void pppoe_send_PADO(struct pppoe_serv_t *serv, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	uint8_t pack[ETHER_MAX_LEN];
	uint8_t cookie[COOKIE_LENGTH];

	setup_header(pack, serv->hwaddr, addr, CODE_PADO, 0);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));
	if (conf_service_name)
		add_tag(pack, TAG_SERVICE_NAME, (uint8_t *)conf_service_name, strlen(conf_service_name));

	if (service_name)
		add_tag2(pack, service_name);

	generate_cookie(serv, addr, cookie, host_uniq, relay_sid);

	add_tag(pack, TAG_AC_COOKIE, cookie, COOKIE_LENGTH);

	if (host_uniq)
		add_tag2(pack, host_uniq);

	if (relay_sid)
		add_tag2(pack, relay_sid);

	if (conf_verbose) {
		log_info2("send ");
		print_packet(pack);
	}

	__sync_add_and_fetch(&stat_PADO_sent, 1);
	pppoe_send(serv->hnd.fd, pack);
}

static void pppoe_send_err(struct pppoe_serv_t *serv, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, int code, int tag_type)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, serv->hwaddr, addr, code, 0);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));
	add_tag(pack, tag_type, NULL, 0);

	if (host_uniq)
		add_tag2(pack, host_uniq);

	if (relay_sid)
		add_tag2(pack, relay_sid);

	if (conf_verbose) {
		log_info2("send ");
		print_packet(pack);
	}

	pppoe_send(serv->hnd.fd, pack);
}

static void pppoe_send_PADS(struct pppoe_conn_t *conn)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, conn->serv->hwaddr, conn->addr, CODE_PADS, conn->sid);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));

	add_tag2(pack, conn->service_name);

	if (conn->host_uniq)
		add_tag2(pack, conn->host_uniq);

	if (conn->relay_sid)
		add_tag2(pack, conn->relay_sid);

	if (conf_verbose) {
		log_info2("send ");
		print_packet(pack);
	}

	__sync_add_and_fetch(&stat_PADS_sent, 1);
	pppoe_send(conn->disc_sock, pack);
}

static void pppoe_send_PADT(struct pppoe_conn_t *conn)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, conn->serv->hwaddr, conn->addr, CODE_PADT, conn->sid);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));

	add_tag2(pack, conn->service_name);

	if (conn->relay_sid)
		add_tag2(pack, conn->relay_sid);

	if (conf_verbose) {
		log_info2("send ");
		print_packet(pack);
	}

	pppoe_send(conn->disc_sock, pack);
}

static void free_delayed_pado(struct delayed_pado_t *pado)
{
	triton_timer_del(&pado->timer);

	__sync_sub_and_fetch(&stat_delayed_pado, 1);
	list_del(&pado->entry);

	if (pado->host_uniq)
		_free(pado->host_uniq);
	if (pado->relay_sid)
		_free(pado->relay_sid);
	if (pado->service_name)
		_free(pado->service_name);

	mempool_free(pado);
}

static void pado_timer(struct triton_timer_t *t)
{
	struct delayed_pado_t *pado = container_of(t, typeof(*pado), timer);

	if (!ap_shutdown)
		pppoe_send_PADO(pado->serv, pado->addr, pado->host_uniq, pado->relay_sid, pado->service_name);

	free_delayed_pado(pado);
}

static int check_padi_limit(struct pppoe_serv_t *serv, uint8_t *addr)
{
	struct padi_t *padi;
	struct timespec ts;

	if (serv->padi_limit == 0)
		goto connlimit_check;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	while (!list_empty(&serv->padi_list)) {
		padi = list_entry(serv->padi_list.next, typeof(*padi), entry);
		if ((ts.tv_sec - padi->ts.tv_sec) * 1000 + (ts.tv_nsec - padi->ts.tv_nsec) / 1000000 > 1000) {
			list_del(&padi->entry);
			mempool_free(padi);
			serv->padi_cnt--;
			__sync_sub_and_fetch(&total_padi_cnt, 1);
		} else
			break;
	}

	if (serv->padi_cnt == serv->padi_limit)
		return -1;

	if (conf_padi_limit && total_padi_cnt >= conf_padi_limit)
		return -1;

	list_for_each_entry(padi, &serv->padi_list, entry) {
		if (memcmp(padi->addr, addr, ETH_ALEN) == 0)
			return -1;
	}

	padi = mempool_alloc(padi_pool);
	if (!padi)
		return -1;

	padi->ts = ts;
	memcpy(padi->addr, addr, ETH_ALEN);
	list_add_tail(&padi->entry, &serv->padi_list);
	serv->padi_cnt++;

	__sync_add_and_fetch(&total_padi_cnt, 1);

connlimit_check:
	if (connlimit_loaded && connlimit_check(cl_key_from_mac(addr)))
		return -1;

	return 0;
}

static void pppoe_recv_PADI(struct pppoe_serv_t *serv, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	int len, n, service_match = 0;
	struct delayed_pado_t *pado;
	struct timespec ts;

	__sync_add_and_fetch(&stat_PADI_recv, 1);

	if (ap_shutdown || pado_delay == -1)
		return;

	if (check_padi_limit(serv, ethhdr->h_source)) {
		__sync_add_and_fetch(&stat_PADI_drop, 1);
		if (conf_verbose) {
			clock_gettime(CLOCK_MONOTONIC, &ts);
			if (ts.tv_sec - 60 >= serv->last_padi_limit_warn) {
				log_warn("pppoe: discarding overlimit PADI packets on interface %s\n", serv->ifname);
				serv->last_padi_limit_warn = ts.tv_sec;
			}
		}
		return;
	}

	if (hdr->sid)
		return;

	len = ntohs(hdr->length);
	for (n = 0; n < len; n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		if (n + sizeof(*tag) + ntohs(tag->tag_len) > len)
			return;
		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				break;
			case TAG_SERVICE_NAME:
				if (conf_service_name && tag->tag_len) {
					if (ntohs(tag->tag_len) != strlen(conf_service_name))
						break;
					if (memcmp(tag->tag_data, conf_service_name, ntohs(tag->tag_len)))
						break;
					service_match = 1;
				} else {
					service_name_tag = tag;
					service_match = 1;
				}
				break;
			case TAG_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case TAG_RELAY_SESSION_ID:
				relay_sid_tag = tag;
				break;
		}
	}

	if (conf_verbose) {
		log_info2("recv ");
		print_packet(pack);
	}

	if (!service_match) {
		if (conf_verbose)
			log_warn("pppoe: discarding PADI packet (Service-Name mismatch)\n");
		return;
	}

	if (pado_delay) {
		list_for_each_entry(pado, &serv->pado_list, entry) {
			if (memcmp(pado->addr, ethhdr->h_source, ETH_ALEN))
				continue;
			if (conf_verbose)
				log_warn("pppoe: discarding PADI packet (already queued)\n");
			return;
		}
		pado = mempool_alloc(pado_pool);
		memset(pado, 0, sizeof(*pado));
		pado->serv = serv;
		memcpy(pado->addr, ethhdr->h_source, ETH_ALEN);

		if (host_uniq_tag) {
			pado->host_uniq = _malloc(sizeof(*host_uniq_tag) + ntohs(host_uniq_tag->tag_len));
			memcpy(pado->host_uniq, host_uniq_tag, sizeof(*host_uniq_tag) + ntohs(host_uniq_tag->tag_len));
		}

		if (relay_sid_tag) {
			pado->relay_sid = _malloc(sizeof(*relay_sid_tag) + ntohs(relay_sid_tag->tag_len));
			memcpy(pado->relay_sid, relay_sid_tag, sizeof(*relay_sid_tag) + ntohs(relay_sid_tag->tag_len));
		}

		if (service_name_tag) {
			pado->service_name = _malloc(sizeof(*service_name_tag) + ntohs(service_name_tag->tag_len));
			memcpy(pado->service_name, service_name_tag, sizeof(*service_name_tag) + ntohs(service_name_tag->tag_len));
		}

		pado->timer.expire = pado_timer;
		pado->timer.period = pado_delay;

		triton_timer_add(&serv->ctx, &pado->timer, 0);

		list_add_tail(&pado->entry, &serv->pado_list);
		__sync_add_and_fetch(&stat_delayed_pado, 1);
	} else
		pppoe_send_PADO(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);
}

static void pppoe_recv_PADR(struct pppoe_serv_t *serv, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *ac_cookie_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	struct pppoe_tag *tr101_tag = NULL;
	int n, service_match = 0;
	struct pppoe_conn_t *conn;
	int vendor_id;

	__sync_add_and_fetch(&stat_PADR_recv, 1);

	if (ap_shutdown)
		return;

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN)) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR (destination address is broadcast)\n");
		return;
	}

	if (hdr->sid) {
		if (conf_verbose)
			log_warn("pppoe: discarding PADR packet (sid is not zero)\n");
		return;
	}

	if (conf_verbose) {
		log_info2("recv ");
		print_packet(pack);
	}

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);

		if (n + sizeof(*tag) > ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: discard PADR packet (truncated tag)\n");
			return;
		}
		if (n + sizeof(*tag) + ntohs(tag->tag_len) > ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: discard PADR packet (invalid tag length)\n");
			return;
		}
		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				break;
			case TAG_SERVICE_NAME:
				service_name_tag = tag;
				if (tag->tag_len == 0)
					service_match = 1;
				else if (conf_service_name) {
					if (ntohs(tag->tag_len) != strlen(conf_service_name))
						break;
					if (memcmp(tag->tag_data, conf_service_name, ntohs(tag->tag_len)))
						break;
					service_match = 1;
				} else {
					service_match = 1;
				}
				break;
			case TAG_HOST_UNIQ:
				host_uniq_tag = tag;
				break;
			case TAG_AC_COOKIE:
				ac_cookie_tag = tag;
				break;
			case TAG_RELAY_SESSION_ID:
				relay_sid_tag = tag;
				break;
			case TAG_VENDOR_SPECIFIC:
				if (ntohs(tag->tag_len) < 4)
					continue;
				vendor_id = ntohl(*(uint32_t *)tag->tag_data);
				if (vendor_id == VENDOR_ADSL_FORUM)
					if (conf_tr101)
						tr101_tag = tag;
				break;
		}
	}

	if (!ac_cookie_tag) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (no AC-Cookie tag present)\n");
		return;
	}

	if (ntohs(ac_cookie_tag->tag_len) != COOKIE_LENGTH) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (incorrect AC-Cookie tag length)\n");
		return;
	}

	if (check_cookie(serv, ethhdr->h_source, (uint8_t *)ac_cookie_tag->tag_data, relay_sid_tag)) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (incorrect AC-Cookie)\n");
		return;
	}

	if (!service_match) {
		if (conf_verbose)
			log_warn("pppoe: Service-Name mismatch\n");
		pppoe_send_err(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, CODE_PADS, TAG_SERVICE_NAME_ERROR);
		return;
	}

	pthread_mutex_lock(&serv->lock);
	conn = find_channel(serv, (uint8_t *)ac_cookie_tag->tag_data);
	if (conn && !conn->ppp.ses.username) {
		__sync_add_and_fetch(&stat_PADR_dup_recv, 1);
		pppoe_send_PADS(conn);
	}
	pthread_mutex_unlock(&serv->lock);

	if (conn)
		return;

	conn = allocate_channel(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag, tr101_tag, (uint8_t *)ac_cookie_tag->tag_data);
	if (!conn)
		pppoe_send_err(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, CODE_PADS, TAG_AC_SYSTEM_ERROR);
	else {
		pppoe_send_PADS(conn);
		triton_context_call(&conn->ctx, (triton_event_func)connect_channel, conn);
		triton_context_wakeup(&conn->ctx);
	}
}

static void pppoe_recv_PADT(struct pppoe_serv_t *serv, uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_conn_t *conn;
	uint16_t sid = ntohs(hdr->sid);

	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN)) {
		if (conf_verbose)
			log_warn("pppoe: discard PADT (destination address is broadcast)\n");
		return;
	}

	if (conf_verbose) {
		log_info2("recv ");
		print_packet(pack);
	}

	pthread_mutex_lock(&serv->lock);
	list_for_each_entry(conn, &serv->conn_list, entry) {
		if (conn->sid == sid) {
			if (!memcmp(conn->addr, ethhdr->h_source, ETH_ALEN))
				triton_context_call(&conn->ctx, (void (*)(void *))disconnect, conn);
			break;
		}
	}
	pthread_mutex_unlock(&serv->lock);
}

static int pppoe_serv_read(struct triton_md_handler_t *h)
{
	struct pppoe_serv_t *serv = container_of(h, typeof(*serv), hnd);
	uint8_t pack[ETHER_MAX_LEN];
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	int n;

	while (1) {
		n = read(h->fd, pack, sizeof(pack));
		if (n < 0) {
			if (errno == EAGAIN)
				break;
			if (errno == ENETDOWN) {
				_server_stop(serv);
				return 1;
			}
			log_error("pppoe: read: %s\n", strerror(errno));
			return 0;
		}

		if (n < ETH_HLEN + sizeof(*hdr)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received (%i)\n", n);
			continue;
		}

		if (mac_filter_check(ethhdr->h_source)) {
			__sync_add_and_fetch(&stat_filtered, 1);
			continue;
		}

		if (memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) && memcmp(ethhdr->h_dest, serv->hwaddr, ETH_ALEN))
			continue;

		if (!memcmp(ethhdr->h_source, bc_addr, ETH_ALEN)) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is broadcast)\n");
			continue;
		}

		if ((ethhdr->h_source[0] & 1) != 0) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is not unicast)\n");
			continue;
		}

		if (n < ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received\n");
			continue;
		}

		if (hdr->ver != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported version %i)\n", hdr->ver);
			continue;
		}

		if (hdr->type != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported type %i)\n", hdr->type);
		}

		switch (hdr->code) {
			case CODE_PADI:
				pppoe_recv_PADI(serv, pack, n);
				break;
			case CODE_PADR:
				pppoe_recv_PADR(serv, pack, n);
				break;
			case CODE_PADT:
				pppoe_recv_PADT(serv, pack);
				break;
		}
	}
	return 0;
}

static void pppoe_serv_close(struct triton_context_t *ctx)
{
	struct pppoe_serv_t *serv = container_of(ctx, typeof(*serv), ctx);

	triton_md_disable_handler(&serv->hnd, MD_MODE_READ | MD_MODE_WRITE);

	serv->stopping = 1;

	pthread_mutex_lock(&serv->lock);
	if (!serv->conn_cnt) {
		pthread_mutex_unlock(&serv->lock);
		pppoe_server_free(serv);
		return;
	}
	pthread_mutex_unlock(&serv->lock);
}

static int parse_server(const char *opt, int *padi_limit)
{
	char *ptr, *endptr;

	ptr = strstr(opt, ",padi-limit=");
	if (ptr) {
		*padi_limit = strtol(ptr + 12, &endptr, 10);
		if (*endptr != 0 && *endptr != ',')
			goto out_err;
	}

	return 0;

out_err:
	return -1;
}

static int __pppoe_add_interface_re(int index, int flags, const char *name, struct iplink_arg *arg)
{
	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	__pppoe_server_start(name, arg->opt, arg->cli);

	return 0;
}

static void pppoe_add_interface_re(const char *opt, void *cli)
{
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	const char *ptr;
	int pcre_offset;
	struct iplink_arg arg;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;

	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

	if (!re) {
		log_error("pppoe: %s at %i\r\n", pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = ptr;
	arg.cli = cli;

	iplink_list((iplink_list_func)__pppoe_add_interface_re, &arg);

	pcre_free(re);
	_free(pattern);
}

void pppoe_server_start(const char *opt, void *cli)
{
	char name[IFNAMSIZ];
	const char *ptr;

	if (strlen(opt) > 3 && memcmp(opt, "re:", 3) == 0) {
		pppoe_add_interface_re(opt, cli);
		return;
	}

	ptr = strchr(opt, ',');
	if (ptr) {
		memcpy(name, opt, ptr - opt);
		name[ptr - opt] = 0;
		__pppoe_server_start(name, ptr, cli);
	} else
		__pppoe_server_start(opt, opt, cli);
}

static void __pppoe_server_start(const char *ifname, const char *opt, void *cli)
{
	struct pppoe_serv_t *serv;
	int sock;
	int f = 1;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	int padi_limit = conf_padi_limit;

	if (parse_server(opt, &padi_limit)) {
		if (cli)
			cli_sendv(cli, "failed to parse '%s'\r\n", opt);
		else
			log_error("pppoe: failed to parse '%s'\r\n", opt);
	}

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		if (!strcmp(serv->ifname, ifname)) {
			if (cli)
				cli_send(cli, "error: already exists\r\n");
			pthread_rwlock_unlock(&serv_lock);
			return;
		}
	}
	pthread_rwlock_unlock(&serv_lock);

	serv = _malloc(sizeof(*serv));
	memset(serv, 0, sizeof(*serv));

	if (init_secret(serv)) {
		if (cli)
			cli_sendv(cli, "init secret failed\r\n");
		_free(serv);
		return;
	}

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC));
	if (sock < 0) {
		if (cli)
			cli_sendv(cli, "socket: %s\r\n", strerror(errno));
		log_error("pppoe: socket: %s\n", strerror(errno));
		_free(serv);
		return;
	}

	fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &f, sizeof(f))) {
		if (cli)
			cli_sendv(cli, "setsockopt(SO_BROADCAST): %s\r\n", strerror(errno));
		log_error("pppoe: setsockopt(SO_BROADCAST): %s\n", strerror(errno));
		goto out_err;
	}

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFHWADDR): %s\r\n", strerror(errno));
		log_error("pppoe: ioctl(SIOCGIFHWADDR): %s\n", strerror(errno));
		goto out_err;
	}

#ifdef ARPHDR_ETHER
	if (ifr.ifr_hwaddr.sa_family != ARPHDR_ETHER) {
		log_error("pppoe: interface %s is not ethernet\n", ifname);
		goto out_err;
	}
#endif

	if ((ifr.ifr_hwaddr.sa_data[0] & 1) != 0) {
		if (cli)
			cli_sendv(cli, "interface %s has not unicast address\r\n", ifname);
		log_error("pppoe: interface %s has not unicast address\n", ifname);
		goto out_err;
	}

	memcpy(serv->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (ioctl(sock, SIOCGIFMTU, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFMTU): %s\r\n", strerror(errno));
		log_error("pppoe: ioctl(SIOCGIFMTU): %s\n", strerror(errno));
		goto out_err;
	}

	if (ifr.ifr_mtu < ETH_DATA_LEN) {
		if (cli)
			cli_sendv(cli, "interface %s has MTU of %i, should be %i\r\n", ifname, ifr.ifr_mtu, ETH_DATA_LEN);
		log_error("pppoe: interface %s has MTU of %i, should be %i\n", ifname, ifr.ifr_mtu, ETH_DATA_LEN);
	}

	if (ioctl(sock, SIOCGIFINDEX, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFINDEX): %s\r\n", strerror(errno));
		log_error("pppoe: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		goto out_err;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_PPP_DISC);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa))) {
		if (cli)
			cli_sendv(cli, "bind: %s\n", strerror(errno));
		log_error("pppoe: bind: %s\n", strerror(errno));
		goto out_err;
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
		if (cli)
			cli_sendv(cli, "failed to set nonblocking mode: %s\n", strerror(errno));
    log_error("pppoe: failed to set nonblocking mode: %s\n", strerror(errno));
		goto out_err;
	}

	serv->ctx.close = pppoe_serv_close;
	serv->ctx.before_switch = log_switch;
	serv->hnd.fd = sock;
	serv->hnd.read = pppoe_serv_read;
	serv->ifname = _strdup(ifname);
	pthread_mutex_init(&serv->lock, NULL);

	INIT_LIST_HEAD(&serv->conn_list);
	INIT_LIST_HEAD(&serv->pado_list);
	INIT_LIST_HEAD(&serv->padi_list);
	serv->padi_limit = padi_limit;

	triton_context_register(&serv->ctx, NULL);
	triton_md_register_handler(&serv->ctx, &serv->hnd);
	triton_md_enable_handler(&serv->hnd, MD_MODE_READ);
	triton_context_wakeup(&serv->ctx);

	pthread_rwlock_wrlock(&serv_lock);
	list_add_tail(&serv->entry, &serv_list);
	pthread_rwlock_unlock(&serv_lock);

	return;

out_err:
	close(sock);
	_free(serv);
}

static void _conn_stop(struct pppoe_conn_t *conn)
{
	ap_session_terminate(&conn->ppp.ses, TERM_ADMIN_RESET, 0);
}

static void _server_stop(struct pppoe_serv_t *serv)
{
	struct pppoe_conn_t *conn;

	if (serv->stopping)
		return;

	serv->stopping = 1;
	triton_md_disable_handler(&serv->hnd, MD_MODE_READ | MD_MODE_WRITE);

	pthread_mutex_lock(&serv->lock);
	if (!serv->conn_cnt) {
		pthread_mutex_unlock(&serv->lock);
		pppoe_server_free(serv);
		return;
	}
	list_for_each_entry(conn, &serv->conn_list, entry)
		triton_context_call(&conn->ctx, (triton_event_func)_conn_stop, conn);
	pthread_mutex_unlock(&serv->lock);
}

void pppoe_server_free(struct pppoe_serv_t *serv)
{
	struct delayed_pado_t *pado;

	pthread_rwlock_wrlock(&serv_lock);
	list_del(&serv->entry);
	pthread_rwlock_unlock(&serv_lock);

	while (!list_empty(&serv->pado_list)) {
		pado = list_entry(serv->pado_list.next, typeof(*pado), entry);
		free_delayed_pado(pado);
	}

	triton_md_unregister_handler(&serv->hnd, 1);
	triton_context_unregister(&serv->ctx);
	_free(serv->ifname);
	_free(serv);
}

void pppoe_server_stop(const char *ifname)
{
	struct pppoe_serv_t *serv;

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		if (strcmp(serv->ifname, ifname))
			continue;
		triton_context_call(&serv->ctx, (triton_event_func)_server_stop, serv);
		break;
	}
	pthread_rwlock_unlock(&serv_lock);
}

void __export pppoe_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static int init_secret(struct pppoe_serv_t *serv)
{
	DES_cblock key;

	if (read(urandom_fd, serv->secret, SECRET_LENGTH) < 0) {
		log_error("pppoe: failed to read /dev/urandom: %s\n", strerror(errno));
		return -1;
	}

	memset(key, 0, sizeof(key));
	DES_random_key(&key);
	DES_set_key(&key, &serv->des_ks);

	return 0;
}

static void load_config(void)
{
	char *opt;

	opt = conf_get_opt("pppoe", "verbose");
	if (opt)
		conf_verbose = atoi(opt);

	opt = conf_get_opt("pppoe", "ac-name");
	if (!opt)
		opt = conf_get_opt("pppoe", "AC-Name");
	if (opt) {
		if (conf_ac_name)
			_free(conf_ac_name);
		conf_ac_name = _strdup(opt);
	} else
		conf_ac_name = _strdup("accel-ppp");

	opt = conf_get_opt("pppoe", "service-name");
	if (!opt)
		opt = conf_get_opt("pppoe", "Service-Name");
	if (opt) {
		if (conf_service_name)
			_free(conf_service_name);
		conf_service_name = _strdup(opt);
	}

	opt = conf_get_opt("pppoe", "ifname-in-sid");
	if (opt) {
		if (!strcmp(opt, "calling-sid"))
			conf_ifname_in_sid = 1;
		else if (!strcmp(opt, "called-sid"))
			conf_ifname_in_sid = 2;
		else if (!strcmp(opt, "both"))
			conf_ifname_in_sid = 3;
		else if (atoi(opt) >= 0)
			conf_ifname_in_sid = atoi(opt);
	}

	opt = conf_get_opt("pppoe", "pado-delay");
	if (!opt)
		opt = conf_get_opt("pppoe", "PADO-Delay");
	if (opt)
		dpado_parse(opt);

	opt = conf_get_opt("pppoe", "tr101");
	if (opt)
		conf_tr101 = atoi(opt);

	opt = conf_get_opt("pppoe", "padi-limit");
	if (opt)
		conf_padi_limit = atoi(opt);

	opt = conf_get_opt("pppoe", "sid-uppercase");
	if (opt)
		conf_sid_uppercase = atoi(opt);

	opt = conf_get_opt("pppoe", "cookie-timeout");
	if (opt)
		conf_cookie_timeout = atoi(opt);
	else
		conf_cookie_timeout = 5;


	conf_mppe = MPPE_UNSET;
	opt = conf_get_opt("pppoe", "mppe");
	if (opt) {
		if (strcmp(opt, "deny") == 0)
			conf_mppe = MPPE_DENY;
		else if (strcmp(opt, "allow") == 0)
			conf_mppe = MPPE_ALLOW;
		else if (strcmp(opt, "prefer") == 0)
			conf_mppe = MPPE_PREFER;
		else if (strcmp(opt, "require") == 0)
			conf_mppe = MPPE_REQUIRE;
	}

	conf_ip_pool = conf_get_opt("pppoe", "ip-pool");

	conf_called_sid = CSID_MAC;
	opt = conf_get_opt("pppoe", "called-sid");
	if (opt) {
		if (!strcmp(opt, "mac"))
			conf_called_sid = CSID_MAC;
		else if (!strcmp(opt, "ifname"))
			conf_called_sid = CSID_IFNAME;
		else if (!strcmp(opt, "ifname:mac"))
			conf_called_sid = CSID_IFNAME_MAC;
		else
			log_error("pppoe: unknown called-sid type\n");
	}
}

static void load_interfaces()
{
	struct conf_sect_t *s = conf_get_section("pppoe");
	struct conf_option_t *opt;

	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "interface")) {
			if (opt->val)
				pppoe_server_start(opt->val, NULL);
		}
	}
}

static void pppoe_init(void)
{
	int fd;
	uint8_t *ptr;

	ptr = malloc(SID_MAX/8);
	memset(ptr, 0xff, SID_MAX/8);
	ptr[0] = 0xfe;
	ptr[SID_MAX/8-1] = 0x7f;
	sid_ptr = sid_map = (unsigned long *)ptr;

	fd = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
	if (fd >= 0)
		close(fd);
	else if (system("modprobe -q pppoe"))
		log_warn("failed to load pppoe kernel module\n");

	conn_pool = mempool_create(sizeof(struct pppoe_conn_t));
	pado_pool = mempool_create(sizeof(struct delayed_pado_t));
	padi_pool = mempool_create(sizeof(struct padi_t));

	if (!conf_get_section("pppoe")) {
		log_error("pppoe: no configuration, disabled...\n");
		return;
	}

	load_config();

	connlimit_loaded = triton_module_loaded("connlimit");

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	triton_context_call(NULL, (triton_event_func)load_interfaces, NULL);
}

DEFINE_INIT(21, pppoe_init);
