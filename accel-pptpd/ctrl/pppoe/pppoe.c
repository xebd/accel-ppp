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

#include <openssl/md5.h>

#include "events.h"
#include "triton.h"
#include "log.h"
#include "ppp.h"
#include "mempool.h"
#include "cli.h"

#include "pppoe.h"

#include "memdebug.h"

struct pppoe_conn_t
{
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
	
	struct ppp_ctrl_t ctrl;
	struct ppp_t ppp;
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

int conf_verbose;
char *conf_service_name;
char *conf_ac_name;
int conf_pado_delay;

static mempool_t conn_pool;
static mempool_t pado_pool;

uint32_t stat_active;
uint32_t stat_delayed_pado;

pthread_rwlock_t serv_lock = PTHREAD_RWLOCK_INITIALIZER;
LIST_HEAD(serv_list);

#define SECRET_SIZE 16
static uint8_t *secret;

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void pppoe_send_PADT(struct pppoe_conn_t *conn);
static void _server_stop(struct pppoe_serv_t *serv);
void pppoe_server_free(struct pppoe_serv_t *serv);

static void disconnect(struct pppoe_conn_t *conn)
{
	if (conn->ppp_started) {
		__sync_fetch_and_sub(&stat_active, 1);
		conn->ppp_started = 0;
		ppp_terminate(&conn->ppp, TERM_USER_REQUEST, 1);
	}

	pppoe_send_PADT(conn);

	close(conn->disc_sock);


	triton_event_fire(EV_CTRL_FINISHED, &conn->ppp);

	if (conf_verbose)
		log_ppp_info("disconnected\n");

	pthread_mutex_lock(&conn->serv->lock);
	conn->serv->conn[conn->sid] = NULL;
	list_del(&conn->entry);
	conn->serv->conn_cnt--;
	if (conn->serv->stopping && conn->serv->conn_cnt == 0) {
		pthread_mutex_unlock(&conn->serv->lock);
		pppoe_server_free(conn->serv);
	} else
		pthread_mutex_unlock(&conn->serv->lock);

	_free(conn->ctrl.calling_station_id);
	_free(conn->ctrl.called_station_id);
	_free(conn->service_name);
	if (conn->host_uniq)
		_free(conn->host_uniq);
	if (conn->relay_sid)
		_free(conn->relay_sid);

	triton_context_unregister(&conn->ctx);

	mempool_free(conn);
}

static void ppp_started(struct ppp_t *ppp)
{
	log_ppp_debug("pppoe: ppp started\n");
}

static void ppp_finished(struct ppp_t *ppp)
{
	struct pppoe_conn_t *conn = container_of(ppp, typeof(*conn), ppp);

	log_ppp_debug("pppoe: ppp finished\n");

	if (conn->ppp_started) {
		__sync_fetch_and_sub(&stat_active, 1);
		conn->ppp_started = 0;
		disconnect(conn);
	}
}

static void pppoe_conn_close(struct triton_context_t *ctx)
{
	struct pppoe_conn_t *conn = container_of(ctx, typeof(*conn), ctx);

	if (conn->ppp_started)
		ppp_terminate(&conn->ppp, TERM_ADMIN_RESET, 0);
	else
		disconnect(conn);
}

static struct pppoe_conn_t *allocate_channel(struct pppoe_serv_t *serv, const uint8_t *addr, const struct pppoe_tag *host_uniq, const struct pppoe_tag *relay_sid, const struct pppoe_tag *service_name)
{
	struct pppoe_conn_t *conn;
	int sid;

	conn = mempool_alloc(conn_pool);
	if (!conn) {
		log_emerg("pppoe: out of memory\n");
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));

	pthread_mutex_lock(&serv->lock);
	for (sid = serv->sid + 1; sid != serv->sid; sid++) {
		if (sid == MAX_SID)
			sid = 1;
		if (!serv->conn[sid]) {
			conn->sid = sid;
			serv->sid = sid;
			serv->conn[sid] = conn;
			list_add_tail(&conn->entry, &serv->conn_list);
			serv->conn_cnt++;
			break;
		}
	}
	pthread_mutex_unlock(&serv->lock);

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

	conn->service_name = _malloc(sizeof(*service_name) + ntohs(service_name->tag_len));
	memcpy(conn->service_name, service_name, sizeof(*service_name) + ntohs(service_name->tag_len));

	conn->ctx.before_switch = log_switch;
	conn->ctx.close = pppoe_conn_close;
	conn->ctrl.ctx = &conn->ctx;
	conn->ctrl.started = ppp_started;
	conn->ctrl.finished = ppp_finished;
	conn->ctrl.max_mtu = MAX_PPPOE_MTU;
	conn->ctrl.name = "pppoe";

	conn->ctrl.calling_station_id = _malloc(19);
	conn->ctrl.called_station_id = _malloc(19);
	sprintf(conn->ctrl.calling_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	sprintf(conn->ctrl.called_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
		serv->hwaddr[0], serv->hwaddr[1], serv->hwaddr[2], serv->hwaddr[3], serv->hwaddr[4], serv->hwaddr[5]);
	
	ppp_init(&conn->ppp);

	conn->ppp.ctrl = &conn->ctrl;
	conn->ppp.chan_name = conn->ctrl.calling_station_id;
	
	triton_context_register(&conn->ctx, &conn->ppp);
	triton_context_wakeup(&conn->ctx);
	
	triton_event_fire(EV_CTRL_STARTING, &conn->ppp);
	triton_event_fire(EV_CTRL_STARTED, &conn->ppp);

	conn->disc_sock = dup(serv->hnd.fd);

	return conn;
}

static int connect_channel(struct pppoe_conn_t *conn)
{
	int sock;
	struct sockaddr_pppox sp;

	sock = socket(AF_PPPOX, SOCK_STREAM, PX_PROTO_OE);
	if (!sock) {
		log_error("pppoe: socket(PPPOX): %s\n", strerror(errno));
		return -1;
	}

	memset(&sp, 0, sizeof(sp));

	sp.sa_family = AF_PPPOX;
	sp.sa_protocol = PX_PROTO_OE;
	sp.sa_addr.pppoe.sid = htons(conn->sid);
	strcpy(sp.sa_addr.pppoe.dev, conn->serv->ifname);
	memcpy(sp.sa_addr.pppoe.remote, conn->addr, ETH_ALEN);

	if (connect(sock, (struct sockaddr *)&sp, sizeof(sp))) {
		log_error("pppoe: connect: %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	conn->ppp.fd = sock;

	if (establish_ppp(&conn->ppp)) {
		close(sock);
		return -1;
	}
	
	return 0;
}

static void print_tag_string(struct pppoe_tag *tag)
{
	int i;

	for (i = 0; i < ntohs(tag->tag_len); i++)
		log_info("%c", tag->tag_data[i]);
}

static void print_tag_octets(struct pppoe_tag *tag)
{
	int i;

	for (i = 0; i < ntohs(tag->tag_len); i++)
		log_info("%02x", (uint8_t)tag->tag_data[i]);
}

static void print_packet(uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	int n;

	log_info("[PPPoE ");

	switch (hdr->code) {
		case CODE_PADI:
			log_info("PADI");
			break;
		case CODE_PADO:
			log_info("PADO");
			break;
		case CODE_PADR:
			log_info("PADR");
			break;
		case CODE_PADS:
			log_info("PADS");
			break;
		case CODE_PADT:
			log_info("PADT");
			break;
	}
	
	log_info(" %02x:%02x:%02x:%02x:%02x:%02x => %02x:%02x:%02x:%02x:%02x:%02x", 
		ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2], ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5],
		ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5]);

	log_info(" sid=%04x", ntohs(hdr->sid));

	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				log_info(" <End-Of-List>");
				break;
			case TAG_SERVICE_NAME:
				log_info(" <Service-Name ");
				print_tag_string(tag);
				log_info(">");
				break;
			case TAG_AC_NAME:
				log_info(" <AC-Name ");
				print_tag_string(tag);
				log_info(">");
				break;
			case TAG_HOST_UNIQ:
				log_info(" <Host-Uniq ");
				print_tag_octets(tag);
				log_info(">");
				break;
			case TAG_AC_COOKIE:
				log_info(" <AC-Cookie ");
				print_tag_octets(tag);
				log_info(">");
				break;
			case TAG_VENDOR_SPECIFIC:
				log_info(" <Vendor-Specific>");
				break;
			case TAG_RELAY_SESSION_ID:
				log_info(" <Relay-Session-Id");
				print_tag_octets(tag);
				log_info(">");
				break;
			case TAG_SERVICE_NAME_ERROR:
				log_info(" <Service-Name-Error>");
				break;
			case TAG_AC_SYSTEM_ERROR:
				log_info(" <AC-System-Error>");
				break;
			case TAG_GENERIC_ERROR:
				log_info(" <Generic-Error>");
				break;
			default:
				log_info(" <Unknown (%x)>", ntohs(tag->tag_type));
				break;
		}
	}

	log_info("]\n");
}

static void generate_cookie(const uint8_t *src, const uint8_t *dst, uint8_t *cookie)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, secret, SECRET_SIZE);
	MD5_Update(&ctx, src, ETH_ALEN);
	MD5_Update(&ctx, dst, ETH_ALEN);
	MD5_Update(&ctx, conf_ac_name, strlen(conf_ac_name));
	MD5_Update(&ctx, secret, SECRET_SIZE);
	MD5_Final(cookie, &ctx);
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
	uint8_t cookie[MD5_DIGEST_LENGTH];

	setup_header(pack, serv->hwaddr, addr, CODE_PADO, 0);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));
	if (conf_service_name)
		add_tag(pack, TAG_SERVICE_NAME, (uint8_t *)conf_service_name, strlen(conf_service_name));

	if (service_name)
		add_tag2(pack, service_name);
	
	generate_cookie(serv->hwaddr, addr, cookie);
	add_tag(pack, TAG_AC_COOKIE, cookie, MD5_DIGEST_LENGTH);

	if (host_uniq)
		add_tag2(pack, host_uniq);
	
	if (relay_sid)
		add_tag2(pack, relay_sid);

	if (conf_verbose) {
		log_info("send ");
		print_packet(pack);
	}

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
		log_info("send ");
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
		log_info("send ");
		print_packet(pack);
	}

	pppoe_send(conn->disc_sock, pack);
}

static void pppoe_send_PADT(struct pppoe_conn_t *conn)
{
	uint8_t pack[ETHER_MAX_LEN];

	setup_header(pack, conn->serv->hwaddr, conn->addr, CODE_PADT, conn->sid);

	add_tag(pack, TAG_AC_NAME, (uint8_t *)conf_ac_name, strlen(conf_ac_name));

	add_tag2(pack, conn->service_name);

	if (conn->host_uniq)
		add_tag2(pack, conn->host_uniq);
	
	if (conn->relay_sid)
		add_tag2(pack, conn->relay_sid);

	if (conf_verbose) {
		log_info("send ");
		print_packet(pack);
	}

	pppoe_send(conn->disc_sock, pack);
}

static void free_delayed_pado(struct delayed_pado_t *pado)
{
	triton_timer_del(&pado->timer);

	__sync_fetch_and_sub(&stat_delayed_pado, 1);
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

	pppoe_send_PADO(pado->serv, pado->addr, pado->host_uniq, pado->relay_sid, pado->service_name);

	free_delayed_pado(pado);
}

static void pppoe_recv_PADI(struct pppoe_serv_t *serv, uint8_t *pack, int size)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_tag *tag;
	struct pppoe_tag *host_uniq_tag = NULL;
	struct pppoe_tag *relay_sid_tag = NULL;
	struct pppoe_tag *service_name_tag = NULL;
	int n, service_match = 0;
	struct delayed_pado_t *pado;

	if (hdr->sid) {
		log_warn("pppoe: discarding PADI packet (sid is not zero)\n");
		return;
	}

	if (conf_verbose) {
		log_info("recv ");
		print_packet(pack);
	}
	
	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
		switch (ntohs(tag->tag_type)) {
			case TAG_END_OF_LIST:
				break;
			case TAG_SERVICE_NAME:
				if (tag->tag_len == 0)
					service_match = 1;
				else if (conf_service_name) {
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

	if (!service_match) {
		if (conf_verbose)
			log_warn("pppoe: discarding PADI packet (Service-Name mismatch)\n");
		return;
	}

	if (conf_pado_delay) {
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
		pado->timer.period = conf_pado_delay;

		triton_timer_add(&serv->ctx, &pado->timer, 0);

		list_add_tail(&pado->entry, &serv->pado_list);
		__sync_fetch_and_add(&stat_delayed_pado, 1);
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
	uint8_t cookie[MD5_DIGEST_LENGTH];
	int n, service_match = 0;
	struct pppoe_conn_t *conn;

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
		log_info("recv ");
		print_packet(pack);
	}
	
	for (n = 0; n < ntohs(hdr->length); n += sizeof(*tag) + ntohs(tag->tag_len)) {
		tag = (struct pppoe_tag *)(pack + ETH_HLEN + sizeof(*hdr) + n);
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
		}
	}

	if (!ac_cookie_tag) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (no AC-Cookie tag present)\n");
		return;
	}

	if (ntohs(ac_cookie_tag->tag_len) != MD5_DIGEST_LENGTH) {
		if (conf_verbose)
			log_warn("pppoe: discard PADR packet (incorrect AC-Cookie tag length)\n");
		return;
	}

	generate_cookie(serv->hwaddr, ethhdr->h_source, cookie);

	if (memcmp(cookie, ac_cookie_tag->tag_data, MD5_DIGEST_LENGTH)) {
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

	conn = allocate_channel(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, service_name_tag);
	if (!conn)
		pppoe_send_err(serv, ethhdr->h_source, host_uniq_tag, relay_sid_tag, CODE_PADS, TAG_AC_SYSTEM_ERROR);
	else {
		pppoe_send_PADS(conn);
		if (connect_channel(conn))
			disconnect(conn);
		else {
			__sync_fetch_and_add(&stat_active, 1);
			conn->ppp_started = 1;
		}
	}
}

static void pppoe_recv_PADT(struct pppoe_serv_t *serv, uint8_t *pack)
{
	struct ethhdr *ethhdr = (struct ethhdr *)pack;
	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
	struct pppoe_conn_t *conn;
	
	if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN)) {
		if (conf_verbose)
			log_warn("pppoe: discard PADT (destination address is broadcast)\n");
		return;
	}
	
	if (conf_verbose) {
		log_info("recv ");
		print_packet(pack);
	}

	pthread_mutex_lock(&serv->lock);
	conn = serv->conn[ntohs(hdr->sid)];
	if (conn && !memcmp(conn->addr, ethhdr->h_source, ETH_ALEN))
		triton_context_call(&conn->ctx, (void (*)(void *))disconnect, conn);
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
			log_error("pppoe: read: %s\n", strerror(errno));
			return 0;
		}

		if (n < ETH_HLEN + sizeof(*hdr)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received (%i)\n", n);
			continue;
		}

		if (mac_filter_check(ethhdr->h_source))
			continue;

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
}

void pppoe_server_start(const char *ifname, void *cli)
{
	struct pppoe_serv_t *serv = _malloc(sizeof(*serv));
	int sock;
	int opt = 1;
	struct ifreq ifr;
	struct sockaddr_ll sa;

	memset(serv, 0, sizeof(*serv));

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC));
	if (sock < 0) {
		if (cli)
			cli_sendv(cli, "socket: %s\r\n", strerror(errno));
		log_emerg("pppoe: socket: %s\n", strerror(errno));
		_free(serv);
		return;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt))) {
		if (cli)
			cli_sendv(cli, "setsockopt(SO_BROADCAST): %s\r\n", strerror(errno));
		log_emerg("pppoe: setsockopt(SO_BROADCAST): %s\n", strerror(errno));
		goto out_err;
	}

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFHWADDR): %s\r\n", strerror(errno));
		log_emerg("pppoe: ioctl(SIOCGIFHWADDR): %s\n", strerror(errno));
		goto out_err;
	}

#ifdef ARPHDR_ETHER
	if (ifr.ifr_hwaddr.sa_family != ARPHDR_ETHER) {
		log_emerg("pppoe: interface %s is not ethernet\n", ifname);
		goto out_err;
	}
#endif

	if ((ifr.ifr_hwaddr.sa_data[0] & 1) != 0) {
		if (cli)
			cli_sendv(cli, "interface %s has not unicast address\r\n", ifname);
		log_emerg("pppoe: interface %s has not unicast address\n", ifname);
		goto out_err;
	}

	memcpy(serv->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	if (ioctl(sock, SIOCGIFMTU, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFMTU): %s\r\n", strerror(errno));
		log_emerg("pppoe: ioctl(SIOCGIFMTU): %s\n", strerror(errno));
		goto out_err;
	}

	if (ifr.ifr_mtu < ETH_DATA_LEN) {
		if (cli)
			cli_sendv(cli, "interface %s has MTU of %i, should be %i\r\n", ifname, ifr.ifr_mtu, ETH_DATA_LEN);
		log_emerg("pppoe: interface %s has MTU of %i, should be %i\n", ifname, ifr.ifr_mtu, ETH_DATA_LEN);
	}
	
	if (ioctl(sock, SIOCGIFINDEX, &ifr)) {
		if (cli)
			cli_sendv(cli, "ioctl(SIOCGIFINDEX): %s\r\n", strerror(errno));
		log_emerg("pppoe: ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		goto out_err;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_PPP_DISC);
	sa.sll_ifindex = ifr.ifr_ifindex;

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa))) {
		if (cli)
			cli_sendv(cli, "bind: %s\n", strerror(errno));
		log_emerg("pppoe: bind: %s\n", strerror(errno));
		goto out_err;
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK)) {
		if (cli)
			cli_sendv(cli, "failed to set nonblocking mode: %s\n", strerror(errno));
    log_emerg("pppoe: failed to set nonblocking mode: %s\n", strerror(errno));
		goto out_err;
	}

	serv->ctx.close = pppoe_serv_close;
	serv->hnd.fd = sock;
	serv->hnd.read = pppoe_serv_read;
	serv->ifname = _strdup(ifname);
	pthread_mutex_init(&serv->lock, NULL);

	INIT_LIST_HEAD(&serv->conn_list);
	INIT_LIST_HEAD(&serv->pado_list);

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
	ppp_terminate(&conn->ppp, 0, TERM_ADMIN_RESET);
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

	triton_md_unregister_handler(&serv->hnd);
	close(serv->hnd.fd);
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

static int init_secret(void)
{
	int fd;

	secret = malloc(SECRET_SIZE);

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) {
		log_emerg("pppoe: cann't open /dev/urandom: %s\n", strerror(errno));
		return -1;
	}

	if (read(fd, secret, SECRET_SIZE) < 0) {
		log_emerg("pppoe: faild to read /dev/urandom\n", strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}

static void __init pppoe_init(void)
{
	struct conf_sect_t *s = conf_get_section("pppoe");
	struct conf_option_t *opt;

	conn_pool = mempool_create(sizeof(struct pppoe_conn_t));
	pado_pool = mempool_create(sizeof(struct delayed_pado_t));

	if (init_secret())
		_exit(EXIT_FAILURE);

	if (!s) {
		log_emerg("pppoe: no configuration, disabled...\n");
		return;
	}
	
	list_for_each_entry(opt, &s->items, entry) {
		if (!strcmp(opt->name, "interface")) {
			if (opt->val)
				pppoe_server_start(opt->val, NULL);
		} else if (!strcmp(opt->name, "verbose")) {
			if (atoi(opt->val) > 0)
				conf_verbose = 1;
		}	else if (!strcmp(opt->name, "ac-name") || !strcmp(opt->name, "AC-Name")) {
			if (opt->val && strlen(opt->val))
				conf_ac_name = _strdup(opt->val);
		} else if (!strcmp(opt->name, "service-name") || !strcmp(opt->name, "Service-Name")) {
			if (opt->val && strlen(opt->val))
				conf_service_name = _strdup(opt->val);
		} else if (!strcmp(opt->name, "pado-delay") || !strcmp(opt->name, "PADO-delay")) {
			if (opt->val && atoi(opt->val) > 0)
				conf_pado_delay = atoi(opt->val);
		}
	}

	if (!conf_ac_name)
		conf_ac_name = _strdup("accel-pptp");
}

