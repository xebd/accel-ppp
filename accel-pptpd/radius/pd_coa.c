#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <openssl/md5.h>

#include "triton.h"
#include "log.h"

#include "radius.h"

#define PD_COA_PORT 3799

struct dm_coa_serv_t
{
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
};

static int dm_coa_check_RA(struct rad_packet_t *pack, const char *secret)
{
	uint8_t RA[16];
	MD5_CTX ctx;

	memset(RA, 0, 16);
	
	MD5_Init(&ctx);
	MD5_Update(&ctx, pack->buf, 4);
	MD5_Update(&ctx, RA, 16);
	MD5_Update(&ctx, pack->buf + 20, pack->len - 20);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(RA, &ctx);

	return memcmp(RA, pack->buf + 4, 16);
}

static void dm_coa_set_RA(struct rad_packet_t *pack, const char *secret)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, pack->buf, pack->len);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(pack->buf + 4, &ctx);
}

static void disconnect_request(struct radius_pd_t *rpd)
{
	rad_packet_free(rpd->dm_coa_req);
	rpd->dm_coa_req = NULL;

	ppp_terminate(rpd->ppp, 0);
}

static void coa_request(struct radius_pd_t *rpd)
{
	rad_packet_free(rpd->dm_coa_req);
	rpd->dm_coa_req = NULL;

/// TODO: CoA handling
}

static int dm_coa_read(struct triton_md_handler_t *h)
{
	struct rad_packet_t *pack;
	struct rad_packet_t *reply = NULL;
	struct radius_pd_t *rpd;
	int err_code;
	uint8_t RA[16];
	struct sockaddr_in addr;


	pack = rad_packet_recv(h->fd, &addr);
	if (!pack)
		return 0;

	if (pack->code != CODE_DISCONNECT_REQUEST	&& pack->code != CODE_COA_REQUEST) {
		log_warn("radius:dm_coa: unexpected code (%i) received\n", pack->code);
		goto out_err_no_reply;
	}

	if (dm_coa_check_RA(pack, conf_dm_coa_secret)) {
		log_warn("radius:dm_coa: RA validation failed\n");
		goto out_err_no_reply;
	}

	memcpy(RA, pack->buf + 4, sizeof(RA));
	
	if (conf_verbose) {
		log_debug("recv ");
		rad_packet_print(pack, log_debug);
	}

	if (rad_check_nas_pack(pack)) {
		log_warn("radius:dm_coa: NAS identification failed\n");
		err_code = 403;
		goto out_err;
	}
	
	rpd = rad_find_session_pack(pack);
	if (!rpd) {
		log_warn("radius:dm_coa: session not found\n");
		err_code = 503;
		goto out_err;
	}
	
	rpd->dm_coa_req = pack;

	if (pack->code == CODE_DISCONNECT_REQUEST)
		triton_context_call(rpd->ppp->ctrl->ctx, (void (*)(void *))disconnect_request, rpd);
	else
		triton_context_call(rpd->ppp->ctrl->ctx, (void (*)(void *))coa_request, rpd);

	pthread_mutex_unlock(&rpd->lock);

	reply = rad_packet_alloc(pack->code == CODE_COA_REQUEST ? CODE_COA_ACK : CODE_DISCONNECT_ACK);
	reply->id = pack->id;
	if (rad_packet_build(reply, RA))
		goto out_err_no_reply;
	dm_coa_set_RA(reply, conf_dm_coa_secret);
	if (conf_verbose) {
		log_debug("send ");
		rad_packet_print(reply, log_debug);
	}
	rad_packet_send(reply, h->fd, &addr);
	rad_packet_free(reply);

	return 0;

out_err:
	reply = rad_packet_alloc(pack->code == CODE_COA_REQUEST ? CODE_COA_NAK : CODE_DISCONNECT_NAK);
	rad_packet_add_int(reply, "Error-Cause", err_code);
	reply->id = pack->id;
	if (rad_packet_build(reply, RA))
		goto out_err_no_reply;
	dm_coa_set_RA(reply, conf_dm_coa_secret);
	if (conf_verbose) {
		log_debug("send ");
		rad_packet_print(reply, log_debug);
	}
	rad_packet_send(reply, h->fd, &addr);

out_err_no_reply:
	rad_packet_free(pack);
	if (reply)
		rad_packet_free(reply);
	return 0;
}

static void dm_coa_close(struct triton_context_t *ctx)
{
	struct dm_coa_serv_t *serv = container_of(ctx, typeof(*serv), ctx);
	triton_md_unregister_handler(&serv->hnd);
	close(serv->hnd.fd);
}

static struct dm_coa_serv_t serv = {
	.ctx.close = dm_coa_close,
	.hnd.read = dm_coa_read,
};

static void __init init(void)
{
  struct sockaddr_in addr;

	serv.hnd.fd = socket (PF_INET, SOCK_DGRAM, 0);
  if (serv.hnd.fd < 0) {
    log_error("radius:dm_coa: socket: %s\n", strerror(errno));
    return;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons (PD_COA_PORT);
	if (conf_nas_ip_address)
	  addr.sin_addr.s_addr = inet_addr(conf_nas_ip_address);
	else
		addr.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (serv.hnd.fd, (struct sockaddr *) &addr, sizeof (addr)) < 0) {
    log_error("radius:dm_coa: bind: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
  }

	if (fcntl(serv.hnd.fd, F_SETFL, O_NONBLOCK)) {
    log_error("radius:dm_coa: failed to set nonblocking mode: %s\n", strerror(errno));
		close(serv.hnd.fd);
    return;
	}
	
	triton_context_register(&serv.ctx);
	triton_md_register_handler(&serv.ctx, &serv.hnd);
	triton_md_enable_handler(&serv.hnd, MD_MODE_READ);
}
