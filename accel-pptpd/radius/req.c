#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "radius.h"

static int urandom_fd;

static int rad_req_read(struct triton_md_handler_t *h);
static void rad_req_timeout(struct triton_timer_t *t);

struct rad_req_t *rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username)
{
	struct rad_req_t *req = malloc(sizeof(*req));

	if (!req)
		return NULL;

	memset(req, 0, sizeof(*req));
	req->rpd = rpd;
	req->hnd.fd = -1;
	req->ctx.before_switch = log_switch;

	req->server_name = conf_auth_server;
	req->server_port = conf_auth_server_port;

	while (1) {
		if (read(urandom_fd, req->RA, 16) != 16) {
			if (errno == EINTR)
				continue;
			log_ppp_error("radius:req:read urandom: %s\n", strerror(errno));
			goto out_err;
		}
		break;
	}

	req->pack = rad_packet_alloc(code);
	if (!req->pack)
		goto out_err;

	if (rad_packet_add_str(req->pack, "User-Name", username, strlen(username)))
		goto out_err;
	if (conf_nas_identifier)
		if (rad_packet_add_str(req->pack, "NAS-Identifier", conf_nas_identifier, strlen(conf_nas_identifier)))
			goto out_err;
	if (rad_packet_add_int(req->pack, "NAS-Port-Id", rpd->ppp->unit_idx))
		goto out_err;
	if (rad_packet_add_val(req->pack, "NAS-Port-Type", "Virtual"))
		goto out_err;
	if (rad_packet_add_val(req->pack, "Service-Type", "Framed-User"))
		goto out_err;
	if (rad_packet_add_val(req->pack, "Framed-Protocol", "PPP"))
		goto out_err;

	return req;

out_err:
	rad_req_free(req);
	return NULL;
}

int rad_req_acct_fill(struct rad_req_t *req)
{
	req->server_name = conf_acct_server;
	req->server_port = conf_acct_server_port;

	memset(req->RA, 0, sizeof(req->RA));

	if (rad_packet_add_val(req->pack, "Acct-Status-Type", "Start"))
		return -1;
	if (rad_packet_add_str(req->pack, "Acct-Session-Id", req->rpd->ppp->sessionid, PPP_SESSIONID_LEN))
		return -1;
	if (rad_packet_add_int(req->pack, "Acct-Session-Time", 0))
		return -1;
	if (rad_packet_add_int(req->pack, "Acct-Input-Octets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, "Acct-Output-Octets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, "Acct-Input-Packets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, "Acct-Output-Packets", 0))
		return -1;

	return 0;
}

void rad_req_free(struct rad_req_t *req)
{
	if (req->hnd.fd >= 0 )
		close(req->hnd.fd);
	if (req->pack)
		rad_packet_free(req->pack);
	if (req->reply)
		rad_packet_free(req->reply);
	free(req);
}

static int make_socket(struct rad_req_t *req)
{
  struct sockaddr_in addr;

	req->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (req->hnd.fd < 0) {
		log_ppp_error("radius:socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	if (conf_nas_ip_address) {
		addr.sin_addr.s_addr = inet_addr(conf_nas_ip_address);
		if (bind(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
			log_ppp_error("radius:bind: %s\n", strerror(errno));
			goto out_err;
		}
	}

	addr.sin_addr.s_addr = inet_addr(req->server_name);
	addr.sin_port = htons(req->server_port);

	if (connect(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
		log_ppp_error("radius:connect: %s\n", strerror(errno));
		goto out_err;
	}

	if (fcntl(req->hnd.fd, F_SETFL, O_NONBLOCK)) {
		log_ppp_error("radius: failed to set nonblocking mode: %s\n", strerror(errno));
		goto out_err;
	}
	
	return 0;

out_err:
	close(req->hnd.fd);
	req->hnd.fd = -1;
	return -1;
}

int rad_req_send(struct rad_req_t *req)
{
	if (req->hnd.fd == -1 && make_socket(req))
		return -1;

	if (!req->pack->buf && rad_packet_build(req->pack, req->RA))
		goto out_err;
	
	if (conf_verbose) {
		log_ppp_debug("send ");
		rad_packet_print(req->pack, log_ppp_debug);
	}

	rad_packet_send(req->pack, req->hnd.fd, NULL);

	return 0;

out_err:
	close(req->hnd.fd);
	req->hnd.fd = -1;
	return -1;
}

static void req_wakeup(struct rad_req_t *req)
{
	triton_context_wakeup(req->rpd->ppp->ctrl->ctx);
	triton_timer_del(&req->timeout);
	triton_md_unregister_handler(&req->hnd);
	triton_context_unregister(&req->ctx);
}
static int rad_req_read(struct triton_md_handler_t *h)
{
	struct rad_req_t *req = container_of(h, typeof(*req), hnd);

	req->reply = rad_packet_recv(h->fd, NULL);
	req_wakeup(req);
	
	return 0;
}
static void rad_req_timeout(struct triton_timer_t *t)
{
	struct rad_req_t *req = container_of(t, typeof(*req), timeout);
	
	req_wakeup(req);
}

int rad_req_wait(struct rad_req_t *req, int timeout)
{
	req->hnd.read = rad_req_read;
	req->timeout.expire = rad_req_timeout;

	triton_context_register(&req->ctx, req->rpd->ppp);
	triton_md_register_handler(&req->ctx, &req->hnd);
	if (triton_md_enable_handler(&req->hnd, MD_MODE_READ))
		return -1;

	req->timeout.period = timeout * 1000;
	if (triton_timer_add(&req->ctx, &req->timeout, 0))
		return -1;

	triton_context_schedule(req->rpd->ppp->ctrl->ctx);

	if (conf_verbose && req->reply) {
		log_ppp_debug("recv ");
		rad_packet_print(req->reply, log_ppp_debug);
	}
	return 0;
}

void __init req_init(void)
{
	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (!urandom_fd) {
		perror("radius:req: open /dev/urandom");
		_exit(EXIT_FAILURE);
	}
}
