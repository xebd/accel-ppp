#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "log.h"
#include "radius_p.h"

#include "memdebug.h"

static int rad_req_read(struct triton_md_handler_t *h);
static void rad_req_timeout(struct triton_timer_t *t);
static int make_socket(struct rad_req_t *req);

static struct rad_req_t *__rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username, in_addr_t addr, int port)
{
	struct rad_plugin_t *plugin;
	struct ppp_t *ppp = NULL;
	struct rad_req_t *req = _malloc(sizeof(*req));

	if (!req) {
		log_emerg("radius: out of memory\n");
		return NULL;
	}

	if (rpd->ses->ctrl->ppp)
		ppp = container_of(rpd->ses, typeof(*ppp), ses);

	memset(req, 0, sizeof(*req));
	req->rpd = rpd;
	req->hnd.fd = -1;
	req->ctx.before_switch = log_switch;

	req->type = code == CODE_ACCESS_REQUEST ? RAD_SERV_AUTH : RAD_SERV_ACCT;

	if (addr)
		req->serv = rad_server_get2(req->type, addr, port);
	else
		req->serv = rad_server_get(req->type);

	if (!req->serv)
		goto out_err;
	
	req->server_addr = req->serv->addr;
	req->server_port = req->serv->auth_port;

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

	if (rad_packet_add_str(req->pack, NULL, "User-Name", username))
		goto out_err;
	if (conf_nas_identifier)
		if (rad_packet_add_str(req->pack, NULL, "NAS-Identifier", conf_nas_identifier))
			goto out_err;
	if (conf_nas_ip_address)
		if (rad_packet_add_ipaddr(req->pack, NULL, "NAS-IP-Address", conf_nas_ip_address))
			goto out_err;
	if (ppp) {
		if (rad_packet_add_int(req->pack, NULL, "NAS-Port", ppp->ses.unit_idx))
			goto out_err;
	}
	
	if (req->rpd->ses->ctrl->type == CTRL_TYPE_IPOE) {
		if (rad_packet_add_val(req->pack, NULL, "NAS-Port-Type", "Ethernet"))
			goto out_err;
	} else {
		if (rad_packet_add_val(req->pack, NULL, "NAS-Port-Type", "Virtual"))
			goto out_err;

		if (rad_packet_add_val(req->pack, NULL, "Service-Type", "Framed-User"))
			goto out_err;

		if (rad_packet_add_val(req->pack, NULL, "Framed-Protocol", "PPP"))
			goto out_err;
	}

	if (rpd->ses->ctrl->calling_station_id)
		if (rad_packet_add_str(req->pack, NULL, "Calling-Station-Id", rpd->ses->ctrl->calling_station_id))
			goto out_err;
	if (rpd->ses->ctrl->called_station_id)
		if (rad_packet_add_str(req->pack, NULL, "Called-Station-Id", rpd->ses->ctrl->called_station_id))
			goto out_err;
	if (rpd->attr_class)
		if (rad_packet_add_octets(req->pack, NULL, "Class", rpd->attr_class, rpd->attr_class_len))
			goto out_err;

	list_for_each_entry(plugin, &req->rpd->plugin_list, entry) {
		switch (code) {
			case CODE_ACCESS_REQUEST:
				if (plugin->send_access_request && plugin->send_access_request(plugin, req->pack))
					goto out_err;
				break;
			case CODE_ACCOUNTING_REQUEST:
				if (plugin->send_accounting_request && plugin->send_accounting_request(plugin, req->pack))
					goto out_err;
				break;
		}
	}

	return req;

out_err:
	if (!req->serv)
		log_ppp_error("radius: no servers available\n");
	else
		log_emerg("radius: out of memory\n");
	rad_req_free(req);
	return NULL;
}

struct rad_req_t *rad_req_alloc(struct radius_pd_t *rpd, int code, const char *username)
{
	return __rad_req_alloc(rpd, code, username, 0, 0);
}

struct rad_req_t *rad_req_alloc2(struct radius_pd_t *rpd, int code, const char *username, in_addr_t addr, int port)
{
	struct rad_req_t *req = __rad_req_alloc(rpd, code, username, addr, port);

	if (!req)
		return NULL;

	if (code == CODE_ACCOUNTING_REQUEST)
		req->server_port = req->serv->acct_port;

	make_socket(req);

	return req;
}

int rad_req_acct_fill(struct rad_req_t *req)
{
	struct ipv6db_addr_t *a;

	req->server_port = req->serv->acct_port;

	memset(req->RA, 0, sizeof(req->RA));

	if (rad_packet_add_val(req->pack, NULL, "Acct-Status-Type", "Start"))
		return -1;
	if (rad_packet_add_val(req->pack, NULL, "Acct-Authentic", "RADIUS"))
		return -1;
	if (rad_packet_add_str(req->pack, NULL, "Acct-Session-Id", req->rpd->ses->sessionid))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Session-Time", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Input-Octets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Output-Octets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Input-Packets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Output-Packets", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Input-Gigawords", 0))
		return -1;
	if (rad_packet_add_int(req->pack, NULL, "Acct-Output-Gigawords", 0))
		return -1;
	if (conf_acct_delay_time) {
		if (rad_packet_add_int(req->pack, NULL, "Acct-Delay-Time", 0))
			return -1;
	}
	if (req->rpd->ses->ipv4) {
		if (rad_packet_add_ipaddr(req->pack, NULL, "Framed-IP-Address", req->rpd->ses->ipv4->peer_addr))
			return -1;
	}
	if (req->rpd->ses->ipv6) {
		if (rad_packet_add_ifid(req->pack, NULL, "Framed-Interface-Id", req->rpd->ses->ipv6->peer_intf_id))
			return -1;
		list_for_each_entry(a, &req->rpd->ses->ipv6->addr_list, entry) {
			if (rad_packet_add_ipv6prefix(req->pack, NULL, "Framed-IPv6-Prefix", &a->addr, a->prefix_len))
				return -1;
		}
	}

	return 0;
}

void rad_req_free(struct rad_req_t *req)
{
	if (req->serv)
		rad_server_put(req->serv, req->type);
	if (req->hnd.fd >= 0 )
		close(req->hnd.fd);
	if (req->pack)
		rad_packet_free(req->pack);
	if (req->reply)
		rad_packet_free(req->reply);
	_free(req);
}

static int make_socket(struct rad_req_t *req)
{
  struct sockaddr_in addr;

	req->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (req->hnd.fd < 0) {
		log_ppp_error("radius:socket: %s\n", strerror(errno));
		return -1;
	}
	
	fcntl(req->hnd.fd, F_SETFD, fcntl(req->hnd.fd, F_GETFD) | FD_CLOEXEC);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;

	if (conf_bind) {
		addr.sin_addr.s_addr = conf_bind;
		if (bind(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
			log_ppp_error("radius:bind: %s\n", strerror(errno));
			goto out_err;
		}
	}

	addr.sin_addr.s_addr = req->server_addr;
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

int rad_req_send(struct rad_req_t *req, int verbose)
{
	if (req->hnd.fd == -1 && make_socket(req))
		return -1;

	if (!req->pack->buf && rad_packet_build(req->pack, req->RA))
		goto out_err;
	
	if (verbose) {
		log_ppp_info1("send ");
		rad_packet_print(req->pack, req->serv, log_ppp_info1);
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
	struct triton_context_t *ctx = req->rpd->ses->ctrl->ctx;
	if (req->timeout.tpd)
		triton_timer_del(&req->timeout);
	triton_md_unregister_handler(&req->hnd);
	triton_context_unregister(&req->ctx);
	triton_context_wakeup(ctx);
}
static int rad_req_read(struct triton_md_handler_t *h)
{
	struct rad_req_t *req = container_of(h, typeof(*req), hnd);
	struct rad_packet_t *pack;
	int r;

	while (1) {
		r = rad_packet_recv(h->fd, &pack, NULL);
		
		if (pack) {
			if (req->reply)
				rad_packet_free(req->reply);
			req->reply = pack;
		}

		if (r)
			break;
	}

	req_wakeup(req);
	
	return 1;
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

	triton_context_register(&req->ctx, req->rpd->ses);
	triton_context_set_priority(&req->ctx, 1);
	triton_md_register_handler(&req->ctx, &req->hnd);
	triton_md_enable_handler(&req->hnd, MD_MODE_READ);

	req->timeout.period = timeout * 1000;
	triton_timer_add(&req->ctx, &req->timeout, 0);
	
	triton_context_wakeup(&req->ctx);

	triton_context_schedule();

	if (conf_verbose && req->reply) {
		log_ppp_info1("recv ");
		rad_packet_print(req->reply, req->serv, log_ppp_info1);
	}
	return 0;
}

static void req_init(void)
{
}

DEFINE_INIT(50, req_init);
