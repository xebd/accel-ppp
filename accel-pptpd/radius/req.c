#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "triton.h"
#include "log.h"
#include "radius.h"


static int rad_req_read(struct triton_md_handler_t *h);
static void rad_req_timeout(struct triton_timer_t *t);

struct rad_req_t *rad_rec_alloc(struct radius_pd_t *rpd, int code, const char *username)
{
	struct rad_req_t *req = malloc(sizeof(*req));

	if (!req)
		return NULL;

	memset(req, 0, sizeof(*req));
	INIT_LIST_HEAD(&req->pack.attrs);
	req->rpd = rpd;
	req->pack.code = code;
	req->pack.len = 20;
	req->hnd.fd = -1;
	req->hnd.read = rad_req_read;
	req->timeout.expire = rad_req_timeout;

	if (rad_req_add_str(req, "User-Name", username, strlen(username)))
		goto out_err;
	if (conf_nas_identifier)
		if (rad_req_add_str(req, "NAS-Identifier", conf_nas_identifier, strlen(conf_nas_identifier)))
			goto out_err;
	if (rad_req_add_int(req, "NAS-Port-Id", rpd->ppp->unit_idx))
		goto out_err;
	if (rad_req_add_str(req, "NAS-Port-Type", "Sync", 4))
		goto out_err;
	if (rad_req_add_str(req, "Service-Type", "Framed-User", 11))
		goto out_err;
	if (rad_req_add_str(req, "Framed-Protocol", "PPP", 3))
		goto out_err;

	return req;

out_err:
	rad_req_free(req);
	return NULL;
}

void rad_rec_free(struct rad_req_t *req)
{

}

int rad_req_send(struct rad_req_t *req)
{
  struct sockaddr_in addr;
	int n;

	if (req->hnd.fd == -1) {
		req->hnd.fd = socket(PF_INET, SOCK_DGRAM ,0);
		if (!req->hnd.fd) {
			log_error("radius:socket: %s\n", strerror(errno));
			return -1;
		}

		if (conf_nas_ip_address) {
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = htonl(inet_addr(conf_nas_ip_address));
			if (bind(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
				log_error("radius:bind: %s\n", strerror(errno));
				goto out_err;
			}
		}

		addr.sin_addr.s_addr = htonl(inet_addr(req->server_name));
		addr.sin_port = htons(req->server_port);

		if (connect(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
			log_error("radius:connect: %s\n", strerror(errno));
			goto out_err;
		}

		if (fcntl(req->hnd.fd, F_SETFL, O_NONBLOCK)) {
			log_error("radius: failed to set nonblocking mode: %s\n", strerror(errno));
			goto out_err;
		}

		if (rad_packet_build(&req->pack))
			goto out_err;
	}
	
	while (1) {
		n = write(req->hnd.fd, req->pack.buf, req->pack.len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_error("radius:write: %s\n", strerror(errno));
			goto out_err_free_pack;
		} else if (n != req->pack.len) {
			log_error("radius:write: short write %i, excpected %i\n", n, req->pack.len);
			goto out_err_free_pack;
		}
		break;
	}

	return 0;

out_err_free_pack:
	rad_packet_free(&req->pack);
out_err:
	close(req->hnd.fd);
	req->hnd.fd = -1;
	return -1;
}

int rad_req_add_int(struct rad_req_t *req, const char *name, int val)
{
	struct rad_req_attr_t *ra;
	struct rad_dict_attr_t *attr;

	if (req->pack.len + 2 + 4 >= REQ_LENGTH_MAX)
		return -1;

	attr = rad_dict_find_attr(name);
	if (!attr)
		return -1;
	
	ra = malloc(sizeof(*ra));
	if (!ra)
		return -1;

	ra->attr = attr;
	ra->len = 4;
	ra->val.integer = val;
	list_add_tail(&ra->entry, &req->pack.attrs);
	req->pack.len += 2 + 4;

	return 0;
}

int rad_req_add_str(struct rad_req_t *req, const char *name, const char *val, int len)
{
	struct rad_req_attr_t *ra;
	struct rad_dict_attr_t *attr;

	if (req->pack.len + 2 + len >= REQ_LENGTH_MAX)
		return -1;

	attr = rad_dict_find_attr(name);
	if (!attr)
		return -1;
	
	ra = malloc(sizeof(*ra));
	if (!ra)
		return -1;

	ra->attr = attr;
	ra->len = len;
	ra->val.string = strdup(val);
	list_add_tail(&ra->entry, &req->pack.attrs);
	req->pack.len += 2 + len;

	return 0;
}

int rad_req_add_val(struct rad_req_t *req, const char *name, const char *val, int len)
{
	struct rad_req_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_value_t *v;

	if (req->pack.len + 2 + len >= REQ_LENGTH_MAX)
		return -1;

	attr = rad_dict_find_attr(name);
	if (!attr)
		return -1;
	
	v = rad_dict_find_val(attr, val);
	if (!v)
		return -1;
	
	ra = malloc(sizeof(*ra));
	if (!ra)
		return -1;

	ra->attr = attr;
	ra->len = len;
	ra->val = v->val;
	list_add_tail(&ra->entry, &req->pack.attrs);
	req->pack.len += 2 + len;

	return 0;
}

static int rad_req_read(struct triton_md_handler_t *h)
{
	struct rad_req_t *req = container_of(h, typeof(*req), hnd);

	req->reply = rad_packet_recv(h->fd);

	return 0;
}
static void rad_req_timeout(struct triton_timer_t *t)
{
}

int rad_req_wait(struct rad_req_t *req, int timeout)
{
	triton_md_register_handler(req->rpd->ppp->ctrl->ctx, &req->hnd);
	if (triton_md_enable_handler(&req->hnd, MD_MODE_READ))
		return -1;

	req->timeout.period = timeout * 1000;
	if (triton_timer_add(req->rpd->ppp->ctrl->ctx, &req->timeout, 0))
		return -1;

	triton_ctx_schedule(&req->hnd, &req->timeout);

	triton_timer_del(&req->timeout);
	triton_md_unregister_handler(&req->hnd);

	return 0;
}

