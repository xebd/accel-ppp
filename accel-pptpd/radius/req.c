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
	req->hnd.read = rad_req_read;
	req->timeout.expire = rad_req_timeout;

	while (1) {
		if (read(urandom_fd, req->RA, 16) != 16) {
			if (errno == EINTR)
				continue;
			log_error("radius:req:read urandom: %s\n", strerror(errno));
			goto out_err;
		}
		break;
	}

	req->pack = rad_packet_alloc(code);
	if (!req->pack)
		goto out_err;

	if (rad_req_add_str(req, "User-Name", username, strlen(username), 1))
		goto out_err;
	if (conf_nas_identifier)
		if (rad_req_add_str(req, "NAS-Identifier", conf_nas_identifier, strlen(conf_nas_identifier), 1))
			goto out_err;
	if (rad_req_add_int(req, "NAS-Port-Id", rpd->ppp->unit_idx))
		goto out_err;
	if (rad_req_add_val(req, "NAS-Port-Type", "Sync", 4))
		goto out_err;
	if (rad_req_add_val(req, "Service-Type", "Framed-User", 4))
		goto out_err;
	if (rad_req_add_val(req, "Framed-Protocol", "PPP", 4))
		goto out_err;

	return req;

out_err:
	rad_req_free(req);
	return NULL;
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

int rad_req_send(struct rad_req_t *req)
{
  struct sockaddr_in addr;
	int n;

	if (req->hnd.fd == -1) {
		req->hnd.fd = socket(PF_INET, SOCK_DGRAM, 0);
		if (req->hnd.fd < 0) {
			log_error("radius:socket: %s\n", strerror(errno));
			return -1;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;

		if (conf_nas_ip_address) {
			addr.sin_addr.s_addr = inet_addr(conf_nas_ip_address);
			if (bind(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
				log_error("radius:bind: %s\n", strerror(errno));
				goto out_err;
			}
		}

		addr.sin_addr.s_addr = inet_addr(req->server_name);
		addr.sin_port = htons(req->server_port);

		if (connect(req->hnd.fd, (struct sockaddr *) &addr, sizeof(addr))) {
			log_error("radius:connect: %s\n", strerror(errno));
			goto out_err;
		}

		if (fcntl(req->hnd.fd, F_SETFL, O_NONBLOCK)) {
			log_error("radius: failed to set nonblocking mode: %s\n", strerror(errno));
			goto out_err;
		}

		if (rad_packet_build(req->pack, req->RA))
			goto out_err;
	}
	
	if (conf_verbose) {
		log_debug("send ");
		rad_packet_print(req->pack, log_debug);
	}

	while (1) {
		n = write(req->hnd.fd, req->pack->buf, req->pack->len);
		//n = sendto(req->hnd.fd, req->pack->buf, req->pack->len, 0, &addr, sizeof(addr));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_error("radius:write: %s\n", strerror(errno));
			goto out_err;
		} else if (n != req->pack->len) {
			log_error("radius:write: short write %i, excpected %i\n", n, req->pack->len);
			goto out_err;
		}
		break;
	}

	return 0;

out_err:
	close(req->hnd.fd);
	req->hnd.fd = -1;
	return -1;
}

int rad_req_add_int(struct rad_req_t *req, const char *name, int val)
{
	struct rad_req_attr_t *ra;
	struct rad_dict_attr_t *attr;

	if (req->pack->len + 2 + 4 >= REQ_LENGTH_MAX)
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
	ra->printable = 1;
	list_add_tail(&ra->entry, &req->pack->attrs);
	req->pack->len += 2 + 4;

	return 0;
}

int rad_req_add_str(struct rad_req_t *req, const char *name, const char *val, int len, int printable)
{
	struct rad_req_attr_t *ra;
	struct rad_dict_attr_t *attr;

	if (req->pack->len + 2 + len >= REQ_LENGTH_MAX)
		return -1;

	attr = rad_dict_find_attr(name);
	if (!attr)
		return -1;
	
	ra = malloc(sizeof(*ra));
	if (!ra) {
		log_error("radius: aout of memory\n");
		return -1;
	}

	ra->attr = attr;
	ra->len = len;
	ra->val.string = malloc(len+1);
	if (!ra->val.string) {
		log_error("radius: out of memory\n");
		free(ra);
		return -1;
	}
	memcpy(ra->val.string, val, len);
	ra->val.string[len] = 0;
	ra->printable = printable;
	list_add_tail(&ra->entry, &req->pack->attrs);
	req->pack->len += 2 + len;

	return 0;
}

int rad_req_add_val(struct rad_req_t *req, const char *name, const char *val, int len)
{
	struct rad_req_attr_t *ra;
	struct rad_dict_attr_t *attr;
	struct rad_dict_value_t *v;

	if (req->pack->len + 2 + len >= REQ_LENGTH_MAX)
		return -1;

	attr = rad_dict_find_attr(name);
	if (!attr)
		return -1;
	
	v = rad_dict_find_val_name(attr, val);
	if (!v)
		return -1;
	
	ra = malloc(sizeof(*ra));
	if (!ra)
		return -1;

	ra->attr = attr;
	ra->len = len;
	ra->val = v->val;
	ra->printable = 1;
	list_add_tail(&ra->entry, &req->pack->attrs);
	req->pack->len += 2 + len;

	return 0;
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

	req->reply = rad_packet_recv(h->fd);
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
	triton_context_register(&req->ctx);
	triton_md_register_handler(&req->ctx, &req->hnd);
	if (triton_md_enable_handler(&req->hnd, MD_MODE_READ))
		return -1;

	req->timeout.period = timeout * 1000;
	if (triton_timer_add(&req->ctx, &req->timeout, 0))
		return -1;

	triton_context_schedule(req->rpd->ppp->ctrl->ctx);

	if (conf_verbose && req->reply) {
		log_debug("recv ");
		rad_packet_print(req->reply, log_debug);
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
