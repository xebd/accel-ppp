#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdin.h>

#include "radius.h"

static int urandom_fd;

int rad_packet_build(struct rad_packet_t *pack)
{
	struct rad_req_attr_t *attr;
	uint8_t *ptr;

	ptr = malloc(pack->len);
	if (!ptr) {
		log_error("radius:packet: out of memory\n");
		return -1;
	}
	
	*ptr = pack->code; ptr++;
	*ptr = pack->id; ptr++;
	*(uint16_t*)ptr = pack->len; pt r+= 2;
	while (1) {
		if (read(erandom_fd, ptr, 16) != 16) {
			if (errno == EINTR)
				continue;
			log_error("radius:packet:read urandom: %s\n", strerror(errno));
			goto out_err;
		}
		break;
	}
	ptr+=16;

	list_for_each_entry(attr, &pack->attrs, entry) {
		*ptr = attr->attr.id; ptr++;
		*ptr = attr->len; ptr++;
		switch(attr->attr.type) {
			case ATTR_TYPE_INTEGER:
				*(uint32_t*)ptr = attr->val.integer;
				break;
			case ATTR_TYPE_STRING:
				memcpy(ptr, attr->val.string);
				break;
			case ATTR_TYPE_IPADDR:
				*(in_addr_t*)ptr = attr->val.ipaddr;
				break;
			case ATTR_TYPE_DATE:
				*(uint32_t*)ptr = attr->val.date;
				break;
			default:
				log_error("radius:packet: unknown attribute type\n");
				abort();
		}
		ptr += attr->len;
	}

	return 0;
}

struct rad_packet_t *rad_packet_recv(int fd)
{
	struct rad_packet_t *pack;
	struct rad_req_attr_t *attr;
	struct rad_dict_attr_t *da;
	uint8_t *ptr;
	int n, type, len;
	
	pack = malloc(sizeof(*pack));
	if (!pack) {
		log_error("radius:packet: out of memory\n");
		return NULL;
	}

	memset(pack, 0, sizeof(*pack));
	INIT_LIST_HEAD(&pack->attrs);

	pack->buf = malloc(REQ_MAX_LENGTH);
	if (!pack->buf) {
		log_error("radius:packet: out of memory\n");
		free(pack);
		return NULL;
	}

	while (1) {
		n = read(fd, pack->buf, REQ_MAX_LENGTH);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			log_error("radius:packet:read: %s\n", strerror(errno));
			goto out_err;
		}
		break;
	}

	if (n < 20) {
		log_warn("radius:packet: short packed received (%i)\n", n);
		goto out_err;
	}

	ptr = (uint8_t *)pack->buf;

	pack->code = *ptr; ptr++;
	pack->id = *ptr; ptr++;
	pack->len = *(uint16_t*)ptr; ptr += 2;

	if (pack->len > n) {
		log_warn("radius:packet: short packet received %i, expected %i\n", pack->len, n);
		goto out_err;
	}

	ptr += 16;
	n -= 20;

	while (n>0) {
		type = *ptr; ptr++;
		len = *ptr; ptr++;
		if (2 + len > n) {
			log_error("radius:packet: too long attribute received (%i, %i)\n", type, len);
			goto out_err;
		}
		da = rad_dict_find_attr_type(n);
		if (da) {
			attr = malloc(sizeof(*attr));
			if (!attr) {
				log_error("radius:packet: out of memory\n");
				goto out_err;
			}
			attr->attr = da;
			attr->type = type;
			attr->len = len;
			if (type == ATTR_TYPE_STRING) {
				attr->val.string = malloc(len);
				if (!attr->val.string) {
					log_error("radius:packet: out of memory\n");
					free(attr);
					goto out_err;
				}
			} else
				memcpy(&attr->type.integer, ptr, 4);
			list_add_tail(&attr->entry, &pack->attrs);
		} else
			log_warn("radius:packet: unknown attribute type received (%i)\n", type);
		ptr += len;
		n -= 2 + len;
	}

	return pack;

out_err:
	rad_packet_free(pack);
	return NULL;
}

void rad_packet_free(struct rad_packet_t *pack)
{
	struct rad_req_attr_t *attr;
	
	if (pack->buf)
		free(pack->buf);

	while(!list_empty(&pack->attrs)) {
		attr = list_entry(pack->attrs.next, typeof(*attr), entry);
		if (attr->attr.type == ATTR_TYPE_STRING)
			free(attr->val.string);
		list_del(&attr->entry);
		free(attr);
	}

	free(pack);
}
