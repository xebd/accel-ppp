#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "log.h"

#include "radius.h"

struct rad_packet_t *rad_packet_alloc(int code)
{
	struct rad_packet_t *pack;

	pack = malloc(sizeof(*pack));
	if (!pack) {
		log_error("radius:packet: out of memory\n");
		return NULL;
	}

	memset(pack, 0, sizeof(*pack));
	pack->code = code;
	pack->len = 20;
	pack->id = 1;
	INIT_LIST_HEAD(&pack->attrs);

	return pack;
}

void print_buf(uint8_t *buf,int size)
{
	int i;
	for(i=0;i<size;i++)
		printf("%x ",buf[i]);
	printf("\n");
}

int rad_packet_build(struct rad_packet_t *pack, uint8_t *RA)
{
	struct rad_req_attr_t *attr;
	uint8_t *ptr;

	ptr = malloc(pack->len);
	if (!ptr) {
		log_error("radius:packet: out of memory\n");
		return -1;
	}
	
	pack->buf = ptr;
	*ptr = pack->code; ptr++;
	*ptr = pack->id; ptr++;
	*(uint16_t*)ptr = htons(pack->len); ptr+= 2;
	memcpy(ptr, RA, 16);	ptr+=16;

	list_for_each_entry(attr, &pack->attrs, entry) {
		*ptr = attr->attr->id; ptr++;
		*ptr = attr->len + 2; ptr++;
		switch(attr->attr->type) {
			case ATTR_TYPE_INTEGER:
				*(uint32_t*)ptr = htonl(attr->val.integer);
				break;
			case ATTR_TYPE_STRING:
				memcpy(ptr, attr->val.string, attr->len);
				break;
			case ATTR_TYPE_IPADDR:
				*(in_addr_t*)ptr = attr->val.ipaddr;
				break;
			case ATTR_TYPE_DATE:
				*(uint32_t*)ptr = htonl(attr->val.date);
				break;
			default:
				log_error("radius:packet:BUG: unknown attribute type\n");
				abort();
		}
		ptr += attr->len;
	}

	print_buf(pack->buf, pack->len);

	return 0;
}

struct rad_packet_t *rad_packet_recv(int fd)
{
	struct rad_packet_t *pack;
	struct rad_req_attr_t *attr;
	struct rad_dict_attr_t *da;
	uint8_t *ptr;
	int n, id, len;

	pack = rad_packet_alloc(0);
	if (!pack)
		return NULL;

	pack->buf = malloc(REQ_LENGTH_MAX);
	if (!pack->buf) {
		log_error("radius:packet: out of memory\n");
		goto out_err;
	}

	while (1) {
		n = read(fd, pack->buf, REQ_LENGTH_MAX);
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
	pack->len = ntohs(*(uint16_t*)ptr); ptr += 2;

	if (pack->len > n) {
		log_warn("radius:packet: short packet received %i, expected %i\n", pack->len, n);
		goto out_err;
	}

	ptr += 16;
	n -= 20;

	while (n>0) {
		id = *ptr; ptr++;
		len = *ptr - 2; ptr++;
		if (len < 0) {
			log_warn("radius:packet short attribute len received\n");
			goto out_err;
		}
		if (2 + len > n) {
			log_warn("radius:packet: too long attribute received (%i, %i)\n", id, len);
			goto out_err;
		}
		da = rad_dict_find_attr_id(id);
		if (da) {
			attr = malloc(sizeof(*attr));
			if (!attr) {
				log_error("radius:packet: out of memory\n");
				goto out_err;
			}
			attr->attr = da;
			attr->len = len;
			switch (da->type) {
				case ATTR_TYPE_STRING:
					attr->val.string = malloc(len+1);
					if (!attr->val.string) {
						log_error("radius:packet: out of memory\n");
						free(attr);
						goto out_err;
					}
					memcpy(attr->val.string, ptr, len);
					attr->val.string[len] = 0;
					break;
				case ATTR_TYPE_DATE:
				case ATTR_TYPE_INTEGER:
					attr->val.integer = ntohl(*(uint32_t*)ptr);
					break;
				case ATTR_TYPE_IPADDR:
					attr->val.integer = *(uint32_t*)ptr;
					break;
			}
			list_add_tail(&attr->entry, &pack->attrs);
		} else
			log_warn("radius:packet: unknown attribute received (%i)\n", id);
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
		if (attr->attr->type == ATTR_TYPE_STRING)
			free((char*)attr->val.string);
		list_del(&attr->entry);
		free(attr);
	}

	free(pack);
}

void rad_packet_print(struct rad_packet_t *pack, void (*print)(const char *fmt, ...))
{
	struct rad_req_attr_t *attr;
	struct rad_dict_value_t *val;
	
	print("[RADIUS ");
	switch(pack->code) {
		case CODE_ACCESS_REQUEST:
			print("Access-Request");
			break;
		case CODE_ACCESS_CHALLENGE:
			print("Access-Challenge");
			break;
		case CODE_ACCESS_ACCEPT:
			print("Access-Accept");
			break;
		case CODE_ACCESS_REJECT:
			print("Access-Reject");
			break;
		default:
			print("Unknown (%i)", pack->code);
	}
	print(" id=%x", pack->id);

	list_for_each_entry(attr, &pack->attrs, entry) {
		print(" <%s ", attr->attr->name);
		if (attr->printable) {
			switch (attr->attr->type) {
				case ATTR_TYPE_INTEGER:
					val = rad_dict_find_val(attr->attr, attr->val);
					if (val)
						print("%s", val->name);
					else
						print("%i", attr->val.integer);
					break;
				case ATTR_TYPE_STRING:
					print("\"%s\"", attr->val.string);
					break;
				case ATTR_TYPE_IPADDR:
					print("%i.%i.%i.%i", attr->val.ipaddr & 0xff, (attr->val.ipaddr >> 8) & 0xff, (attr->val.ipaddr >> 16) & 0xff, (attr->val.ipaddr >> 24) & 0xff);
					break;
			}
		}
		print(">");
	}
	print("]\n");
}

