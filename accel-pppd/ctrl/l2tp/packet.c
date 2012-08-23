#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "memdebug.h"

#include "l2tp.h"
#include "attr_defs.h"

static mempool_t attr_pool;
static mempool_t pack_pool;
static mempool_t buf_pool;

void l2tp_packet_print(struct l2tp_packet_t *pack, void (*print)(const char *fmt, ...))
{
	struct l2tp_attr_t *attr;
	struct l2tp_dict_value_t *val;

	if (pack->hdr.ver == 2) {
		print("[L2TP tid=%i sid=%i", ntohs(pack->hdr.tid), ntohs(pack->hdr.sid));
		log_ppp_debug(" Ns=%i Nr=%i", ntohs(pack->hdr.Ns), ntohs(pack->hdr.Nr));
	} else {
		print("[L2TP cid=%u", pack->hdr.cid);
		log_ppp_debug(" Ns=%i Nr=%i", ntohs(pack->hdr.Ns), ntohs(pack->hdr.Nr));
	}

	list_for_each_entry(attr, &pack->attrs, entry) {
		print(" <%s", attr->attr->name);
		val = l2tp_dict_find_value(attr->attr, attr->val);
		if (val)
			print(" %s", val->name);
		else {
			switch (attr->attr->type) {
				case ATTR_TYPE_INT16:
					print(" %i", attr->val.int16);
					break;
				case ATTR_TYPE_INT32:
					print(" %i", attr->val.int32);
					break;
				case ATTR_TYPE_STRING:
					print(" %s", attr->val.string);
					break;
			}
		}
		print(">");
	}

	print("]\n");
}

struct l2tp_packet_t *l2tp_packet_alloc(int ver, int msg_type, struct sockaddr_in *addr)
{
	struct l2tp_packet_t *pack = mempool_alloc(pack_pool);
	if (!pack)
		return NULL;
	
	memset(pack, 0, sizeof(*pack));
	INIT_LIST_HEAD(&pack->attrs);
	pack->hdr.ver = ver;
	pack->hdr.T = 1;
	pack->hdr.L = 1;
	pack->hdr.S = 1;
	memcpy(&pack->addr, addr, sizeof(*addr));

	if (msg_type) {
		if (l2tp_packet_add_int16(pack, Message_Type, msg_type, 1)) {
			mempool_free(pack);
			return NULL;
		}
	}

	return pack;
}

void l2tp_packet_free(struct l2tp_packet_t *pack)
{
	struct l2tp_attr_t *attr;

	while (!list_empty(&pack->attrs)) {
		attr = list_entry(pack->attrs.next, typeof(*attr), entry);
		if (attr->attr->type == ATTR_TYPE_OCTETS || attr->attr->type == ATTR_TYPE_STRING)
			_free(attr->val.octets);
		list_del(&attr->entry);
		mempool_free(attr);
	}

	mempool_free(pack);
}

int l2tp_recv(int fd, struct l2tp_packet_t **p, struct in_pktinfo *pkt_info)
{
	int n, length;
	uint8_t *buf;
	struct l2tp_hdr_t *hdr;
	struct l2tp_avp_t *avp;
	struct l2tp_dict_attr_t *da;
	struct l2tp_attr_t *attr, *RV = NULL;
	uint8_t *ptr;
	struct l2tp_packet_t *pack;
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	struct msghdr msg;
	char msg_control[128];
	struct cmsghdr *cmsg;

  *p = NULL;

	if (pkt_info) {
		memset(&msg, 0, sizeof(msg));
		msg.msg_control = msg_control;
		msg.msg_controllen = 128;
		
		n = recvmsg(fd, &msg, MSG_PEEK);
		
		if (n < 0) {
			if (errno == EAGAIN)
				return -1;
			log_error("l2tp: recvmsg: %s\n", strerror(errno));
			return 0;
		}
		
		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
				memcpy(pkt_info, CMSG_DATA(cmsg), sizeof(*pkt_info));
				break;
			}
		}
	}

	buf = mempool_alloc(buf_pool);
	if (!buf) {
		log_emerg("l2tp: out of memory\n");
		return 0;
	}
	hdr = (struct l2tp_hdr_t *)buf;
	ptr = (uint8_t *)(hdr + 1);

	n = recvfrom(fd, buf, L2TP_MAX_PACKET_SIZE, 0, &addr, &len);

	if (n < 0) {
		mempool_free(buf);
		if (errno == EAGAIN) {
			return -1;
		} else if (errno == ECONNREFUSED) {
			return -2;
		}
		log_error("l2tp: recv: %s\n", strerror(errno));
		return 0;
	}

	if (n < sizeof(*hdr)) {
		if (conf_verbose)
			log_warn("l2tp: short packet received (%i/%i)\n", n, sizeof(*hdr));
		goto out_err_hdr;
	}

	if (n < ntohs(hdr->length)) {
		if (conf_verbose)
			log_warn("l2tp: short packet received (%i/%i)\n", n, ntohs(hdr->length));
		goto out_err_hdr;
	}

	if (hdr->T == 0)
		goto out_err_hdr;

	if (hdr->ver == 2) {
		if (hdr->L == 0) {
			if (conf_verbose)
				log_warn("l2tp: incorrect message received (L=0)\n");
			if (!conf_avp_permissive)
			    goto out_err_hdr;
		}

		if (hdr->S == 0) {
			if (conf_verbose)
				log_warn("l2tp: incorrect message received (S=0)\n");
			if (!conf_avp_permissive)
			    goto out_err_hdr;
		}

		if (hdr->O == 1) {
			if (conf_verbose)
				log_warn("l2tp: incorrect message received (O=1)\n");
			if (!conf_avp_permissive)
			    goto out_err_hdr;
		}
	} else if (hdr->ver != 3) {
		if (conf_verbose)
			log_warn("l2tp: protocol version %i is not supported\n", hdr->ver);
		goto out_err_hdr;
	}

	pack = mempool_alloc(pack_pool);
	if (!pack) {
		log_emerg("l2tp: out of memory\n");
		goto out_err_hdr;
	}

	memset(pack, 0, sizeof(*pack));
	INIT_LIST_HEAD(&pack->attrs);

	memcpy(&pack->addr, &addr, sizeof(addr));
	memcpy(&pack->hdr, hdr, sizeof(*hdr));
	length = ntohs(hdr->length) - sizeof(*hdr);

	while (length) {
		*(uint16_t *)ptr = ntohs(*(uint16_t *)ptr);
		avp = (struct l2tp_avp_t *)ptr;

		if (avp->length > length) {
			if (conf_verbose)
				log_warn("l2tp: incorrect avp received (exceeds message length)\n");
			goto out_err;
		}

		if (avp->vendor)
			goto skip;

		da = l2tp_dict_find_attr_by_id(ntohs(avp->type));
		if (!da) {
			if (conf_verbose)
				log_warn("l2tp: unknown avp received (type=%i, M=%u)\n", ntohs(avp->type), avp->M);
			if (avp->M && !conf_avp_permissive)
				goto out_err;
		} else {
			if (da->M != -1 && da->M != avp->M) {
				if (conf_verbose)
					log_warn("l2tp: incorrect avp received (type=%i, M=%i, must be %i)\n", ntohs(avp->type), avp->M, da->M);
				if (!conf_avp_permissive)
				    goto out_err;
			}

			if (da->H != -1 && da->H != avp->H) {
				if (conf_verbose)
					log_warn("l2tp: incorrect avp received (type=%i, H=%i, must be %i)\n", ntohs(avp->type), avp->H, da->H);
				if (!conf_avp_permissive)
				    goto out_err;
			}

			if (avp->H) {
				if (!RV) {
					if (conf_verbose)
						log_warn("l2tp: incorrect avp received (type=%i, H=1, but Random-Vector is not received)\n", ntohs(avp->type));
					goto out_err;
				} else {
					if (conf_verbose)
						log_warn("l2tp: hidden avp received (type=%i)\n", ntohs(avp->type));
				}
			}

			attr = mempool_alloc(attr_pool);
			memset(attr, 0, sizeof(*attr));
			list_add_tail(&attr->entry, &pack->attrs);

			attr->attr = da;
			attr->M = avp->M;
			attr->H = avp->H;
			attr->length = avp->length - sizeof(*avp);
			
			if (attr->attr->id == Random_Vector)
				RV = attr;

			switch (da->type) {
				case ATTR_TYPE_INT16:
					if (avp->length != sizeof(*avp) + 2)
						goto out_err_len;
					attr->val.uint16 = ntohs(*(uint16_t *)avp->val);
					break;
				case ATTR_TYPE_INT32:
					if (avp->length != sizeof(*avp) + 4)
						goto out_err_len;
					attr->val.uint32 = ntohl(*(uint32_t *)avp->val);
					break;
				case ATTR_TYPE_INT64:
					if (avp->length != sizeof(*avp) + 8)
						goto out_err_len;
					attr->val.uint64 = *(uint64_t *)avp->val;
					break;
				case ATTR_TYPE_OCTETS:
					attr->val.octets = _malloc(attr->length);
					if (!attr->val.octets)
						goto out_err_mem;
					memcpy(attr->val.octets, avp->val, attr->length);
					break;
				case ATTR_TYPE_STRING:
					attr->val.string = _malloc(attr->length + 1);
					if (!attr->val.string)
						goto out_err_mem;
					memcpy(attr->val.string, avp->val, attr->length);
					attr->val.string[attr->length] = 0;
					break;
			}
		}
skip:
		ptr += avp->length;
		length -= avp->length;
	}

	*p = pack;

	mempool_free(buf);

	return 0;

out_err:
	l2tp_packet_free(pack);
out_err_hdr:
	mempool_free(buf);
	return 0;
out_err_len:
	if (conf_verbose)
		log_warn("l2tp: incorrect avp received (type=%i, incorrect length %i)\n", ntohs(avp->type), avp->length);
	goto out_err;
out_err_mem:
	log_emerg("l2tp: out of memory\n");
	goto out_err;
}

int l2tp_packet_send(int sock, struct l2tp_packet_t *pack)
{
	uint8_t *buf = mempool_alloc(buf_pool);
	struct l2tp_avp_t *avp;
	struct l2tp_attr_t *attr;
	uint8_t *ptr;
	int n;
	int len = sizeof(pack->hdr);

	if (!buf) {
		log_emerg("l2tp: out of memory\n");
		return -1;
	}

	memset(buf, 0, L2TP_MAX_PACKET_SIZE);

	ptr = buf + sizeof(pack->hdr);

	list_for_each_entry(attr, &pack->attrs, entry) {
		if (len + sizeof(*avp) + attr->length >= L2TP_MAX_PACKET_SIZE) {
			log_error("l2tp: cann't send packet (exceeds maximum size)\n");
			mempool_free(buf);
			return -1;
		}
		avp = (struct l2tp_avp_t *)ptr;
		avp->type = htons(attr->attr->id);
		avp->M = attr->M;
		avp->H = attr->H;
		avp->length = sizeof(*avp) + attr->length;
		*(uint16_t *)ptr = htons(*(uint16_t *)ptr);
		switch (attr->attr->type) {
			case ATTR_TYPE_INT16:
				*(int16_t *)avp->val = htons(attr->val.int16);
				break;
			case ATTR_TYPE_INT32:
				*(int32_t *)avp->val = htonl(attr->val.int32);
				break;
			case ATTR_TYPE_STRING:
			case ATTR_TYPE_OCTETS:
				memcpy(avp->val, attr->val.string, attr->length);
				break;
		}

		ptr += sizeof(*avp) + attr->length;
		len += sizeof(*avp) + attr->length;
	}

	pack->hdr.length = htons(len);
	memcpy(buf, &pack->hdr, sizeof(pack->hdr));

	n = write(sock, buf, ntohs(pack->hdr.length));
	
	mempool_free(buf);

	if (n < 0) {
		if (errno == EAGAIN) {
			if (conf_verbose)
				log_warn("l2tp: buffer overflow (packet lost)\n");
		} else {
			if (conf_verbose)
				log_warn("l2tp: sendto: %s\n", strerror(errno));
			return -1;
		}
	}

	if (n != ntohs(pack->hdr.length)) {
		if (conf_verbose)
			log_warn("l2tp: short write (%i/%i)\n", n, ntohs(pack->hdr.length));
	}

	return 0;
}

static struct l2tp_attr_t *attr_alloc(int id, int M)
{
	struct l2tp_attr_t *attr;
	struct l2tp_dict_attr_t *da;

	da = l2tp_dict_find_attr_by_id(id);
	if (!da)
		return NULL;

	attr = mempool_alloc(attr_pool);
	if (!attr) {
		log_emerg("l2tp: out of memory\n");
		return NULL;
	}

	memset(attr, 0, sizeof(*attr));

	attr->attr = da;

	if (da->M != -1)
		attr->M = da->M;
	else
		attr->M = M;

	//if (da->H != -1)
	//attr->H = da->H;

	return attr;
}

int l2tp_packet_add_int16(struct l2tp_packet_t *pack, int id, int16_t val, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M);

	if (!attr)
		return -1;

	attr->length = 2;
	attr->val.int16 = val;
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;
}
int l2tp_packet_add_int32(struct l2tp_packet_t *pack, int id, int32_t val, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M);

	if (!attr)
		return -1;

	attr->length = 4;
	attr->val.int32 = val;
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;
}
int l2tp_packet_add_string(struct l2tp_packet_t *pack, int id, const char *val, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M);

	if (!attr)
		return -1;

	attr->length = strlen(val);
	attr->val.string = _strdup(val);
	if (!attr->val.string) {
		log_emerg("l2tp: out of memory\n");
		mempool_free(attr);
		return -1;
	}
	memcpy(attr->val.string, val, attr->length);
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;
}

int l2tp_packet_add_octets(struct l2tp_packet_t *pack, int id, const uint8_t *val, int size, int M)
{
	struct l2tp_attr_t *attr = attr_alloc(id, M);

	if (!attr)
		return -1;

	attr->length = size;
	attr->val.octets = _malloc(size);
	if (!attr->val.string) {
		log_emerg("l2tp: out of memory\n");
		mempool_free(attr);
		return -1;
	}
	memcpy(attr->val.octets, val, attr->length);
	list_add_tail(&attr->entry, &pack->attrs);

	return 0;
}

static void init(void)
{
	attr_pool = mempool_create(sizeof(struct l2tp_attr_t));
	pack_pool = mempool_create(sizeof(struct l2tp_packet_t));
	buf_pool = mempool_create(L2TP_MAX_PACKET_SIZE);
}

DEFINE_INIT(21, init);
