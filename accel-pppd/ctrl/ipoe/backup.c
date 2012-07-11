#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "triton.h"
#include "events.h"
#include "log.h"
#include "memdebug.h"

#include "ipoe.h"
#include "backup.h"
#include "ap_session_backup.h"

#define IPOE_TAG_HWADDR              1
#define IPOE_TAG_CLIENT_ID            2
#define IPOE_TAG_AGENT_CIRCUIT_ID    3
#define IPOE_TAG_AGENT_REMOTE_ID     4
#define IPOE_TAG_XID                 5
#define IPOE_TAG_GIADDR              6
#define IPOE_TAG_CALLING_SID         7
#define IPOE_TAG_CALLED_SID          8
#define IPOE_TAG_IFNAME              9

#define IPOE_TAG_IFINDEX           100


#define add_tag(id, data, size) if (!backup_add_tag(m, id, 0, data, size)) return -1;
#define add_tag_i(id, data, size) if (!backup_add_tag(m, id, 1, data, size)) return -1;

static LIST_HEAD(ds_list);

static void restore_complete(void);

#ifdef USE_BACKUP
static int session_save(struct ap_session *ses, struct backup_mod *m)
{
	struct ipoe_session *conn = container_of(ses, typeof(*conn), ses);

	add_tag(IPOE_TAG_HWADDR, conn->hwaddr, 6);
	add_tag(IPOE_TAG_CALLING_SID, ses->ctrl->calling_station_id, strlen(ses->ctrl->calling_station_id));
	add_tag(IPOE_TAG_CALLED_SID, ses->ctrl->called_station_id, strlen(ses->ctrl->called_station_id));
	add_tag(IPOE_TAG_XID, &conn->xid, 4);
	add_tag(IPOE_TAG_GIADDR, &conn->giaddr, 4);

	if (conn->client_id)
		add_tag(IPOE_TAG_CLIENT_ID, conn->client_id->data, conn->client_id->len);
	if (conn->agent_circuit_id)
		add_tag(IPOE_TAG_AGENT_CIRCUIT_ID, conn->agent_circuit_id->data, conn->agent_circuit_id->len);
	if (conn->agent_circuit_id)
		add_tag(IPOE_TAG_AGENT_REMOTE_ID, conn->agent_remote_id->data, conn->agent_remote_id->len);
	
	add_tag(IPOE_TAG_IFNAME, conn->serv->ifname, strlen(conn->serv->ifname) + 1);

	add_tag_i(IPOE_TAG_IFINDEX, &conn->ifindex, 4);

	return 0;
}

static int session_restore(struct ap_session *ses, struct backup_mod *m)
{
	struct ipoe_session *conn = container_of(ses, typeof(*conn), ses);


	return 0;
}

static void set_dhcpv4_opt(struct dhcp_opt **opt, struct backup_tag *t, uint8_t **ptr)
{
	*opt = (struct dhcp_opt *)(*ptr); 
	(*opt)->len = t->size;
	memcpy((*opt)->data, t->data, t->size);
	(*ptr) += sizeof(**opt) + t->size;
}

static struct ap_session *ctrl_restore(struct backup_mod *m)
{
	struct backup_tag *t;
	struct ipoe_session *ses;
	struct ipoe_serv *serv;
	struct backup_tag *ifname = NULL;
	int dlen = 0;
	uint8_t *ptr;
	struct ipoe_session_info *info;

	//if (!m->data->internal)
	//	return NULL;

	list_for_each_entry(t, &m->tag_list, entry) {
		switch(t->id) {
			case IPOE_TAG_CLIENT_ID:
			case IPOE_TAG_AGENT_CIRCUIT_ID:
			case IPOE_TAG_AGENT_REMOTE_ID:
				dlen += sizeof(struct dhcp_opt) + t->size;
				break;
			case IPOE_TAG_IFNAME:
				ifname = t;
				break;
		}
	}

	if (!ifname)
		return NULL;

	serv = ipoe_find_serv((char *)ifname->data);
	if (!serv)
		return NULL;

	ses = ipoe_session_alloc();
	if (!ses)
		return NULL;

	if (dlen)
		ses->data = _malloc(dlen);

	ptr = ses->data;

	list_for_each_entry(t, &m->tag_list, entry) {
		switch(t->id) {
			case IPOE_TAG_HWADDR:
				memcpy(ses->hwaddr, t->data, 6);
				break;
			case IPOE_TAG_CALLING_SID:
				ses->ctrl.calling_station_id = _malloc(t->size + 1);
				memcpy(ses->ctrl.calling_station_id, t->data, t->size);
				ses->ctrl.calling_station_id[t->size] = 0;
				break;
			case IPOE_TAG_CALLED_SID:
				ses->ctrl.called_station_id = _malloc(t->size + 1);
				memcpy(ses->ctrl.called_station_id, t->data, t->size);
				ses->ctrl.called_station_id[t->size] = 0;
				break;
			case IPOE_TAG_XID:
				ses->xid = *(uint32_t *)t->data;
				break;
			case IPOE_TAG_GIADDR:
				ses->giaddr = *(uint32_t *)t->data;
				break;
			case IPOE_TAG_CLIENT_ID:
				set_dhcpv4_opt(&ses->client_id, t, &ptr);
				break;
			case IPOE_TAG_AGENT_CIRCUIT_ID:
				set_dhcpv4_opt(&ses->agent_circuit_id, t, &ptr);
				break;
			case IPOE_TAG_AGENT_REMOTE_ID:
				set_dhcpv4_opt(&ses->agent_remote_id, t, &ptr);
				break;
			case IPOE_TAG_IFINDEX:
				ses->ifindex = *(uint32_t *)t->data;
				break;
		}
	}

	ses->serv = serv;
	
	triton_context_register(&ses->ctx, &ses->ses);
	triton_context_wakeup(&ses->ctx);

	pthread_mutex_lock(&serv->lock);
	list_add_tail(&ses->entry, &serv->sessions);
	pthread_mutex_unlock(&serv->lock);

	if (ses->ifindex != -1) {
		list_for_each_entry(info, &ds_list, entry) {
			if (info->ifindex == ses->ifindex) {
				list_del(&info->entry);
				_free(info);
				break;
			}
		}
	}

	return &ses->ses;
}

static struct backup_module mod = {
	.id = MODID_IPOE,
	.save = session_save,
	.restore = session_restore,
	.ctrl_restore = ctrl_restore,
	.restore_complete = restore_complete,
};
#endif

static void dump_sessions(void)
{
	ipoe_nl_get_sessions(&ds_list);

#ifndef USE_BACKUP
	restore_complete();
#endif
}

static void restore_complete(void)
{
	struct ipoe_session_info *info;

	while (!list_empty(&ds_list)) {
		info = list_entry(ds_list.next, typeof(*info), entry);
		ipoe_nl_delete(info->ifindex);
		list_del(&info->entry);
		_free(info);
	}
}

static void init(void)
{
	dump_sessions();

#ifdef USE_BACKUP
	backup_register_module(&mod);
#endif
}

DEFINE_INIT(100, init);

