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
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/route.h>

#include <pcre.h>

#include "events.h"
#include "list.h"
#include "triton.h"
#include "log.h"
#include "mempool.h"
#include "utils.h"
#include "cli.h"
#include "ap_session.h"
#include "pwdb.h"
#include "ipdb.h"

#include "iputils.h"
#include "connlimit.h"
#ifdef RADIUS
#include "radius.h"
#endif

#include "ipoe.h"

#include "memdebug.h"

#define USERNAME_IFNAME 0
#define USERNAME_LUA 1

#define MODE_L2 0
#define MODE_L3 1

static int conf_dhcpv4 = 1;
static int conf_up = 0;
static int conf_mode = 0;
static int conf_shared = 1;
static int conf_ifcfg = 1;
//static int conf_dhcpv6;
static int conf_username;
static int conf_unit_cache;
static int conf_noauth;
#ifdef RADIUS
static int conf_attr_dhcp_client_ip;
static int conf_attr_dhcp_router_ip;
static int conf_attr_dhcp_mask;
static int conf_attr_l4_redirect;
#endif
static int conf_l4_redirect_table;
static int conf_l4_redirect_on_reject;
static const char *conf_relay;

#ifdef USE_LUA
static const char *conf_lua_username_func;
#endif

static int conf_offer_timeout = 3;
static in_addr_t conf_gw_address;
static int conf_netmask = 24;
static int conf_lease_time = 600;
static int conf_lease_timeout = 660;
static int conf_verbose;
static const char *conf_agent_remote_id;

static unsigned int stat_starting;
static unsigned int stat_active;

static mempool_t ses_pool;

static LIST_HEAD(serv_list);

struct ifaddr
{
	struct list_head entry;
	in_addr_t addr;
	int refs;
};

struct iplink_arg
{
	pcre *re;
	const char *opt;
};

struct unit_cache
{
	struct list_head entry;
	int ifindex;
};

struct l4_redirect
{
	struct list_head entry;
	int ifindex;
	in_addr_t addr;
	time_t timeout;
};

static pthread_mutex_t uc_lock = PTHREAD_MUTEX_INITIALIZER;
static LIST_HEAD(uc_list);
static int uc_size;
static mempool_t uc_pool;

static pthread_rwlock_t l4_list_lock = PTHREAD_RWLOCK_INITIALIZER;
static LIST_HEAD(l4_redirect_list);
static struct triton_timer_t l4_redirect_timer;
static struct triton_context_t l4_redirect_ctx;

static void ipoe_session_finished(struct ap_session *s);
static void ipoe_drop_sessions(struct ipoe_serv *serv, struct ipoe_session *skip);
static void ipoe_serv_close(struct triton_context_t *ctx);
static void __ipoe_session_activate(struct ipoe_session *ses);
static void ipoe_ses_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack);

static struct ipoe_session *ipoe_session_lookup(struct ipoe_serv *serv, struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses;
	
	uint8_t *agent_circuit_id = NULL;
	uint8_t *agent_remote_id = NULL;

	if (pack->relay_agent && dhcpv4_parse_opt82(pack->relay_agent, &agent_circuit_id, &agent_remote_id)) {
		agent_circuit_id = NULL;
		agent_remote_id = NULL;
	}

	list_for_each_entry(ses, &serv->sessions, entry) {
		if (agent_circuit_id && !ses->agent_circuit_id)
			continue;
		
		if (agent_remote_id && !ses->agent_remote_id)
			continue;
		
		if (!agent_circuit_id && ses->agent_circuit_id)
			continue;
		
		if (!agent_remote_id && ses->agent_remote_id)
			continue;
		
		if (agent_circuit_id) {
			if (*agent_circuit_id != *ses->agent_circuit_id)
				continue;
			if (memcmp(agent_circuit_id + 1, ses->agent_circuit_id + 1, *agent_circuit_id))
				continue;
		}
		
		if (agent_remote_id) {
			if (*agent_remote_id != *ses->agent_remote_id)
				continue;
			if (memcmp(agent_remote_id + 1, ses->agent_remote_id + 1, *agent_remote_id))
				continue;
		
			return ses;
		}
			
		if (memcmp(pack->hdr->chaddr, ses->hwaddr, 6))
			continue;
	
		return ses;
		
		/*if (pack->client_id && !ses->client_id)
			continue;
		
		if (!pack->client_id && ses->client_id)
			continue;
		
		if (pack->client_id) {
			if (pack->client_id->len != ses->client_id->len)
				continue;
			if (memcmp(pack->client_id->data, ses->client_id->data, pack->client_id->len))
				continue;
		}

		ses1 = ses;

		if (pack->hdr->xid != ses->xid)
			continue;

		return ses;*/
	}

	return NULL;
}

static void ipoe_session_timeout(struct triton_timer_t *t)
{
	struct ipoe_session *ses = container_of(t, typeof(*ses), timer);

	triton_timer_del(t);

	log_ppp_info2("ipoe: session timed out\n");

	ap_session_terminate(&ses->ses, TERM_LOST_CARRIER, 0);
}

static void ipoe_session_set_username(struct ipoe_session *ses)
{
#ifdef USE_LUA
	if (conf_username == USERNAME_LUA) {
		ipoe_lua_set_username(ses, conf_lua_username_func);
	} else
#endif
	ses->ses.username = _strdup(ses->ses.ifname);
}

static void l4_redirect_list_add(in_addr_t addr, int ifindex)
{
	struct l4_redirect *n = _malloc(sizeof(*n));
	struct timespec ts;

	if (!n)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memset(n, 0, sizeof(*n));
	n->addr = addr;
	n->ifindex = ifindex;
	n->timeout = ts.tv_sec + conf_l4_redirect_on_reject;
	
	ipoe_nl_modify(ifindex, addr, 1, NULL, NULL);
	iprule_add(addr, conf_l4_redirect_table);

	pthread_rwlock_wrlock(&l4_list_lock);
	
	list_add_tail(&n->entry, &l4_redirect_list);
	
	if (!l4_redirect_timer.tpd)
		triton_timer_add(&l4_redirect_ctx, &l4_redirect_timer, 0);

	pthread_rwlock_unlock(&l4_list_lock);	
}

static int l4_redirect_list_check(in_addr_t addr)
{
	struct l4_redirect *n;

	pthread_rwlock_rdlock(&l4_list_lock);
	list_for_each_entry(n, &l4_redirect_list, entry) {
		if (n->addr == addr) {
			pthread_rwlock_unlock(&l4_list_lock);
			return 1;
		}
	}
	pthread_rwlock_unlock(&l4_list_lock);
	return 0;
}

static void l4_redirect_list_timer(struct triton_timer_t *t)
{
	struct l4_redirect *n;
	struct timespec ts;
	struct unit_cache *uc;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	pthread_rwlock_wrlock(&l4_list_lock);
	while (!list_empty(&l4_redirect_list)) {
		n = list_entry(l4_redirect_list.next, typeof(*n), entry);
		if (ts.tv_sec > n->timeout) {
			list_del(&n->entry);
			pthread_rwlock_unlock(&l4_list_lock);
			iprule_del(n->addr, conf_l4_redirect_table);

			if (uc_size < conf_unit_cache && ipoe_nl_modify(n->ifindex, 0, 0, "", NULL)) {
				uc = mempool_alloc(uc_pool);
				uc->ifindex = n->ifindex;
				pthread_mutex_lock(&uc_lock);
				list_add_tail(&uc->entry, &uc_list);
				++uc_size;
				pthread_mutex_unlock(&uc_lock);
			} else
				ipoe_nl_delete(n->ifindex);

			_free(n);
			pthread_rwlock_wrlock(&l4_list_lock);
		} else
			break;
	}

	if (list_empty(&l4_redirect_list) && l4_redirect_timer.tpd)
		triton_timer_del(&l4_redirect_timer);

	pthread_rwlock_unlock(&l4_list_lock);
}

static void ipoe_change_l4_redirect(struct ipoe_session *ses, int del)
{
	in_addr_t addr;
	
	if (conf_l4_redirect_table <= 0)
		return;

	if (ses->ses.ipv4)
		addr = ses->ses.ipv4->addr;
	else
		addr = ses->yiaddr;

	if (del) {
		iprule_del(addr, conf_l4_redirect_table);
		ses->l4_redirect_set = 0;
	} else {
		iprule_add(addr, conf_l4_redirect_table);
		ses->l4_redirect_set = 1;
	}
}

static void ipoe_change_addr(struct ipoe_session *ses, in_addr_t newaddr)
{

}

static void __ipoe_session_start(struct ipoe_session *ses);
static void ipoe_session_start(struct ipoe_session *ses)
{
	int r;
	char *passwd;
	struct ifreq ifr;
	struct unit_cache *uc;

	if (!ses->ses.username) {
		strncpy(ses->ses.ifname, ses->serv->ifname, AP_IFNAME_LEN);
		
		ipoe_session_set_username(ses);

		if (!ses->ses.username) {
			ipoe_session_finished(&ses->ses);
			return;
		}
	}

	ses->ses.unit_idx = ses->serv->ifindex;
	
	triton_event_fire(EV_CTRL_STARTING, &ses->ses);
	triton_event_fire(EV_CTRL_STARTED, &ses->ses);

	ap_session_starting(&ses->ses);
	
	if (!conf_noauth) {
		r = pwdb_check(&ses->ses, ses->ses.username, PPP_PAP, ses->ses.username);
		if (r == PWDB_NO_IMPL) {
			passwd = pwdb_get_passwd(&ses->ses, ses->ses.username);
			if (!passwd)
				r = PWDB_DENIED;
			else {
				r = PWDB_SUCCESS;
				_free(passwd);
			}
		}

		if (r == PWDB_DENIED) {
			if (conf_ppp_verbose)
				log_ppp_warn("authentication failed\n");
			if (conf_l4_redirect_on_reject && !ses->dhcpv4_request && ses->ifindex != -1) {
				l4_redirect_list_add(ses->yiaddr, ses->ifindex);
				ses->ifindex = -1;
			}
			ap_session_terminate(&ses->ses, TERM_AUTH_ERROR, 0);
			return;
		}
	}
	
	ses->ses.ipv4 = ipdb_get_ipv4(&ses->ses);
	
	if (ses->serv->opt_shared == 0 && (!ses->ses.ipv4 || ses->ses.ipv4->peer_addr == ses->yiaddr)) {
		strncpy(ses->ses.ifname, ses->serv->ifname, AP_IFNAME_LEN);
		ses->ses.ifindex = ses->serv->ifindex;
	} else if (ses->ifindex == -1) {
		pthread_mutex_lock(&uc_lock);
		if (!list_empty(&uc_list)) {
			uc = list_entry(uc_list.next, typeof(*uc), entry);
			ses->ifindex = uc->ifindex;
			list_del(&uc->entry);
			--uc_size;
			pthread_mutex_unlock(&uc_lock);
			mempool_free(uc);
		} else {
			pthread_mutex_unlock(&uc_lock);
			ses->ifindex = ipoe_nl_create(0, 0, ses->serv->opt_mode == MODE_L2 ? ses->serv->ifname : NULL, ses->hwaddr);
			if (ses->ifindex == -1) {
				log_ppp_error("ipoe: failed to create interface\n");
				ipoe_session_finished(&ses->ses);
				return;
			}
		}

		memset(&ifr, 0, sizeof(ifr));
		ifr.ifr_ifindex = ses->ifindex;
		if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
			log_ppp_error("ipoe: failed to get interface name\n");
			ses->ifindex = -1;
			ipoe_session_finished(&ses->ses);
			return;
		}

		strncpy(ses->ses.ifname, ifr.ifr_name, AP_IFNAME_LEN);
		ses->ses.ifindex = ses->ifindex;
		ses->ses.unit_idx = ses->ifindex;
		ses->ctrl.dont_ifcfg = 0;
	}

	ap_session_set_ifindex(&ses->ses);

	if (ses->dhcpv4_request && ses->serv->dhcpv4_relay) {
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id);

		ses->timer.expire = ipoe_session_timeout;
		ses->timer.expire_tv.tv_sec = conf_offer_timeout;
		triton_timer_add(&ses->ctx, &ses->timer, 0);
	} else
		__ipoe_session_start(ses);
}

static void __ipoe_session_start(struct ipoe_session *ses) 
{
	if (!ses->yiaddr) {
		dhcpv4_get_ip(ses->serv->dhcpv4, &ses->yiaddr, &ses->router, &ses->mask);
		if (ses->yiaddr)
			ses->dhcp_addr = 1;
	}

	if (ses->ses.ipv4) {
		if (conf_gw_address)
			ses->ses.ipv4->addr = conf_gw_address;
		
		if (conf_netmask)
			ses->ses.ipv4->mask = conf_netmask;
		else if (!ses->ses.ipv4->mask)
			ses->ses.ipv4->mask = 24;

		if (!ses->yiaddr)
			ses->yiaddr = ses->ses.ipv4->peer_addr;
	
		if (!ses->router)
			ses->router = ses->ses.ipv4->addr;
	} /*else if (ses->yiaddr) {
		ses->ses.ipv4 = &ses->ipv4;
		ses->ipv4.addr = ses->siaddr;
		ses->ipv4.peer_addr = ses->yiaddr;
		ses->ipv4.mask = ses->mask;
		ses->ipv4.owner = NULL;
	}*/

	if (ses->dhcpv4_request) {
		if (!ses->yiaddr) {
			log_ppp_error("no free IPv4 address\n");
			ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 0);
			return;
		}
			
		if (!ses->siaddr && ses->router != ses->yiaddr)
			ses->siaddr = ses->router;
		
		if (!ses->siaddr && ses->serv->dhcpv4_relay)
			ses->siaddr = ses->serv->dhcpv4_relay->giaddr;

		if (!ses->siaddr) {
			log_ppp_error("can't determine Server-ID\n");
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 0);
			return;
		}
				
		if (!ses->mask)
			ses->mask = 32;
	
		dhcpv4_send_reply(DHCPOFFER, ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->dhcpv4_relay_reply);

		dhcpv4_packet_free(ses->dhcpv4_request);
		ses->dhcpv4_request = NULL;
	
		ses->timer.expire = ipoe_session_timeout;
		ses->timer.expire_tv.tv_sec = conf_offer_timeout;
		triton_timer_add(&ses->ctx, &ses->timer, 0);
	} else
		__ipoe_session_activate(ses);
}

static void ipoe_serv_add_addr(struct ipoe_serv *serv, in_addr_t addr)
{
	struct ifaddr *a;

	pthread_mutex_lock(&serv->lock);
	
	list_for_each_entry(a, &serv->addr_list, entry) {
		if (a->addr == addr) {
			a->refs++;
			pthread_mutex_unlock(&serv->lock);

			return;
		}
	}

	a = _malloc(sizeof(*a));
	a->addr = addr;
	a->refs = 1;
	list_add_tail(&a->entry, &serv->addr_list);

	if (ipaddr_add(serv->ifindex, a->addr, 32))
		log_warn("ipoe: failed to add addess to interface '%s'\n", serv->ifname);

	pthread_mutex_unlock(&serv->lock);
}

static void ipoe_serv_del_addr(struct ipoe_serv *serv, in_addr_t addr)
{
	struct ifaddr *a;

	pthread_mutex_lock(&serv->lock);

	list_for_each_entry(a, &serv->addr_list, entry) {
		if (a->addr == addr) {
			if (--a->refs == 0) {
				if (ipaddr_del(serv->ifindex, a->addr))
					log_warn("ipoe: failed to delete addess from interface '%s'\n", serv->ifname);
				list_del(&a->entry);
				_free(a);
			}
			break;
		}
	}
	
	pthread_mutex_unlock(&serv->lock);
}

static void ipoe_ifcfg_add(struct ipoe_session *ses)
{
	struct ipoe_serv *serv = ses->serv;

	if (ses->serv->opt_ifcfg) {
		if (ses->serv->opt_shared)
			ipoe_serv_add_addr(ses->serv, ses->siaddr);
		else {
			pthread_mutex_lock(&serv->lock);
			if (ipaddr_add(serv->ifindex, ses->siaddr, 32))
				log_ppp_warn("ipoe: failed to add addess to interface '%s'\n", serv->ifname);
			pthread_mutex_unlock(&serv->lock);
		}
		if (iproute_add(serv->ifindex, ses->siaddr, ses->yiaddr))
			log_ppp_warn("ipoe: failed to add route to interface '%s'\n", serv->ifname);
	} else if (iproute_add(serv->ifindex, 0, ses->yiaddr))
		log_ppp_warn("ipoe: failed to add route to interface '%s'\n", serv->ifname);

	ses->ifcfg = 1;
}

static void ipoe_ifcfg_del(struct ipoe_session *ses)
{
	struct ipoe_serv *serv = ses->serv;
	
	if (iproute_del(serv->ifindex, ses->yiaddr))
		log_ppp_warn("ipoe: failed to delete route from interface '%s'\n", serv->ifname);

	if (ses->serv->opt_ifcfg) {
		if (iproute_del(serv->ifindex, ses->yiaddr))
			log_ppp_warn("ipoe: failed to delete route from interface '%s'\n", serv->ifname);
			
		if (ses->serv->opt_shared) {
			ipoe_serv_del_addr(ses->serv, ses->siaddr);
		} else {
			pthread_mutex_lock(&serv->lock);
			if (ipaddr_del(serv->ifindex, ses->siaddr))
				log_ppp_warn("ipoe: failed to remove addess from interface '%s'\n", serv->ifname);
			pthread_mutex_unlock(&serv->lock);
		}
	}
}

static void __ipoe_session_activate(struct ipoe_session *ses)
{
	uint32_t addr;

	if (ses->terminating)
		return;
	
	if (ses->ifindex != -1) {
		addr = 0;
		if (!ses->ses.ipv4) {
			if (ses->serv->opt_mode == MODE_L3) {
				addr = 1;
				ses->ctrl.dont_ifcfg = 1;
			}
		} else if (ses->ses.ipv4->peer_addr != ses->yiaddr)
			addr = ses->ses.ipv4->peer_addr;
		
		if (ipoe_nl_modify(ses->ifindex, ses->yiaddr, addr, NULL, NULL)) {
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 0);
			return;
		}
	}
	
	if (!ses->ses.ipv4) {
		ses->ses.ipv4 = &ses->ipv4;
		ses->ipv4.owner = NULL;
		ses->ipv4.peer_addr = ses->yiaddr;
		ses->ipv4.addr = ses->siaddr;
	}
	
	if (ses->ifindex == -1 && (ses->serv->opt_ifcfg || (ses->serv->opt_mode == MODE_L2)))
		ipoe_ifcfg_add(ses);
	
	if (ses->l4_redirect)
		ipoe_change_l4_redirect(ses, 0);

	ap_session_activate(&ses->ses);

	if (ses->dhcpv4_request) {
		if (ses->ses.state == AP_STATE_ACTIVE)
			dhcpv4_send_reply(DHCPACK, ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->dhcpv4_relay_reply);
		else
			dhcpv4_send_nak(ses->serv->dhcpv4, ses->dhcpv4_request);

		dhcpv4_packet_free(ses->dhcpv4_request);
		ses->dhcpv4_request = NULL;
	}
	
	ses->timer.expire = ipoe_session_timeout;
	ses->timer.expire_tv.tv_sec = conf_lease_timeout ? conf_lease_timeout : ses->lease_time;
	if (ses->timer.tpd)
		triton_timer_mod(&ses->timer, 0);
}

static void ipoe_session_activate(struct ipoe_session *ses)
{
	if (ses->serv->dhcpv4_relay)
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id);
	else
		__ipoe_session_activate(ses);
}

static void ipoe_session_keepalive(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (ses->dhcpv4_request)
		dhcpv4_packet_free(ses->dhcpv4_request);
	
	ses->dhcpv4_request = pack;

	if (ses->timer.tpd)
		triton_timer_mod(&ses->timer, 0);

	ses->xid = ses->dhcpv4_request->hdr->xid;
	
	if (/*ses->ses.state == AP_STATE_ACTIVE &&*/ ses->serv->dhcpv4_relay) {
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id);
		return;
	}

	if (ses->ses.state == AP_STATE_ACTIVE) {
		dhcpv4_send_reply(DHCPACK, ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->dhcpv4_relay_reply);
	} else
		dhcpv4_send_nak(ses->serv->dhcpv4, ses->dhcpv4_request);

	dhcpv4_packet_free(ses->dhcpv4_request);
	ses->dhcpv4_request = NULL;
}
			
static void ipoe_session_decline(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}
	
	if (pack->msg_type == DHCPDECLINE && ses->serv->dhcpv4_relay)
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, pack, 0, ses->serv->ifname, conf_agent_remote_id);

	dhcpv4_packet_free(pack);

	ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 0);
}

static void ipoe_session_started(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);
	
	log_ppp_debug("ipoe: session started\n");

	if (ses->timer.tpd)
		triton_timer_mod(&ses->timer, 0);
	
	if (ses->ifindex != -1 && ses->xid) {
		ses->dhcpv4 = dhcpv4_create(ses->ctrl.ctx, ses->ses.ifname, "");
		if (!ses->dhcpv4) {
			//terminate
			return;
		}
		ses->dhcpv4->recv = ipoe_ses_recv_dhcpv4;
	}
}

static void ipoe_session_free(struct ipoe_session *ses)
{
	struct unit_cache *uc;

	if (ses->timer.tpd)
		triton_timer_del(&ses->timer);

	if (ses->dhcpv4_request)
		dhcpv4_packet_free(ses->dhcpv4_request);
	
	if (ses->ctrl.called_station_id)
		_free(ses->ctrl.called_station_id);
	
	if (ses->ctrl.calling_station_id)
		_free(ses->ctrl.calling_station_id);

	triton_context_unregister(&ses->ctx);
	
	if (ses->data)
		_free(ses->data);
	
	if (ses->ifindex != -1) {
		if (uc_size < conf_unit_cache && ipoe_nl_modify(ses->ifindex, 0, 0, "", NULL)) {
			uc = mempool_alloc(uc_pool);
			uc->ifindex = ses->ifindex;
			pthread_mutex_lock(&uc_lock);
			list_add_tail(&uc->entry, &uc_list);
			++uc_size;
			pthread_mutex_unlock(&uc_lock);
		} else
			ipoe_nl_delete(ses->ifindex);
	}

	mempool_free(ses);
}

static void ipoe_session_finished(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);
	int serv_close;

	log_ppp_debug("ipoe: session finished\n");

	pthread_mutex_lock(&ses->serv->lock);
	list_del(&ses->entry);
	serv_close = ses->serv->need_close && list_empty(&ses->serv->sessions);
	pthread_mutex_unlock(&ses->serv->lock);

	if (ses->dhcp_addr)
		dhcpv4_put_ip(ses->serv->dhcpv4, ses->yiaddr);
	
	if (ses->relay_addr && ses->serv->dhcpv4_relay)
		dhcpv4_relay_send_release(ses->serv->dhcpv4_relay, ses->hwaddr, ses->xid, ses->yiaddr, ses->client_id, ses->relay_agent, ses->serv->ifname, conf_agent_remote_id);

	if (ses->ifcfg)
		ipoe_ifcfg_del(ses);

	if (serv_close)
		ipoe_serv_close(&ses->serv->ctx);
	
	if (ses->dhcpv4)
		dhcpv4_free(ses->dhcpv4);

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_free, ses);
}

static void ipoe_session_terminate(struct ap_session *s, int hard)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

	if (ses->l4_redirect_set)
		ipoe_change_l4_redirect(ses, 1);

	ap_session_finished(s);
}


static void ipoe_session_close(struct triton_context_t *ctx)
{
	struct ipoe_session *ses = container_of(ctx, typeof(*ses), ctx);
	
	if (ses->ses.state)
		ap_session_terminate(&ses->ses, TERM_ADMIN_RESET, 1);
	else
		ipoe_session_finished(&ses->ses);
}

static struct ipoe_session *ipoe_session_create_dhcpv4(struct ipoe_serv *serv, struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses;
	int dlen = 0;
	uint8_t *ptr;
	
	ses = mempool_alloc(ses_pool);
	if (!ses) {
		log_emerg("out of memery\n");
		return NULL;
	}

	memset(ses, 0, sizeof(*ses));

	ap_session_init(&ses->ses);

	ses->serv = serv;
	ses->ifindex = -1;
	ses->dhcpv4_request = pack;
	
	ses->xid = pack->hdr->xid;
	memcpy(ses->hwaddr, pack->hdr->chaddr, 6);
	ses->giaddr = pack->hdr->giaddr;
	ses->lease_time = conf_lease_time;

	if (pack->client_id)
		dlen += sizeof(struct dhcpv4_option) + pack->client_id->len;
	
	if (pack->relay_agent)
		dlen += sizeof(struct dhcpv4_option) + pack->relay_agent->len;
	
	if (dlen) {
		ses->data = _malloc(dlen);
		if (!ses->data) {
			log_emerg("out of memery\n");
			mempool_free(ses);
			return NULL;
		}
		ptr = ses->data;
	}

	if (pack->client_id) {
		ses->client_id = (struct dhcpv4_option *)ptr;
		ses->client_id->len = pack->client_id->len;
		ses->client_id->data = (uint8_t *)(ses->client_id + 1);
		memcpy(ses->client_id->data, pack->client_id->data, pack->client_id->len);
		ptr += sizeof(struct dhcpv4_option) + pack->client_id->len;
	}
	
	if (pack->relay_agent) {
		ses->relay_agent = (struct dhcpv4_option *)ptr;
		ses->relay_agent->len = pack->relay_agent->len;
		ses->relay_agent->data = (uint8_t *)(ses->relay_agent + 1);
		memcpy(ses->relay_agent->data, pack->relay_agent->data, pack->relay_agent->len);
		ptr += sizeof(struct dhcpv4_option) + pack->relay_agent->len;
		if (dhcpv4_parse_opt82(ses->relay_agent, &ses->agent_circuit_id, &ses->agent_remote_id))
			ses->relay_agent = NULL;
	}

	ses->ctx.before_switch = log_switch;
	ses->ctx.close = ipoe_session_close;
	ses->ctrl.ctx = &ses->ctx;
	ses->ctrl.started = ipoe_session_started;
	ses->ctrl.finished = ipoe_session_finished;
	ses->ctrl.terminate = ipoe_session_terminate;
	ses->ctrl.type = CTRL_TYPE_IPOE;
	ses->ctrl.name = "ipoe";
	
	ses->ctrl.calling_station_id = _malloc(19);
	ses->ctrl.called_station_id = _strdup(serv->ifname);
	
	ptr = ses->hwaddr;
	sprintf(ses->ctrl.calling_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
		ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
	
	ses->ses.ctrl = &ses->ctrl;
	ses->ses.chan_name = ses->ctrl.calling_station_id;

	triton_context_register(&ses->ctx, &ses->ses);

	triton_context_wakeup(&ses->ctx);

	//pthread_mutex_lock(&serv->lock);
	list_add_tail(&ses->entry, &serv->sessions);
	//pthread_mutex_unlock(&serv->lock);

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_start, ses);

	return ses;
}

static void __ipoe_session_terminate(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_USER_REQUEST, 0);
}

static void ipoe_ses_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(dhcpv4->ctx, typeof(*ses), ctx);

	if (ap_shutdown)
		return;
			
	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_info2);
	}
			
	if (pack->msg_type == DHCPDISCOVER) {
		if (ses->yiaddr) {
			if (ses->serv->dhcpv4_relay) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_keepalive, pack);
			} else
				dhcpv4_send_reply(DHCPOFFER, dhcpv4, pack, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->dhcpv4_relay_reply);
		}
	} else if (pack->msg_type == DHCPREQUEST) {
		if (pack->hdr->ciaddr == ses->yiaddr && pack->hdr->xid != ses->xid)
			ses->xid = pack->hdr->xid;
		if ((pack->server_id && (pack->server_id != ses->siaddr || pack->request_ip != ses->yiaddr)) ||
			(pack->hdr->ciaddr && (pack->hdr->xid != ses->xid || pack->hdr->ciaddr != ses->yiaddr))) {

			if (pack->server_id == ses->siaddr)
				dhcpv4_send_nak(dhcpv4, pack);
			else if (ses->serv->dhcpv4_relay)
				dhcpv4_relay_send(ses->serv->dhcpv4_relay, pack, 0, ses->serv->ifname, conf_agent_remote_id);
			
			ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 0);
		} else {
			dhcpv4_packet_ref(pack);
			ipoe_session_keepalive(pack);
		}
	} else if (pack->msg_type == DHCPDECLINE || pack->msg_type == DHCPRELEASE) {
		dhcpv4_packet_ref(pack);
		ipoe_session_decline(pack);
	}
}

static void ipoe_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack)
{
	struct ipoe_serv *serv = container_of(dhcpv4->ctx, typeof(*serv), ctx);
	struct ipoe_session *ses;
	//struct dhcpv4_packet *reply;

	if (ap_shutdown)
		return;

	pthread_mutex_lock(&serv->lock);
	if (pack->msg_type == DHCPDISCOVER) {
		ses = ipoe_session_lookup(serv, pack);
		if (!ses) {
			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, NULL);

			ses = ipoe_session_create_dhcpv4(serv, pack);
			if (ses) {
				dhcpv4_packet_ref(pack);

				if (conf_verbose) {
					log_switch(dhcpv4->ctx, &ses->ses);
					log_ppp_info2("recv ");
					dhcpv4_print_packet(pack, 0, log_ppp_info2);
				}
			}
		}	else {
			log_switch(dhcpv4->ctx, &ses->ses);

			if (conf_verbose) {
				log_ppp_info2("recv ");
				dhcpv4_print_packet(pack, 0, log_ppp_info2);
			}

			if (ses->yiaddr) {
				if (ses->serv->dhcpv4_relay) {
					dhcpv4_packet_ref(pack);
					triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_keepalive, pack);
				} else
					dhcpv4_send_reply(DHCPOFFER, dhcpv4, pack, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->dhcpv4_relay_reply);
			}
		}
	} else if (pack->msg_type == DHCPREQUEST) {
		ses = ipoe_session_lookup(serv, pack);

		if (!ses) {
			if (conf_verbose) {
				log_info2("recv ");
				dhcpv4_print_packet(pack, 0, log_info2);
			}
				
			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, NULL);

			dhcpv4_send_nak(dhcpv4, pack);
		} else {
			if (pack->hdr->ciaddr == ses->yiaddr && pack->hdr->xid != ses->xid)
				ses->xid = pack->hdr->xid;
			if ((pack->server_id && (pack->server_id != ses->siaddr || pack->request_ip != ses->yiaddr)) ||
				(pack->hdr->ciaddr && (pack->hdr->xid != ses->xid || pack->hdr->ciaddr != ses->yiaddr))) {

				if (conf_verbose) {
					log_switch(dhcpv4->ctx, &ses->ses);
					log_ppp_info2("recv ");
					dhcpv4_print_packet(pack, 0, log_info2);
				}

				if (pack->server_id == ses->siaddr)
					dhcpv4_send_nak(dhcpv4, pack);
				else if (ses->serv->dhcpv4_relay)
					dhcpv4_relay_send(ses->serv->dhcpv4_relay, pack, 0, ses->serv->ifname, conf_agent_remote_id);
				
				triton_context_call(&ses->ctx, (triton_event_func)__ipoe_session_terminate, &ses->ses);
			} else {
				if (conf_verbose) {
					log_switch(dhcpv4->ctx, &ses->ses);
					log_ppp_info2("recv ");
					dhcpv4_print_packet(pack, 0, log_ppp_info2);
				}

				if (serv->opt_shared == 0)
					ipoe_drop_sessions(serv, ses);

				if (ses->ses.state == AP_STATE_STARTING && ses->yiaddr && !ses->dhcpv4_request) {
					ses->dhcpv4_request = pack;
					dhcpv4_packet_ref(pack);
					triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_activate, ses);
				} else if (ses->ses.state == AP_STATE_ACTIVE) {
					dhcpv4_packet_ref(pack);
					triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_keepalive, pack);
				}
			}
		}
	} else if (pack->msg_type == DHCPDECLINE || pack->msg_type == DHCPRELEASE) {
		ses = ipoe_session_lookup(serv, pack);
		if (ses) {
			dhcpv4_packet_ref(pack);
			triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_decline, pack);
		}
	}
	pthread_mutex_unlock(&serv->lock);
}

static int parse_dhcpv4_mask(uint32_t mask)
{
	int i;

	for (i = 31; i >= 0 && (mask & (1 << i)); i--);

	return 32 - (i + 1);
}

static void ipoe_ses_recv_dhcpv4_relay(struct ipoe_session *ses)
{
	struct dhcpv4_packet *pack = ses->dhcpv4_relay_reply;
	struct dhcpv4_option *opt;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 1, log_ppp_info2);
	}

	opt = dhcpv4_packet_find_opt(pack, 51);
	if (opt)
		ses->lease_time = ntohl(*(uint32_t *)opt->data);

	opt = dhcpv4_packet_find_opt(pack, 1);
	if (opt)
		ses->mask = parse_dhcpv4_mask(ntohl(*(uint32_t *)opt->data));

	if (pack->msg_type == DHCPOFFER) {
		if (ses->ses.state == AP_STATE_STARTING) {
			triton_timer_del(&ses->timer);

			ses->relay_server_id = pack->server_id;

			if (!ses->yiaddr) {
				ses->yiaddr = pack->hdr->yiaddr;
				ses->relay_addr = 1;
			}

			__ipoe_session_start(ses);
		} else
			dhcpv4_send_reply(DHCPOFFER, ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->dhcpv4_relay_reply);
	} else if (pack->msg_type == DHCPACK) {
		if (ses->ses.state == AP_STATE_STARTING)
			__ipoe_session_activate(ses);
		else
			dhcpv4_send_reply(DHCPACK, ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->dhcpv4_relay_reply);

	} else if (pack->msg_type == DHCPNAK) {
		dhcpv4_send_nak(ses->serv->dhcpv4, ses->dhcpv4_request);
		ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 0);
		return;
	}
		
	dhcpv4_packet_free(ses->dhcpv4_relay_reply);
	ses->dhcpv4_relay_reply = NULL;
}

static void ipoe_recv_dhcpv4_relay(struct dhcpv4_packet *pack)
{
	struct ipoe_serv *serv = container_of(triton_context_self(), typeof(*serv), ctx);
	struct ipoe_session *ses;
	int found = 0;
	//struct dhcpv4_packet *reply;

	if (ap_shutdown) {
		dhcpv4_packet_free(pack);
		return;
	}

	pthread_mutex_lock(&serv->lock);
	list_for_each_entry(ses, &serv->sessions, entry) {
		if (ses->xid != pack->hdr->xid)
			continue;
		if (memcmp(ses->hwaddr, pack->hdr->chaddr, 6))
			continue;

		found = 1;
		break;
	}
	
	if (found && !ses->dhcpv4_relay_reply) {
		ses->dhcpv4_relay_reply = pack;
		triton_context_call(&ses->ctx, (triton_event_func)ipoe_ses_recv_dhcpv4_relay, ses);
	} else
		dhcpv4_packet_free(pack);

	pthread_mutex_unlock(&serv->lock);
}


static struct ipoe_session *ipoe_session_create_up(struct ipoe_serv *serv, struct ethhdr *eth, struct iphdr *iph)
{
	struct ipoe_session *ses;

	if (ap_shutdown)
		return NULL;
	
	if (l4_redirect_list_check(iph->saddr))
		return NULL;
	
	ses = mempool_alloc(ses_pool);
	if (!ses) {
		log_emerg("out of memery\n");
		return NULL;
	}

	memset(ses, 0, sizeof(*ses));

	ap_session_init(&ses->ses);

	ses->serv = serv;
	ses->ifindex = -1;
	
	memcpy(ses->hwaddr, eth->h_source, 6);

	ses->ctx.before_switch = log_switch;
	ses->ctx.close = ipoe_session_close;
	ses->ctrl.ctx = &ses->ctx;
	ses->ctrl.started = ipoe_session_started;
	ses->ctrl.finished = ipoe_session_finished;
	ses->ctrl.terminate = ipoe_session_terminate;
	ses->ctrl.type = CTRL_TYPE_IPOE;
	ses->ctrl.name = "ipoe";

	ses->yiaddr = iph->saddr;

	ses->ctrl.calling_station_id = _malloc(17);
	ses->ctrl.called_station_id = _malloc(17);

	u_inet_ntoa(iph->saddr, ses->ctrl.calling_station_id);
	u_inet_ntoa(iph->daddr, ses->ctrl.called_station_id);
	
	ses->ses.username = _strdup(ses->ctrl.calling_station_id);
	
	ses->ses.ctrl = &ses->ctrl;
	ses->ses.chan_name = ses->ctrl.calling_station_id;

	triton_context_register(&ses->ctx, &ses->ses);

	triton_context_wakeup(&ses->ctx);

	//pthread_mutex_lock(&serv->lock);
	list_add_tail(&ses->entry, &serv->sessions);
	//pthread_mutex_unlock(&serv->lock);

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_start, ses);

	return ses;
}

struct ipoe_session *ipoe_session_alloc(void)
{
	struct ipoe_session *ses;

	ses = mempool_alloc(ses_pool);
	if (!ses) {
		log_emerg("out of memery\n");
		return NULL;
	}

	memset(ses, 0, sizeof(*ses));

	ap_session_init(&ses->ses);

	ses->ifindex = -1;
	
	ses->ctx.before_switch = log_switch;
	ses->ctx.close = ipoe_session_close;
	ses->ctrl.ctx = &ses->ctx;
	ses->ctrl.started = ipoe_session_started;
	ses->ctrl.finished = ipoe_session_finished;
	ses->ctrl.terminate = ipoe_session_terminate;
	ses->ctrl.type = CTRL_TYPE_IPOE;
	ses->ctrl.name = "ipoe";

	ses->ses.ctrl = &ses->ctrl;
	ses->ses.chan_name = ses->ctrl.calling_station_id;

	return ses;
}

void ipoe_recv_up(int ifindex, struct ethhdr *eth, struct iphdr *iph)
{
	struct ipoe_serv *serv;
	struct ipoe_session *ses;

	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->ifindex != ifindex)
			continue;

		if (!serv->opt_up)
			return;
		
		pthread_mutex_lock(&serv->lock);
		list_for_each_entry(ses, &serv->sessions, entry) {
			if (ses->yiaddr == iph->saddr) {
				pthread_mutex_unlock(&serv->lock);
				return;
			}
		}
		pthread_mutex_unlock(&serv->lock);
		
		ipoe_session_create_up(serv, eth, iph);

		break;
	}
}

#ifdef RADIUS
static void ev_radius_access_accept(struct ev_radius_t *ev)
{
	struct ipoe_session *ses = container_of(ev->ses, typeof(*ses), ses);
	struct rad_attr_t *attr;

	if (ev->ses->ctrl->type != CTRL_TYPE_IPOE)
		return;

	list_for_each_entry(attr, &ev->reply->attrs, entry) {
		if (attr->attr->id == conf_attr_dhcp_client_ip)
			ses->yiaddr = attr->val.ipaddr;
		else if (attr->attr->id == conf_attr_dhcp_router_ip)
			ses->router = attr->val.ipaddr;
		else if (attr->attr->id == conf_attr_dhcp_mask) {
			if (attr->attr->type == ATTR_TYPE_INTEGER) {
				if (attr->val.integer > 0 && attr->val.integer < 31)
					ses->mask = attr->val.integer;
			} else if (attr->attr->type == ATTR_TYPE_IPADDR) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
				ses->mask = ffs(~attr->val.ipaddr) - 1;
#else
				ses->mask = ffs(~htole32(attr->val.ipaddr)) - 1;
#endif
			}
		} else if (attr->attr->id == conf_attr_l4_redirect) {
			if (attr->attr->type == ATTR_TYPE_STRING) {
				if (attr->len && attr->val.string[0] != '0')
					ses->l4_redirect = 1;
			} else if (attr->val.integer != 0)
				ses->l4_redirect = 1;
		}
	}
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	struct ipoe_session *ses = container_of(ev->ses, typeof(*ses), ses);
	struct rad_attr_t *attr;
	int l4_redirect;
	
	if (ev->ses->ctrl->type != CTRL_TYPE_IPOE)
		return;
	
	l4_redirect = ses->l4_redirect;

	list_for_each_entry(attr, &ev->request->attrs, entry) {
		if (attr->attr->id == conf_attr_l4_redirect) {
			if (attr->attr->type == ATTR_TYPE_STRING)
				ses->l4_redirect = attr->len && attr->val.string[0] != '0';
			else
				ses->l4_redirect = ((unsigned int)attr->val.integer) > 0;
		} else if (strcmp(attr->attr->name, "Framed-IP-Address") == 0) {
			if (ses->ses.ipv4 && ses->ses.ipv4->peer_addr != attr->val.ipaddr)
				ipoe_change_addr(ses, attr->val.ipaddr);
		}
	}

	//if (l4_redirect && !ses->l4_redirect) || (!l4_redirect && ses->l4_redirect))
	if (l4_redirect != ses->l4_redirect && ev->ses->state == AP_STATE_ACTIVE)
		ipoe_change_l4_redirect(ses, l4_redirect);
}
#endif

static void ipoe_serv_close(struct triton_context_t *ctx)
{
	struct ipoe_serv *serv = container_of(ctx, typeof(*serv), ctx);

	pthread_mutex_lock(&serv->lock);
	if (!list_empty(&serv->sessions)) {
		serv->need_close = 1;
		pthread_mutex_unlock(&serv->lock);
		return;
	}
	pthread_mutex_unlock(&serv->lock);

	if (serv->dhcpv4)
		dhcpv4_free(serv->dhcpv4);
	
	if (serv->dhcpv4_relay) {
		ipoe_serv_del_addr(serv, serv->dhcpv4_relay->giaddr);
		dhcpv4_relay_free(serv->dhcpv4_relay, &serv->ctx);
	}

	triton_context_unregister(ctx);

	_free(serv->ifname);
	_free(serv);
}

static void l4_redirect_ctx_close(struct triton_context_t *ctx)
{
	struct l4_redirect *n;

	pthread_rwlock_wrlock(&l4_list_lock);
	while (!list_empty(&l4_redirect_list)) {
		n = list_entry(l4_redirect_list.next, typeof(*n), entry);
		list_del(&n->entry);
		iprule_del(n->addr, conf_l4_redirect_table);
		ipoe_nl_delete(n->ifindex);
		_free(n);
	}
	pthread_rwlock_unlock(&l4_list_lock);

	if (l4_redirect_timer.tpd)
		triton_timer_del(&l4_redirect_timer);
	
	triton_context_unregister(&l4_redirect_ctx);
}

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "ipoe:\r\n");
	cli_sendv(client,"  starting: %u\r\n", stat_starting);
	cli_sendv(client,"  active: %u\r\n", stat_active);

	return CLI_CMD_OK;
}

void __export ipoe_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void __terminate(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REQUEST, 0);
}

static void ipoe_drop_sessions(struct ipoe_serv *serv, struct ipoe_session *skip)
{
	struct ipoe_session *ses;

	list_for_each_entry(ses, &serv->sessions, entry) {
		if (ses == skip)
			continue;

		ses->terminating = 1;
		if (ses->ifcfg) {
			ipoe_ifcfg_del(ses);
			ses->ifcfg = 0;
		}

		if (ses->ses.state == AP_STATE_ACTIVE)
			ap_session_ifdown(&ses->ses);

		triton_context_call(&ses->ctx, (triton_event_func)__terminate, &ses->ses);
	}
}

struct ipoe_serv *ipoe_find_serv(const char *ifname)
{
	struct ipoe_serv *serv;

	list_for_each_entry(serv, &serv_list, entry) {
		if (strcmp(serv->ifname, ifname) == 0)
			return serv;
	}

	return NULL;
}

static void add_interface(const char *ifname, int ifindex, const char *opt)
{
	char *str0 = NULL, *str, *ptr1, *ptr2;
	int end;
	struct ipoe_serv *serv;
	int opt_shared = conf_shared;
	int opt_dhcpv4 = 0;
	int opt_up = 0;
	int opt_mode = conf_mode;
	int opt_ifcfg = conf_ifcfg;
	const char *opt_relay = conf_relay;
	const char *opt_giaddr = NULL;
	in_addr_t relay_addr = 0;
	in_addr_t giaddr = 0;

	str0 = strchr(opt, ',');
	if (str0) {
		str0 = _strdup(str0 + 1);
		str = str0;
	
		while (1) {
			for (ptr1 = str + 1; *ptr1 && *ptr1 != '='; ptr1++);

			if (!*ptr1)
				goto parse_err;
		
			*ptr1 = 0;

			for (ptr2 = ++ptr1; *ptr2 && *ptr2 != ','; ptr2++);

			end = *ptr2 == 0;

			if (!end)
				*ptr2 = 0;

			if (ptr2 == ptr1)
				goto parse_err;

			if (strcmp(str, "start") == 0) {
				if (!strcmp(ptr1, "up"))
					opt_up = 1;
				else if (!strcmp(ptr1, "dhcpv4"))
					opt_dhcpv4 = 1;
				else
					goto parse_err;
			} else if (strcmp(str, "shared") == 0) {
				opt_shared = atoi(ptr1);
			} else if (strcmp(str, "mode") == 0) {
				if (!strcmp(ptr1, "L2"))
					opt_mode = MODE_L2;
				else if (!strcmp(ptr1, "L3"))
					opt_mode = MODE_L3;
				else
					goto parse_err;
			} else if (strcmp(str, "ifcfg") == 0) {
				opt_ifcfg = atoi(ptr1);
			} else if (strcmp(str, "relay") == 0) {
				opt_relay = ptr1;
				relay_addr = inet_addr(ptr1);
			} else if (strcmp(str, "giaddr") == 0) {
				opt_giaddr = ptr1;
				giaddr = inet_addr(ptr1);
			}

			if (end)
				break;

			str = ptr2 + 1;
		}
	}		

	if (!opt_up && !opt_dhcpv4) {
		opt_up = conf_up;
		opt_dhcpv4 = conf_dhcpv4;
	}

	if (opt_up)
		ipoe_nl_add_interface(ifindex);

	list_for_each_entry(serv, &serv_list, entry) {
		if (strcmp(ifname, serv->ifname))
			continue;

		serv->active = 1;
		serv->ifindex = ifindex;
		
		if ((opt_shared && !serv->opt_shared) || (!opt_shared && serv->opt_shared)) {
			ipoe_drop_sessions(serv, NULL);
			serv->opt_shared = opt_shared;
		}

		if (opt_dhcpv4 && !serv->dhcpv4) {
			serv->dhcpv4 = dhcpv4_create(&serv->ctx, serv->ifname, opt);
			if (serv->dhcpv4)
				serv->dhcpv4->recv = ipoe_recv_dhcpv4;
		} else if (!opt_dhcpv4 && serv->dhcpv4) {
			dhcpv4_free(serv->dhcpv4);
			serv->dhcpv4 = NULL;
		}

		if (serv->dhcpv4_relay && 
				(serv->dhcpv4_relay->addr != relay_addr || serv->dhcpv4_relay->giaddr != giaddr)) {
			if (serv->opt_ifcfg)
				ipoe_serv_del_addr(serv, serv->dhcpv4_relay->giaddr);
			dhcpv4_relay_free(serv->dhcpv4_relay, &serv->ctx);
			serv->dhcpv4_relay = NULL;
		}

		if (serv->opt_dhcpv4 && opt_relay) {
			if (opt_ifcfg)
				ipoe_serv_add_addr(serv, giaddr);
			serv->dhcpv4_relay = dhcpv4_relay_create(opt_relay, opt_giaddr, &serv->ctx, (triton_event_func)ipoe_recv_dhcpv4_relay);
		}
		
		serv->opt_up = opt_up;
		serv->opt_mode = opt_mode;
		serv->opt_ifcfg = opt_ifcfg;


		if (str0)
			_free(str0);

		return;
	}

	serv = _malloc(sizeof(*serv));
	memset(serv, 0, sizeof(*serv));
	serv->ctx.close = ipoe_serv_close;
	serv->ifname = _strdup(ifname);
	serv->ifindex = ifindex;
	serv->opt_shared = opt_shared;
	serv->opt_dhcpv4 = opt_dhcpv4;
	serv->opt_up = opt_up;
	serv->opt_mode = opt_mode;
	serv->opt_ifcfg = opt_ifcfg;
	serv->active = 1;
	INIT_LIST_HEAD(&serv->sessions);
	INIT_LIST_HEAD(&serv->addr_list);
	pthread_mutex_init(&serv->lock, NULL);

	triton_context_register(&serv->ctx, NULL);

	if (serv->opt_dhcpv4) {
		serv->dhcpv4 = dhcpv4_create(&serv->ctx, serv->ifname, opt);
		if (serv->dhcpv4)
			serv->dhcpv4->recv = ipoe_recv_dhcpv4;
	
		if (opt_relay) {
			if (opt_ifcfg)
				ipoe_serv_add_addr(serv, giaddr);
			serv->dhcpv4_relay = dhcpv4_relay_create(opt_relay, opt_giaddr, &serv->ctx, (triton_event_func)ipoe_recv_dhcpv4_relay);
		}
	}

	triton_context_wakeup(&serv->ctx);

	list_add_tail(&serv->entry, &serv_list);

	if (str0)
		_free(str0);

	return;

parse_err:
	log_error("ipoe: failed to parse '%s'\n", opt);
	_free(str0);
}

static void load_interface(const char *opt)
{
	const char *ptr;
	struct ifreq ifr;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	if (ptr - opt >= sizeof(ifr.ifr_name))
		return;

	memcpy(ifr.ifr_name, opt, ptr - opt);
	ifr.ifr_name[ptr - opt] = 0;
	
	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("ipoe: '%s': ioctl(SIOCGIFINDEX): %s\n", ifr.ifr_name, strerror(errno));
		return;
	}

	add_interface(ifr.ifr_name, ifr.ifr_ifindex, opt);
}

static int __load_interface_re(int index, int flags, const char *name, struct iplink_arg *arg)
{
	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	add_interface(name, index, arg->opt);

	return 0;
}

static void load_interface_re(const char *opt)
{
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	const char *ptr;
	int pcre_offset;
	struct iplink_arg arg;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);
	
	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;
	
	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);
		
	if (!re) {
		log_error("ipoe: %s at %i\r\n", pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = opt;

	iplink_list((iplink_list_func)__load_interface_re, &arg);

	pcre_free(re);
	_free(pattern);
}

static void load_interfaces(struct conf_sect_t *sect)
{
	struct ipoe_serv *serv;
	struct conf_option_t *opt;
	struct list_head *pos, *n;

	ipoe_nl_delete_interfaces();

	list_for_each_entry(serv, &serv_list, entry)
		serv->active = 0;

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "interface"))
			continue;
		if (!opt->val)
			continue;

		if (strlen(opt->val) > 3 && memcmp(opt->val, "re:", 3) == 0)
			load_interface_re(opt->val);
		else
			load_interface(opt->val);
	}
	
	list_for_each_safe(pos, n, &serv_list) {
		serv = list_entry(pos, typeof(*serv), entry);
		if (!serv->active) {
			ipoe_drop_sessions(serv, NULL);
			list_del(&serv->entry);
			triton_context_call(&serv->ctx, (triton_event_func)ipoe_serv_close, &serv->ctx);
		}
	}
}

static void parse_local_net(const char *opt)
{
	const char *ptr;
	char str[17];
	in_addr_t addr;
	int mask;
	char *endptr;

	ptr = strchr(opt, '/');
	if (ptr) {
		memcpy(str, opt, ptr - opt);
		str[ptr - opt] = 0;
		addr = inet_addr(str);
		if (addr == INADDR_NONE)
			goto out_err;
		mask = strtoul(ptr + 1, &endptr, 10);
		if (mask > 32)
			goto out_err;
	} else {
		addr = inet_addr(opt);
		if (addr == INADDR_NONE)
			goto out_err;
		mask = 24;
	}

	if (mask == 32)
		mask = 0xffffffff;
	else
		mask = (1 << (32-mask)) - 1;

	addr = ntohl(addr);
	mask = ~mask;

	//printf("%x/%x %x\n", htonl(addr), ~mask, htonl(addr)&(~mask));

	ipoe_nl_add_net(addr & mask, mask);

	return;

out_err:
	log_error("ipoe: failed to parse 'local-net=%s'\n", opt);
}

static void load_local_nets(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;

	ipoe_nl_delete_nets();

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "local-net"))
			continue;
		if (!opt->val)
			continue;
		parse_local_net(opt->val);
	}
}

#ifdef RADIUS
static void parse_conf_rad_attr(const char *opt, int *val)
{
	struct rad_dict_attr_t *attr;

	opt = conf_get_opt("ipoe", opt);

	if (opt) {
		if (atoi(opt) > 0)
			*val = atoi(opt);
		else {
			attr = rad_dict_find_attr(opt);
			if (attr)
				*val = attr->id;
			else
				log_emerg("ipoe: couldn't find '%s' in dictionary\n", opt);
		}
	} else
		*val = -1;
}

static void load_radius_attrs(void)
{
	parse_conf_rad_attr("attr-dhcp-client-ip", &conf_attr_dhcp_client_ip);
	parse_conf_rad_attr("attr-dhcp-router-ip", &conf_attr_dhcp_router_ip);
	parse_conf_rad_attr("attr-dhcp-mask", &conf_attr_dhcp_mask);
	parse_conf_rad_attr("attr-l4-redirect", &conf_attr_l4_redirect);
}
#endif

static void load_config(void)
{
	const char *opt;
	struct conf_sect_t *s = conf_get_section("ipoe");
	struct conf_option_t *opt1;

	if (!s)
		return;

	opt = conf_get_opt("ipoe", "username");
	if (opt) {
		if (strcmp(opt, "ifname") == 0)
			conf_username = USERNAME_IFNAME;
#ifdef USE_LUA
		else if (strlen(opt) > 4 && memcmp(opt, "lua:", 4) == 0) {
			conf_username = USERNAME_LUA;
			conf_lua_username_func = opt + 4;
		}
#endif
		else
			log_emerg("ipoe: unknown username value '%s'\n", opt);
	}

	opt = conf_get_opt("ipoe", "gw-ip-address");
	if (opt)
		conf_gw_address = inet_addr(opt);
	else
		conf_gw_address = 0;

	opt = conf_get_opt("ipoe", "netmask");
	if (opt) {
		conf_netmask = atoi(opt);
		if (conf_netmask <= 0 || conf_netmask > 32) {
			log_error("ipoe: invalid netmask %s\n", opt);
			conf_netmask = 0;
		}
	} else
		conf_netmask = 0;
	
	opt = conf_get_opt("ipoe", "verbose");
	if (opt)
		conf_verbose = atoi(opt);

	opt = conf_get_opt("ipoe", "lease-time");
	if (opt)
		conf_lease_time = atoi(opt);
	else
		conf_lease_time = 600;
	
	opt = conf_get_opt("ipoe", "max-lease-time");
	if (opt)
		conf_lease_timeout = atoi(opt);
	else
		conf_lease_timeout = 660;
	
	opt = conf_get_opt("ipoe", "unit-cache");
	if (opt)
		conf_unit_cache = atoi(opt);
	
	opt = conf_get_opt("ipoe", "l4-redirect-table");
	if (opt)
		conf_l4_redirect_table = atoi(opt);
	else
		conf_l4_redirect_table = 1;
	
	opt = conf_get_opt("ipoe", "l4-redirect-on-reject");
	if (opt) {
		conf_l4_redirect_on_reject = atoi(opt);
	} else
		conf_l4_redirect_on_reject = 0;
		
	if (conf_l4_redirect_on_reject) {
		l4_redirect_timer.period = conf_l4_redirect_on_reject / 10 * 1000;
		if (l4_redirect_timer.tpd)
			triton_timer_mod(&l4_redirect_timer, 0);
	}
	
	opt = conf_get_opt("ipoe", "shared");
	if (opt)
		conf_shared = atoi(opt);
	else
		conf_shared = 1;
	
	opt = conf_get_opt("ipoe", "ifcfg");
	if (opt)
		conf_ifcfg = atoi(opt);
	else
		conf_ifcfg = 1;
	
	opt = conf_get_opt("ipoe", "mode");
	if (opt) {
		if (!strcmp(opt, "L2"))
			conf_mode = MODE_L2;
		else if (!strcmp(opt, "L3"))
			conf_mode = MODE_L3;
		else
			log_emerg("ipoe: failed to parse 'mode=%s'\n", opt);
	} else
		conf_mode = MODE_L2;
	
	conf_relay = conf_get_opt("ipoe", "relay");
	
	opt = conf_get_opt("ipoe", "agent-remote-id");
	if (opt)
		conf_agent_remote_id = opt;
	else
		conf_agent_remote_id = "accel-pppd";
	
	opt = conf_get_opt("ipoe", "noauth");
	if (opt)
		conf_noauth = atoi(opt);
	else
		conf_noauth = 0;

	conf_dhcpv4 = 0;
	conf_up = 0;

	list_for_each_entry(opt1, &s->items, entry) {
		if (strcmp(opt1->name, "start"))
			continue;
		if (!strcmp(opt1->val, "dhcpv4"))
			conf_dhcpv4 = 1;
		else if (!strcmp(opt1->val, "up"))
			conf_up = 1;
	}

	if (!conf_dhcpv4 && !conf_up)
		conf_dhcpv4 = 1;
	
#ifdef RADIUS
	if (triton_module_loaded("radius"))
		load_radius_attrs();
#endif
	
	load_interfaces(s);
	load_local_nets(s);
}

static struct triton_context_t l4_redirect_ctx = {
	.close = l4_redirect_ctx_close,
};

static struct triton_timer_t l4_redirect_timer = {
	.expire = l4_redirect_list_timer,
};

static void ipoe_init(void)
{
	ses_pool = mempool_create(sizeof(struct ipoe_session));
	uc_pool = mempool_create(sizeof(struct unit_cache));

	triton_context_register(&l4_redirect_ctx, NULL);
	triton_context_wakeup(&l4_redirect_ctx);

	load_config();

	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");
	
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif
}

DEFINE_INIT(52, ipoe_init);
