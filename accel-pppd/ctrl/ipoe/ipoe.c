#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
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
#include "ipset.h"

#include "connlimit.h"

#include "ipoe.h"

#include "memdebug.h"

#define USERNAME_UNSET 0
#define USERNAME_IFNAME 1
#define USERNAME_LUA 2

#define MODE_L2 0
#define MODE_L3 1

struct ifaddr {
	struct list_head entry;
	in_addr_t addr;
	int mask;
	int refs;
};

struct iplink_arg {
	pcre *re;
	const char *opt;
	long *arg1;
};

struct unit_cache {
	struct list_head entry;
	int ifindex;
};

struct l4_redirect {
	struct list_head entry;
	in_addr_t addr;
	time_t timeout;
};

struct gw_addr {
	struct list_head entry;
	in_addr_t addr;
	int mask;
	int mask1;
};

struct disc_item {
	struct list_head entry;
	struct dhcpv4_packet *pack;
	struct timespec ts;
};

struct delay {
	struct list_head entry;
	unsigned int conn_cnt;
	int delay;
};

struct request_item {
	struct list_head entry;
	uint32_t xid;
	time_t expire;
	int cnt;
};

enum {SID_MAC, SID_IP};

static int conf_dhcpv4 = 1;
static int conf_up;
static int conf_mode;
static int conf_shared = 1;
static int conf_ifcfg = 1;
static int conf_nat;
static int conf_arp;
static int conf_ipv6;
static uint32_t conf_src;
static const char *conf_ip_pool;
static const char *conf_l4_redirect_pool;
//static int conf_dhcpv6;
static int conf_username;
static const char *conf_password;
static int conf_unit_cache;
static int conf_noauth;
#ifdef RADIUS
static int conf_attr_dhcp_client_ip;
static int conf_attr_dhcp_router_ip;
static int conf_attr_dhcp_mask;
static int conf_attr_dhcp_lease_time;
static int conf_attr_dhcp_renew_time;
static int conf_attr_l4_redirect;
static int conf_attr_l4_redirect_table;
static int conf_attr_l4_redirect_ipset;
static const char *conf_attr_dhcp_opt82;
static const char *conf_attr_dhcp_opt82_remote_id;
static const char *conf_attr_dhcp_opt82_circuit_id;
#endif
static int conf_l4_redirect_table;
static int conf_l4_redirect_on_reject;
static const char *conf_l4_redirect_ipset;
static int conf_vlan_timeout = 30;
static int conf_max_request = 3;
static int conf_session_timeout;
static int conf_idle_timeout;

static const char *conf_relay;

#ifdef USE_LUA
static const char *conf_lua_username_func;
#endif

static int conf_offer_timeout = 10;
static int conf_relay_timeout = 3;
static int conf_relay_retransmit = 3;
static LIST_HEAD(conf_gw_addr);
static int conf_netmask = 24;
static int conf_lease_time = 600;
static int conf_lease_timeout = 660;
static int conf_renew_time = 300;
static int conf_verbose;
static const char *conf_agent_remote_id;
static int conf_proto;
static LIST_HEAD(conf_offer_delay);
static const char *conf_vlan_name;
static int conf_ip_unnumbered;
static int conf_check_mac_change;
static int conf_soft_terminate;
static int conf_calling_sid = SID_MAC;

static unsigned int stat_starting;
static unsigned int stat_active;
static unsigned int stat_delayed_offer;

static mempool_t ses_pool;
static mempool_t disc_item_pool;
static mempool_t req_item_pool;

static int connlimit_loaded;
static int radius_loaded;

static LIST_HEAD(serv_list);
static pthread_mutex_t serv_lock = PTHREAD_MUTEX_INITIALIZER;

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
static void ipoe_serv_release(struct ipoe_serv *serv);
static void __ipoe_session_activate(struct ipoe_session *ses);
static void ipoe_ses_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack);
static void __ipoe_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack, int force);
static void ipoe_session_keepalive(struct dhcpv4_packet *pack);
static void add_interface(const char *ifname, int ifindex, const char *opt, int parent_ifindex, int vid);
static int get_offer_delay();
static void __ipoe_session_start(struct ipoe_session *ses);
static int ipoe_rad_send_auth_request(struct rad_plugin_t *rad, struct rad_packet_t *pack);
static int ipoe_rad_send_acct_request(struct rad_plugin_t *rad, struct rad_packet_t *pack);

static struct ipoe_session *ipoe_session_lookup(struct ipoe_serv *serv, struct dhcpv4_packet *pack, struct ipoe_session **opt82_ses)
{
	struct ipoe_session *ses, *res = NULL;

	uint8_t *agent_circuit_id = NULL;
	uint8_t *agent_remote_id = NULL;
	int opt82_match;

	if (opt82_ses)
		*opt82_ses = NULL;

	if (!conf_check_mac_change || (pack->relay_agent && dhcpv4_parse_opt82(pack->relay_agent, &agent_circuit_id, &agent_remote_id))) {
		agent_circuit_id = NULL;
		agent_remote_id = NULL;
	}

	list_for_each_entry(ses, &serv->sessions, entry) {
		opt82_match = conf_check_mac_change && pack->relay_agent != NULL;

		if (agent_circuit_id && !ses->agent_circuit_id)
			opt82_match = 0;

		if (opt82_match && agent_remote_id && !ses->agent_remote_id)
			opt82_match = 0;

		if (opt82_match && !agent_circuit_id && ses->agent_circuit_id)
			opt82_match = 0;

		if (opt82_match && !agent_remote_id && ses->agent_remote_id)
			opt82_match = 0;

		if (opt82_match && agent_circuit_id) {
			if (*agent_circuit_id != *ses->agent_circuit_id)
				opt82_match = 0;

			if (memcmp(agent_circuit_id + 1, ses->agent_circuit_id + 1, *agent_circuit_id))
				opt82_match = 0;
		}

		if (opt82_match && agent_remote_id) {
			if (*agent_remote_id != *ses->agent_remote_id)
				opt82_match = 0;

			if (memcmp(agent_remote_id + 1, ses->agent_remote_id + 1, *agent_remote_id))
				opt82_match = 0;
		}

		if (opt82_match && opt82_ses)
			*opt82_ses = ses;

		if (memcmp(pack->hdr->chaddr, ses->hwaddr, ETH_ALEN))
			continue;

		res = ses;
		break;

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

	if (!res || !pack->relay_agent || !opt82_ses || *opt82_ses)
		return res;

	list_for_each_entry(ses, &serv->sessions, entry) {
		if (agent_circuit_id && !ses->agent_circuit_id)
			continue;

		if (opt82_match && agent_remote_id && !ses->agent_remote_id)
			continue;

		if (opt82_match && !agent_circuit_id && ses->agent_circuit_id)
			continue;

		if (opt82_match && !agent_remote_id && ses->agent_remote_id)
			continue;

		if (opt82_match && agent_circuit_id) {
			if (*agent_circuit_id != *ses->agent_circuit_id)
				continue;

			if (memcmp(agent_circuit_id + 1, ses->agent_circuit_id + 1, *agent_circuit_id))
				continue;
		}

		if (opt82_match && agent_remote_id) {
			if (*agent_remote_id != *ses->agent_remote_id)
				continue;

			if (memcmp(agent_remote_id + 1, ses->agent_remote_id + 1, *agent_remote_id))
				continue;
		}

		*opt82_ses = ses;
		break;
	}

	return res;
}

static void ipoe_session_timeout(struct triton_timer_t *t)
{
	struct ipoe_session *ses = container_of(t, typeof(*ses), timer);

	triton_timer_del(t);

	log_ppp_info2("ipoe: session timed out\n");

	ap_session_terminate(&ses->ses, TERM_LOST_CARRIER, 1);
}

static void ipoe_session_l4_redirect_timeout(struct triton_timer_t *t)
{
	struct ipoe_session *ses = container_of(t, typeof(*ses), l4_redirect_timer);

	triton_timer_del(t);

	log_ppp_info2("ipoe: session timed out\n");

	ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
}

static void ipoe_relay_timeout(struct triton_timer_t *t)
{
	struct ipoe_session *ses = container_of(t, typeof(*ses), timer);

	if (!ses->serv->dhcpv4_relay || !ses->dhcpv4_request) {
		triton_timer_del(t);
		return;
	}

	if (++ses->relay_retransmit > conf_relay_retransmit) {
		triton_timer_del(t);

		log_ppp_info2("ipoe: relay timed out\n");

		ap_session_terminate(&ses->ses, TERM_LOST_CARRIER, 1);
	} else
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id);
}


static char *ipoe_session_get_username(struct ipoe_session *ses)
{
	if (ses->username)
		return ses->username;

#ifdef USE_LUA
	if (ses->serv->opt_username == USERNAME_LUA)
		return ipoe_lua_get_username(ses, ses->serv->opt_lua_username_func ? : conf_lua_username_func);
	else
#endif
	if (!ses->dhcpv4_request)
		return _strdup(ses->ctrl.calling_station_id);

	return _strdup(ses->serv->ifname);
}

static void l4_redirect_list_add(in_addr_t addr)
{
	struct l4_redirect *n = _malloc(sizeof(*n));
	struct timespec ts;

	if (!n)
		return;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	memset(n, 0, sizeof(*n));
	n->addr = addr;
	n->timeout = ts.tv_sec + conf_l4_redirect_on_reject;

	ipoe_nl_add_exclude(addr, 32);

	if (conf_l4_redirect_table)
		iprule_add(addr, conf_l4_redirect_table);

	if (conf_l4_redirect_ipset)
		ipset_add(conf_l4_redirect_ipset, addr);

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

	clock_gettime(CLOCK_MONOTONIC, &ts);

	pthread_rwlock_wrlock(&l4_list_lock);
	while (!list_empty(&l4_redirect_list)) {
		n = list_entry(l4_redirect_list.next, typeof(*n), entry);
		if (ts.tv_sec > n->timeout) {
			list_del(&n->entry);
			pthread_rwlock_unlock(&l4_list_lock);

			if (conf_l4_redirect_table)
				iprule_del(n->addr, conf_l4_redirect_table);

			if (conf_l4_redirect_ipset)
				ipset_del(conf_l4_redirect_ipset, n->addr);

			ipoe_nl_del_exclude(n->addr);

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

	if (ses->ses.ipv4)
		addr = ses->ses.ipv4->peer_addr;
	else
		addr = ses->yiaddr;

	if (ses->l4_redirect_table) {
		if (del) {
			iprule_del(addr, ses->l4_redirect_table);
			ses->l4_redirect_set = 0;
		} else {
			iprule_add(addr, ses->l4_redirect_table);
			ses->l4_redirect_set = 1;
		}
	}

	if (conf_l4_redirect_ipset || ses->l4_redirect_ipset) {
		if (del) {
			ipset_del(ses->l4_redirect_ipset ?: conf_l4_redirect_ipset, addr);
			ses->l4_redirect_set = 0;
		} else {
			ipset_add(ses->l4_redirect_ipset ?: conf_l4_redirect_ipset, addr);
			ses->l4_redirect_set = 1;
		}
	}

	if (del && ses->l4_redirect_timer.tpd)
		triton_timer_del(&ses->l4_redirect_timer);
}

static void ipoe_change_addr(struct ipoe_session *ses, in_addr_t newaddr)
{

}

static int ipoe_create_interface(struct ipoe_session *ses)
{
	struct unit_cache *uc;
	struct ifreq ifr;

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
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return -1;
		}
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ses->ifindex;
	if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		log_ppp_error("ipoe: failed to get interface name\n");
		ses->ifindex = -1;
		ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
		return -1;
	}

	strncpy(ses->ses.ifname, ifr.ifr_name, AP_IFNAME_LEN);
	ses->ses.ifindex = ses->ifindex;
	ses->ses.unit_idx = ses->ifindex;
	ses->ctrl.dont_ifcfg = !conf_ip_unnumbered;

	log_ppp_info2("create interface %s parent %s\n", ifr.ifr_name, ses->serv->ifname);

	return 0;
}

static void auth_result(struct ipoe_session *ses, int r)
{
	char *username = ses->username;

	ses->username = NULL;

	if (r == PWDB_DENIED) {
		if (conf_l4_redirect_on_reject && ses->dhcpv4_request) {
			ses->l4_redirect = 1;
			if (conf_l4_redirect_pool) {
				if (ses->ses.ipv4_pool_name)
					_free(ses->ses.ipv4_pool_name);
				ses->ses.ipv4_pool_name = _strdup(conf_l4_redirect_pool);
			}

			ses->l4_redirect_timer.expire = ipoe_session_l4_redirect_timeout;
			ses->l4_redirect_timer.expire_tv.tv_sec = conf_l4_redirect_on_reject;
			triton_timer_add(&ses->ctx, &ses->l4_redirect_timer, 0);

			ap_session_set_username(&ses->ses, username);
			log_ppp_info1("%s: authentication failed\n", ses->ses.username);
			log_ppp_info1("%s: start temporary session (l4-redirect)\n", ses->ses.username);
			goto cont;
		}

		pthread_rwlock_wrlock(&ses_lock);
		ses->ses.username = username;
		ses->ses.terminate_cause = TERM_AUTH_ERROR;
		pthread_rwlock_unlock(&ses_lock);
		if (conf_ppp_verbose)
			log_ppp_warn("authentication failed\n");
		if (conf_l4_redirect_on_reject && !ses->dhcpv4_request)
			l4_redirect_list_add(ses->yiaddr);
		ap_session_terminate(&ses->ses, TERM_AUTH_ERROR, 1);
		return;
	}

	ap_session_set_username(&ses->ses, username);
	log_ppp_info1("%s: authentication succeeded\n", ses->ses.username);

cont:
	triton_event_fire(EV_SES_AUTHORIZED, &ses->ses);

	if (ses->serv->opt_nat)
		ses->ses.ipv4 = ipdb_get_ipv4(&ses->ses);

	if (ses->serv->opt_shared == 0 && ses->ses.ipv4 && ses->ses.ipv4->peer_addr != ses->yiaddr) {
		if (ipoe_create_interface(ses))
			return;

		ap_session_set_ifindex(&ses->ses);
	}

	if (ses->dhcpv4_request && ses->serv->dhcpv4_relay) {
		dhcpv4_relay_send(ses->serv->dhcpv4_relay, ses->dhcpv4_request, ses->relay_server_id, ses->serv->ifname, conf_agent_remote_id);

		ses->timer.expire = ipoe_relay_timeout;
		ses->timer.period = conf_relay_timeout * 1000;
		triton_timer_add(&ses->ctx, &ses->timer, 0);
	} else
		__ipoe_session_start(ses);
}

static void ipoe_session_start(struct ipoe_session *ses)
{
	int r;
	char *passwd;
	char *username;
	const char *pass;

	if (ses->dhcpv4_request && conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(ses->dhcpv4_request, 0, log_ppp_info2);
	}

	__sync_add_and_fetch(&stat_starting, 1);

	assert(!ses->ses.username);

	username = ipoe_session_get_username(ses);

	if (!username) {
		ipoe_session_finished(&ses->ses);
		return;
	}

	ses->ses.unit_idx = ses->serv->ifindex;

	triton_event_fire(EV_CTRL_STARTING, &ses->ses);
	triton_event_fire(EV_CTRL_STARTED, &ses->ses);

	ap_session_starting(&ses->ses);

	if (conf_noauth)
		r = PWDB_SUCCESS;
	else {
		if (ses->serv->opt_shared && ipoe_create_interface(ses))
			return;

#ifdef RADIUS
		if (radius_loaded) {
			ses->radius.send_access_request = ipoe_rad_send_auth_request;
			ses->radius.send_accounting_request = ipoe_rad_send_acct_request;
			rad_register_plugin(&ses->ses, &ses->radius);
		}
#endif

		if (conf_password) {
			if (!strcmp(conf_password, "csid"))
				pass = ses->ctrl.calling_station_id;
			else
				pass = conf_password;
		} else
			pass = username;

		ses->username = username;
		r = pwdb_check(&ses->ses, (pwdb_callback)auth_result, ses, username, PPP_PAP, pass);

		if (r == PWDB_WAIT)
			return;

		if (r == PWDB_NO_IMPL) {
			passwd = pwdb_get_passwd(&ses->ses, username);
			if (!passwd || strcmp(passwd, pass))
				r = PWDB_DENIED;
			else {
				r = PWDB_SUCCESS;
				_free(passwd);
			}
		}
	}

	auth_result(ses, r);
}

static void find_gw_addr(struct ipoe_session *ses)
{
	struct gw_addr *a;

	list_for_each_entry(a, &conf_gw_addr, entry) {
		if ((ntohl(ses->yiaddr) & (a->mask1)) == (ntohl(a->addr) & (a->mask1))) {
			ses->router = a->addr;
			ses->mask = a->mask;
			return;
		}
	}
}

static void __ipoe_session_start(struct ipoe_session *ses)
{
	if (!ses->yiaddr) {
		dhcpv4_get_ip(ses->serv->dhcpv4, &ses->yiaddr, &ses->router, &ses->mask);
		if (ses->yiaddr)
			ses->dhcp_addr = 1;
	}

	if (!ses->yiaddr && !ses->serv->opt_nat)
		ses->ses.ipv4 = ipdb_get_ipv4(&ses->ses);

	if (ses->ses.ipv4) {
		if (!ses->mask)
			ses->mask = ses->ses.ipv4->mask;

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
			ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
			return;
		}

		if (!ses->router)
			find_gw_addr(ses);

		if (!ses->mask)
			ses->mask = conf_netmask;

		if (!ses->mask)
			ses->mask = 32;

		if (ses->dhcpv4_request->hdr->giaddr) {
			/*uint32_t mask = ses->mask == 32 ? 0xffffffff : (((1 << ses->mask) - 1) << (32 - ses->mask));

			ses->siaddr = iproute_get(ses->dhcpv4_request->hdr->giaddr);
			if ((ntohl(ses->router) & mask) == (ntohl(ses->siaddr) & mask))
				ses->siaddr = ses->router;
			else if (!ses->router)
				ses->router = ses->dhcpv4_request->hdr->giaddr;*/
			if (ses->serv->opt_mode == MODE_L2)
				ses->siaddr = ses->router;
			else {
				ses->siaddr = iproute_get(ses->dhcpv4_request->hdr->giaddr, NULL);
				if (!ses->router)
					ses->router = ses->dhcpv4_request->hdr->giaddr;
			}
		}

		if (!ses->router) {
			log_ppp_error("can't determine router address\n");
			ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
			return;
		}

		if (!ses->siaddr && ses->router != ses->yiaddr)
			ses->siaddr = ses->router;

		if (!ses->siaddr)
			ses->siaddr = ses->serv->opt_src;

		if (!ses->siaddr && ses->serv->dhcpv4_relay)
			ses->siaddr = ses->serv->dhcpv4_relay->giaddr;

		if (!ses->siaddr) {
			log_ppp_error("can't determine Server-ID\n");
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return;
		}

		if (ses->ses.ipv4 && !ses->ses.ipv4->addr)
			ses->ses.ipv4->addr = ses->siaddr;

		dhcpv4_send_reply(DHCPOFFER, ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->renew_time, ses->dhcpv4_relay_reply);

		dhcpv4_packet_free(ses->dhcpv4_request);
		ses->dhcpv4_request = NULL;

		ses->timer.expire = ipoe_session_timeout;
		ses->timer.period = 0;
		ses->timer.expire_tv.tv_sec = conf_offer_timeout;
		triton_timer_add(&ses->ctx, &ses->timer, 0);
	} else {
		if (!ses->siaddr)
			find_gw_addr(ses);

		if (!ses->siaddr)
			ses->siaddr = ses->serv->opt_src;

		if (!ses->siaddr)
			ses->siaddr = iproute_get(ses->yiaddr, NULL);

		if (!ses->siaddr) {
			log_ppp_error("can't determine local address\n");
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return;
		}

		if (ses->ses.ipv4 && !ses->ses.ipv4->addr)
			ses->ses.ipv4->addr = ses->siaddr;

		__ipoe_session_activate(ses);
	}
}

static void ipoe_serv_add_addr(struct ipoe_serv *serv, in_addr_t addr, int mask)
{
	struct ifaddr *a;

	pthread_mutex_lock(&serv->lock);

	if (serv->opt_shared) {
		list_for_each_entry(a, &serv->addr_list, entry) {
			if (a->addr == addr) {
				a->refs++;
				pthread_mutex_unlock(&serv->lock);

				return;
			}
		}
	}

	a = _malloc(sizeof(*a));
	a->addr = addr;
	a->mask = mask;
	a->refs = 1;
	list_add_tail(&a->entry, &serv->addr_list);

	if (ipaddr_add(serv->ifindex, a->addr, mask))
		log_warn("ipoe: failed to add addess to interface '%s'\n", serv->ifname);

	pthread_mutex_unlock(&serv->lock);
}

static void ipoe_serv_del_addr(struct ipoe_serv *serv, in_addr_t addr, int lock)
{
	struct ifaddr *a;

	if (lock)
		pthread_mutex_lock(&serv->lock);

	list_for_each_entry(a, &serv->addr_list, entry) {
		if (a->addr == addr) {
			if (--a->refs == 0) {
				if (ipaddr_del(serv->ifindex, a->addr, a->mask))
					log_warn("ipoe: failed to delete addess from interface '%s'\n", serv->ifname);
				list_del(&a->entry);
				_free(a);
			}
			break;
		}
	}

	if (lock)
		pthread_mutex_unlock(&serv->lock);
}

static void ipoe_ifcfg_add(struct ipoe_session *ses)
{
	struct ipoe_serv *serv = ses->serv;

	if (ses->serv->opt_ifcfg)
		ipoe_serv_add_addr(ses->serv, ses->siaddr, conf_ip_unnumbered ? 32 : ses->mask);

	if (conf_ip_unnumbered) {
		if (iproute_add(serv->ifindex, ses->serv->opt_src ? ses->serv->opt_src : ses->router, ses->yiaddr, 0, conf_proto))
			log_ppp_warn("ipoe: failed to add route to interface '%s'\n", serv->ifname);
	}

	ses->ifcfg = 1;
}

static void ipoe_ifcfg_del(struct ipoe_session *ses, int lock)
{
	struct ipoe_serv *serv = ses->serv;

	if (conf_ip_unnumbered) {
		if (iproute_del(serv->ifindex, ses->yiaddr, conf_proto))
			log_ppp_warn("ipoe: failed to delete route from interface '%s'\n", serv->ifname);
	}

	if (ses->serv->opt_ifcfg)
		ipoe_serv_del_addr(ses->serv, ses->siaddr, lock);
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
		else if (!conf_ip_unnumbered)
			ses->ctrl.dont_ifcfg = 1;

		if (ses->dhcpv4_request && ses->serv->opt_mode == MODE_L3) {
			in_addr_t gw;
			iproute_get(ses->router, &gw);
			if (gw)
				iproute_add(0, ses->siaddr, ses->yiaddr, gw, conf_proto);
			else
				iproute_add(0, ses->siaddr, ses->router, gw, conf_proto);
		}

		if (ipoe_nl_modify(ses->ifindex, ses->yiaddr, addr, NULL, NULL)) {
			ap_session_terminate(&ses->ses, TERM_NAS_ERROR, 1);
			return;
		}
	}

	if (!ses->ses.ipv4) {
		ses->ses.ipv4 = &ses->ipv4;
		ses->ipv4.owner = NULL;
		ses->ipv4.peer_addr = ses->yiaddr;
		ses->ipv4.addr = ses->siaddr;
	}

	if (ses->ifindex == -1) {
		if (ses->serv->opt_ifcfg || (ses->serv->opt_mode == MODE_L2))
			ipoe_ifcfg_add(ses);

		ipoe_nl_add_exclude(ses->yiaddr, 32);

		ses->ctrl.dont_ifcfg = 1;
	} else if (ses->ctrl.dont_ifcfg && ses->serv->opt_mode == MODE_L2)
		ipaddr_add(ses->ifindex, ses->siaddr, ses->mask);

	if (ses->l4_redirect)
		ipoe_change_l4_redirect(ses, 0);

	if (ses->serv->opt_mode == MODE_L2 && ses->serv->opt_ipv6 && sock6_fd != -1) {
		ses->ses.ipv6 = ipdb_get_ipv6(&ses->ses);
		if (!ses->ses.ipv6)
			log_ppp_warn("ipoe: no free IPv6 address\n");
		else if (!ses->ses.ipv6->peer_intf_id)
			ses->ses.ipv6->peer_intf_id = htobe64(1);
	}

	__sync_sub_and_fetch(&stat_starting, 1);
	__sync_add_and_fetch(&stat_active, 1);
	ses->started = 1;

	ap_session_activate(&ses->ses);

	if (ses->dhcpv4_request) {
		if (ses->ses.state == AP_STATE_ACTIVE)
			dhcpv4_send_reply(DHCPACK, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->renew_time, ses->dhcpv4_relay_reply);
		else
			dhcpv4_send_nak(ses->serv->dhcpv4, ses->dhcpv4_request);

		dhcpv4_packet_free(ses->dhcpv4_request);
		ses->dhcpv4_request = NULL;
	}

	ses->timer.expire = ipoe_session_timeout;
	ses->timer.period = 0;
	ses->timer.expire_tv.tv_sec = ses->lease_time;
	if (ses->timer.tpd)
		triton_timer_mod(&ses->timer, 0);
}

static void ipoe_session_activate(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (ses->ses.state == AP_STATE_ACTIVE) {
		ipoe_session_keepalive(pack);
		return;
	}

	if (ses->dhcpv4_request)
		dhcpv4_packet_free(ses->dhcpv4_request);

	ses->dhcpv4_request = pack;

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
		dhcpv4_send_reply(DHCPACK, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->renew_time, ses->dhcpv4_relay_reply);
	} else
		dhcpv4_send_nak(ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request);

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

	ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 1);
}

static void ipoe_session_started(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

	log_ppp_info1("ipoe: session started\n");

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
	if (ses->started)
		__sync_sub_and_fetch(&stat_active, 1);
	else
		__sync_sub_and_fetch(&stat_starting, 1);

	if (ses->timer.tpd)
		triton_timer_del(&ses->timer);

	if (ses->l4_redirect_timer.tpd)
		triton_timer_del(&ses->l4_redirect_timer);

	if (ses->dhcpv4_request)
		dhcpv4_packet_free(ses->dhcpv4_request);

	if (ses->dhcpv4_relay_reply)
		dhcpv4_packet_free(ses->dhcpv4_relay_reply);

	if (ses->ctrl.called_station_id)
		_free(ses->ctrl.called_station_id);

	if (ses->ctrl.calling_station_id)
		_free(ses->ctrl.calling_station_id);

	if (ses->l4_redirect_ipset)
		_free(ses->l4_redirect_ipset);

	triton_context_unregister(&ses->ctx);

	if (ses->data)
		_free(ses->data);

	mempool_free(ses);
}

static void ipoe_session_finished(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);
	struct unit_cache *uc;

	log_ppp_info1("ipoe: session finished\n");

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
	} else
		ipoe_nl_del_exclude(ses->yiaddr);

	if (ses->dhcp_addr)
		dhcpv4_put_ip(ses->serv->dhcpv4, ses->yiaddr);

	if (ses->relay_addr && ses->serv->dhcpv4_relay)
		dhcpv4_relay_send_release(ses->serv->dhcpv4_relay, ses->hwaddr, ses->xid, ses->yiaddr, ses->client_id, ses->relay_agent, ses->serv->ifname, conf_agent_remote_id);

	if (ses->ifcfg)
		ipoe_ifcfg_del(ses, 1);

	if (ses->dhcpv4)
		dhcpv4_free(ses->dhcpv4);

	triton_event_fire(EV_CTRL_FINISHED, s);

	if (s->ifindex == ses->serv->ifindex && strcmp(s->ifname, ses->serv->ifname)) {
		struct ifreq ifr;

		strcpy(ifr.ifr_name, s->ifname);

		ioctl(sock_fd, SIOCGIFFLAGS, &ifr);
		ifr.ifr_flags &= ~IFF_UP;
		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);

		strcpy(ifr.ifr_newname, ses->serv->ifname);
		ioctl(sock_fd, SIOCSIFNAME, &ifr);

		strcpy(ifr.ifr_name, ses->serv->ifname);
		ifr.ifr_flags |= IFF_UP;
		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	pthread_mutex_lock(&ses->serv->lock);
	list_del(&ses->entry);
	if  ((ses->serv->vid || ses->serv->need_close) && list_empty(&ses->serv->sessions))
		triton_context_call(&ses->serv->ctx, (triton_event_func)ipoe_serv_release, ses->serv);
	pthread_mutex_unlock(&ses->serv->lock);

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_free, ses);
}

static void ipoe_session_terminated(struct ipoe_session *ses)
{
	if (ses->l4_redirect_set)
		ipoe_change_l4_redirect(ses, 1);

	ap_session_finished(&ses->ses);
}

static void ipoe_session_terminated_pkt(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	dhcpv4_send_nak(ses->serv->dhcpv4, pack);

	dhcpv4_packet_free(pack);

	ipoe_session_terminated(ses);
}

static int ipoe_session_terminate(struct ap_session *s, int hard)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

	if (hard || !conf_soft_terminate || ses->UP)
		ipoe_session_terminated(ses);
	else
		ses->terminate = 1;

	return 0;
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
	uint8_t *ptr = NULL;

	ses = ipoe_session_alloc();
	if (!ses)
		return NULL;

	ses->serv = serv;
	ses->dhcpv4_request = pack;

	if (!serv->opt_shared)
		strncpy(ses->ses.ifname, serv->ifname, AP_IFNAME_LEN);

	ses->xid = pack->hdr->xid;
	memcpy(ses->hwaddr, pack->hdr->chaddr, 6);
	ses->giaddr = pack->hdr->giaddr;
	ses->lease_time = conf_lease_time;
	ses->renew_time = conf_renew_time;

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

	ses->ctrl.dont_ifcfg = 1;

	ses->ctrl.calling_station_id = _malloc(19);
	ses->ctrl.called_station_id = _strdup(serv->ifname);

	ptr = ses->hwaddr;
	sprintf(ses->ctrl.calling_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
			ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

	ses->ses.ctrl = &ses->ctrl;
	ses->ses.chan_name = ses->ctrl.calling_station_id;

	if (conf_ip_pool)
		ses->ses.ipv4_pool_name = _strdup(conf_ip_pool);

	triton_context_register(&ses->ctx, &ses->ses);

	triton_context_wakeup(&ses->ctx);

	//pthread_mutex_lock(&serv->lock);
	list_add_tail(&ses->entry, &serv->sessions);
	//pthread_mutex_unlock(&serv->lock);

	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);

	dhcpv4_packet_ref(pack);

	triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_start, ses);

	return ses;
}

static void __ipoe_session_terminate(struct ap_session *s)
{
	struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

	if (ses->terminate)
		ipoe_session_terminated(ses);
	else
		ap_session_terminate(s, TERM_USER_REQUEST, 1);
}

static void ipoe_ses_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(dhcpv4->ctx, typeof(*ses), ctx);
	int opt82_match;
	uint8_t *agent_circuit_id = NULL;
	uint8_t *agent_remote_id = NULL;

	if (ap_shutdown)
		return;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if (ses->terminate) {
		if (pack->msg_type != DHCPDISCOVER)
			dhcpv4_send_nak(dhcpv4, pack);
		triton_context_call(ses->ctrl.ctx, (triton_event_func)ipoe_session_terminated, ses);
		return;
	}

	if (pack->relay_agent && dhcpv4_parse_opt82(pack->relay_agent, &agent_circuit_id, &agent_remote_id)) {
		agent_circuit_id = NULL;
		agent_remote_id = NULL;
	}

	opt82_match = pack->relay_agent != NULL;

	if (agent_circuit_id && !ses->agent_circuit_id)
		opt82_match = 0;

	if (opt82_match && agent_remote_id && !ses->agent_remote_id)
		opt82_match = 0;

	if (opt82_match && !agent_circuit_id && ses->agent_circuit_id)
		opt82_match = 0;

	if (opt82_match && !agent_remote_id && ses->agent_remote_id)
		opt82_match = 0;

	if (opt82_match && agent_circuit_id) {
		if (*agent_circuit_id != *ses->agent_circuit_id)
			opt82_match = 0;

		if (memcmp(agent_circuit_id + 1, ses->agent_circuit_id + 1, *agent_circuit_id))
			opt82_match = 0;
	}

	if (opt82_match && agent_remote_id) {
		if (*agent_remote_id != *ses->agent_remote_id)
			opt82_match = 0;

		if (memcmp(agent_remote_id + 1, ses->agent_remote_id + 1, *agent_remote_id))
			opt82_match = 0;
	}

	if (conf_check_mac_change && pack->relay_agent && !opt82_match) {
		log_ppp_info2("port change detected\n");
		if (pack->msg_type == DHCPREQUEST)
			dhcpv4_send_nak(dhcpv4, pack);
		triton_context_call(ses->ctrl.ctx, (triton_event_func)__ipoe_session_terminate, &ses->ses);
		return;
	}

	if (pack->msg_type == DHCPDISCOVER) {
		if (ses->yiaddr) {
			if (ses->serv->dhcpv4_relay) {
				dhcpv4_packet_ref(pack);
				ipoe_session_keepalive(pack);
			} else
				dhcpv4_send_reply(DHCPOFFER, dhcpv4, pack, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->renew_time, ses->dhcpv4_relay_reply);
		}
	} else if (pack->msg_type == DHCPREQUEST) {
		ses->xid = pack->hdr->xid;
		if (pack->hdr->ciaddr == ses->yiaddr && pack->hdr->xid != ses->xid)
			ses->xid = pack->hdr->xid;
		if ((pack->server_id && (pack->server_id != ses->siaddr || pack->request_ip != ses->yiaddr)) ||
			(pack->hdr->ciaddr && (pack->hdr->xid != ses->xid || pack->hdr->ciaddr != ses->yiaddr))) {

			if (pack->server_id == ses->siaddr)
				dhcpv4_send_nak(dhcpv4, pack);
			else if (ses->serv->dhcpv4_relay)
				dhcpv4_relay_send(ses->serv->dhcpv4_relay, pack, 0, ses->serv->ifname, conf_agent_remote_id);

			triton_context_call(ses->ctrl.ctx, (triton_event_func)__ipoe_session_terminate, &ses->ses);
		} else {
			dhcpv4_packet_ref(pack);
			ipoe_session_keepalive(pack);
		}
	} else if (pack->msg_type == DHCPDECLINE || pack->msg_type == DHCPRELEASE) {
		dhcpv4_packet_ref(pack);
		triton_context_call(ses->ctrl.ctx, (triton_event_func)ipoe_session_decline, pack);
	}
}

static void ipoe_ses_recv_dhcpv4_discover(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if (ses->yiaddr)
		dhcpv4_send_reply(DHCPOFFER, ses->dhcpv4 ?: ses->serv->dhcpv4, pack, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->renew_time, ses->dhcpv4_relay_reply);

	dhcpv4_packet_free(pack);
}

static void ipoe_ses_recv_dhcpv4_request(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	ses->xid = pack->hdr->xid;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	if ((pack->server_id && (pack->server_id != ses->siaddr || pack->request_ip != ses->yiaddr)) ||
		(pack->hdr->ciaddr && (pack->hdr->ciaddr != ses->yiaddr))) {

		if (pack->server_id == ses->siaddr)
			dhcpv4_send_nak(ses->serv->dhcpv4, pack);

		ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 1);

		dhcpv4_packet_free(pack);
		return;
	}

	if (ses->ses.state == AP_STATE_STARTING && ses->yiaddr)
		ipoe_session_activate(pack);
	else if (ses->ses.state == AP_STATE_ACTIVE)
		ipoe_session_keepalive(pack);
	else
		dhcpv4_packet_free(pack);
}

static void ipoe_serv_disc_timer(struct triton_timer_t *t)
{
	struct ipoe_serv *serv = container_of(t, typeof(*serv), disc_timer);
	struct disc_item *d;
	struct timespec ts;
	int delay, offer_delay;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	while (!list_empty(&serv->disc_list)) {
		d = list_entry(serv->disc_list.next, typeof(*d), entry);

		delay = (ts.tv_sec - d->ts.tv_sec) * 1000 + (ts.tv_nsec - d->ts.tv_nsec) / 1000000;
		offer_delay = get_offer_delay();

		if (delay < offer_delay - 1) {
			delay = offer_delay - delay;
			t->expire_tv.tv_sec = delay / 1000;
			t->expire_tv.tv_usec = (delay % 1000) * 1000;
			triton_timer_mod(t, 0);
			return;
		}

		__ipoe_recv_dhcpv4(serv->dhcpv4, d->pack, 1);

		list_del(&d->entry);
		dhcpv4_packet_free(d->pack);
		mempool_free(d);

		__sync_sub_and_fetch(&stat_delayed_offer, 1);
	}

	triton_timer_del(t);
}

static void ipoe_serv_add_disc(struct ipoe_serv *serv, struct dhcpv4_packet *pack, int offer_delay)
{
	struct disc_item *d = mempool_alloc(disc_item_pool);

	if (!d)
		return;

	__sync_add_and_fetch(&stat_delayed_offer, 1);

	dhcpv4_packet_ref(pack);
	d->pack = pack;
	clock_gettime(CLOCK_MONOTONIC, &d->ts);
	list_add_tail(&d->entry, &serv->disc_list);

	if (!serv->disc_timer.tpd) {
		serv->disc_timer.expire_tv.tv_sec = offer_delay / 1000;
		serv->disc_timer.expire_tv.tv_usec = (offer_delay % 1000) * 1000;
		triton_timer_add(&serv->ctx, &serv->disc_timer, 0);
	}
}

static void ipoe_serv_check_disc(struct ipoe_serv *serv, struct dhcpv4_packet *pack)
{
	struct disc_item *d;

	list_for_each_entry(d, &serv->disc_list, entry) {
		if (d->pack->hdr->xid != pack->hdr->xid)
			continue;

		if (memcmp(d->pack->hdr->chaddr, pack->hdr->chaddr, ETH_ALEN))
			continue;

		list_del(&d->entry);
		dhcpv4_packet_free(d->pack);
		mempool_free(d);

		__sync_sub_and_fetch(&stat_delayed_offer, 1);

		break;
	}
}

static int ipoe_serv_request_check(struct ipoe_serv *serv, uint32_t xid)
{
	struct request_item *r;
	struct list_head *pos, *n;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	list_for_each_safe(pos, n, &serv->req_list) {
		r = list_entry(pos, typeof(*r), entry);
		if (r->xid == xid) {
			if (++r->cnt == conf_max_request) {
				list_del(&r->entry);
				mempool_free(r);
				return 1;
			}

			r->expire = ts.tv_sec + 30;
			return 0;
		}

		if (ts.tv_sec > r->expire) {
			list_del(&r->entry);
			mempool_free(r);
		}
	}

	r = mempool_alloc(req_item_pool);
	r->xid = xid;
	r->expire = ts.tv_sec + 30;
	r->cnt = 0;
	list_add_tail(&r->entry, &serv->req_list);

	return 0;
}

static void port_change_detected(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	dhcpv4_packet_free(pack);

	log_ppp_warn("port change detected\n");

	ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 1);
}

static void mac_change_detected(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 0, log_ppp_info2);
	}

	dhcpv4_packet_free(pack);

	log_ppp_warn("mac change detected\n");

	ap_session_terminate(&ses->ses, TERM_USER_REQUEST, 1);
}

static void __ipoe_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack, int force)
{
	struct ipoe_serv *serv = container_of(dhcpv4->ctx, typeof(*serv), ctx);
	struct ipoe_session *ses, *opt82_ses;
	int offer_delay;
	//struct dhcpv4_packet *reply;

	if (serv->timer.tpd)
		triton_timer_mod(&serv->timer, 0);

	if (ap_shutdown)
		return;

	if (connlimit_loaded && pack->msg_type == DHCPDISCOVER && connlimit_check(serv->opt_shared ? cl_key_from_mac(pack->hdr->chaddr) : serv->ifindex))
		return;

	pthread_mutex_lock(&serv->lock);
	if (pack->msg_type == DHCPDISCOVER) {
		ses = ipoe_session_lookup(serv, pack, &opt82_ses);
		if (!ses) {
			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, NULL);
			else if (opt82_ses) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&opt82_ses->ctx, (triton_event_func)mac_change_detected, pack);
			}

			offer_delay = get_offer_delay();
			if (offer_delay == -1)
				goto out;

			if (offer_delay && !force) {
				ipoe_serv_add_disc(serv, pack, offer_delay);
				goto out;
			}

			ses = ipoe_session_create_dhcpv4(serv, pack);
		}	else {
			if (ses->terminate) {
				triton_context_call(ses->ctrl.ctx, (triton_event_func)ipoe_session_terminated, ses);
				goto out;
			}

			if (conf_check_mac_change && ((opt82_ses && ses != opt82_ses) || (!opt82_ses && pack->relay_agent))) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&ses->ctx, (triton_event_func)port_change_detected, pack);
				if (opt82_ses)
					triton_context_call(&opt82_ses->ctx, (triton_event_func)__ipoe_session_terminate, &opt82_ses->ses);
				goto out;
			}

			dhcpv4_packet_ref(pack);
			triton_context_call(&ses->ctx, (triton_event_func)ipoe_ses_recv_dhcpv4_discover, pack);
		}
	} else if (pack->msg_type == DHCPREQUEST) {
		ipoe_serv_check_disc(serv, pack);

		ses = ipoe_session_lookup(serv, pack, &opt82_ses);

		if (!ses) {
			if (conf_verbose) {
				log_debug("%s: recv ", serv->ifname);
				dhcpv4_print_packet(pack, 0, log_debug);
			}

			if (!pack->server_id)
				dhcpv4_send_nak(dhcpv4, pack);

			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, NULL);
			else if (opt82_ses) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&opt82_ses->ctx, (triton_event_func)mac_change_detected, pack);
			} else if (list_empty(&conf_offer_delay) || ipoe_serv_request_check(serv, pack->hdr->xid))
				dhcpv4_send_nak(dhcpv4, pack);
		} else {
			if (ses->terminate) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_terminated_pkt, pack);
				goto out;
			}

			if (conf_check_mac_change && ((opt82_ses && ses != opt82_ses) || (!opt82_ses && pack->relay_agent))) {
				dhcpv4_packet_ref(pack);
				triton_context_call(&ses->ctx, (triton_event_func)port_change_detected, pack);
				if (opt82_ses)
					triton_context_call(&opt82_ses->ctx, (triton_event_func)__ipoe_session_terminate, &opt82_ses->ses);
				goto out;
			}

			if (serv->opt_shared == 0)
				ipoe_drop_sessions(serv, ses);

			dhcpv4_packet_ref(pack);
			triton_context_call(&ses->ctx, (triton_event_func)ipoe_ses_recv_dhcpv4_request, pack);
		}
	} else if (pack->msg_type == DHCPDECLINE || pack->msg_type == DHCPRELEASE) {
		ses = ipoe_session_lookup(serv, pack, &opt82_ses);
		if (ses) {
			ses->xid = pack->hdr->xid;
			dhcpv4_packet_ref(pack);
			triton_context_call(&ses->ctx, (triton_event_func)ipoe_session_decline, pack);
		}
	}

out:
	pthread_mutex_unlock(&serv->lock);
}

static void ipoe_recv_dhcpv4(struct dhcpv4_serv *dhcpv4, struct dhcpv4_packet *pack)
{
	__ipoe_recv_dhcpv4(dhcpv4, pack, 0);
}

static int parse_dhcpv4_mask(uint32_t mask)
{
	int i;

	for (i = 31; i >= 0 && (mask & (1 << i)); i--);

	return 32 - (i + 1);
}

static void ipoe_ses_recv_dhcpv4_relay(struct dhcpv4_packet *pack)
{
	struct ipoe_session *ses = container_of(triton_context_self(), typeof(*ses), ctx);
	struct dhcpv4_option *opt;

	if (ses->dhcpv4_relay_reply)
		dhcpv4_packet_free(ses->dhcpv4_relay_reply);

	if (!ses->dhcpv4_request) {
		ses->dhcpv4_relay_reply = NULL;
		return;
	}

	ses->dhcpv4_relay_reply = pack;

	if (conf_verbose) {
		log_ppp_info2("recv ");
		dhcpv4_print_packet(pack, 1, log_ppp_info2);
	}

	opt = dhcpv4_packet_find_opt(pack, 51);
	if (opt)
		ses->lease_time = ntohl(*(uint32_t *)opt->data);

	opt = dhcpv4_packet_find_opt(pack, 58);
	if (opt)
		ses->renew_time = ntohl(*(uint32_t *)opt->data);

	opt = dhcpv4_packet_find_opt(pack, 1);
	if (opt)
		ses->mask = parse_dhcpv4_mask(ntohl(*(uint32_t *)opt->data));

	opt = dhcpv4_packet_find_opt(pack, 3);
	if (opt)
		ses->router = *(uint32_t *)opt->data;

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
			dhcpv4_send_reply(DHCPOFFER, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->renew_time, ses->dhcpv4_relay_reply);
	} else if (pack->msg_type == DHCPACK) {
		if (ses->ses.state == AP_STATE_STARTING)
			__ipoe_session_activate(ses);
		else
			dhcpv4_send_reply(DHCPACK, ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request, ses->yiaddr, ses->siaddr, ses->router, ses->mask, ses->lease_time, ses->renew_time, ses->dhcpv4_relay_reply);

	} else if (pack->msg_type == DHCPNAK) {
		dhcpv4_send_nak(ses->dhcpv4 ?: ses->serv->dhcpv4, ses->dhcpv4_request);
		ap_session_terminate(&ses->ses, TERM_NAS_REQUEST, 1);
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

	if (found) {
		triton_context_call(&ses->ctx, (triton_event_func)ipoe_ses_recv_dhcpv4_relay, pack);
	} else
		dhcpv4_packet_free(pack);

	pthread_mutex_unlock(&serv->lock);
}


static struct ipoe_session *ipoe_session_create_up(struct ipoe_serv *serv, struct ethhdr *eth, struct iphdr *iph)
{
	struct ipoe_session *ses;
	uint8_t *hwaddr = eth->h_source;

	if (ap_shutdown)
		return NULL;

	if (l4_redirect_list_check(iph->saddr))
		return NULL;

	ses = ipoe_session_alloc();
	if (!ses)
		return NULL;

	ses->serv = serv;
	memcpy(ses->hwaddr, eth->h_source, 6);
	ses->yiaddr = iph->saddr;
	ses->UP = 1;

	if (!serv->opt_shared)
		strncpy(ses->ses.ifname, serv->ifname, AP_IFNAME_LEN);

	ses->ctrl.called_station_id = _strdup(serv->ifname);

	if (conf_calling_sid == SID_MAC) {
		ses->ctrl.calling_station_id = _malloc(19);
		sprintf(ses->ctrl.calling_station_id, "%02x:%02x:%02x:%02x:%02x:%02x",
				hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
	} else {
		ses->ctrl.calling_station_id = _malloc(17);
		u_inet_ntoa(iph->saddr, ses->ctrl.calling_station_id);
	}

	if (ses->serv->opt_username == USERNAME_IFNAME)
		ses->username = _strdup(serv->ifname);
	else {
		ses->username = _malloc(17);
		u_inet_ntoa(iph->saddr, ses->username);
	}

	ses->ses.chan_name = ses->ctrl.calling_station_id;

	if (conf_ip_pool)
		ses->ses.ipv4_pool_name = _strdup(conf_ip_pool);

	triton_context_register(&ses->ctx, &ses->ses);

	triton_context_wakeup(&ses->ctx);

	//pthread_mutex_lock(&serv->lock);
	list_add_tail(&ses->entry, &serv->sessions);
	//pthread_mutex_unlock(&serv->lock);

	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);

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
	ses->l4_redirect_table = conf_l4_redirect_table;

	ses->ses.ctrl = &ses->ctrl;

	ses->ses.idle_timeout = conf_idle_timeout;
	ses->ses.session_timeout = conf_session_timeout;

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
	int lease_time_set = 0, renew_time_set = 0;

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
				if (attr->val.ipaddr == 0xffffffff)
					ses->mask = 32;
				else
#if __BYTE_ORDER == __LITTLE_ENDIAN
				ses->mask = 31 - ffs(htonl(attr->val.ipaddr));
#else
				ses->mask = 31 - ffs(attr->val.ipaddr);
#endif
			}
		} else if (attr->attr->id == conf_attr_l4_redirect) {
			if (attr->attr->type == ATTR_TYPE_STRING) {
				if (attr->len && attr->val.string[0] != '0')
					ses->l4_redirect = 1;
			} else if (attr->val.integer != 0)
				ses->l4_redirect = 1;
		} else if (attr->attr->id == conf_attr_dhcp_lease_time) {
			ses->lease_time = attr->val.integer;
			lease_time_set = 1;
		}	else if (attr->attr->id == conf_attr_dhcp_renew_time) {
			ses->renew_time = attr->val.integer;
			renew_time_set = 1;
		} else if (attr->attr->id == conf_attr_l4_redirect_table)
			ses->l4_redirect_table = attr->val.integer;
		else if (attr->attr->id == conf_attr_l4_redirect_ipset) {
			if (attr->attr->type == ATTR_TYPE_STRING)
				ses->l4_redirect_ipset = _strdup(attr->val.string);
		}
	}

	if (lease_time_set && !renew_time_set)
		ses->renew_time = ses->lease_time / 2;
	else if (renew_time_set && ses->renew_time > ses->lease_time) {
		log_ppp_warn("ipoe: overriding renew time\n");
		ses->renew_time = ses->lease_time / 2;
	}
}

static void ev_radius_coa(struct ev_radius_t *ev)
{
	struct ipoe_session *ses = container_of(ev->ses, typeof(*ses), ses);
	struct rad_attr_t *attr;
	int l4_redirect;
	int lease_time_set = 0, renew_time_set = 0;

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
		} else if (attr->attr->id == conf_attr_dhcp_lease_time) {
			ses->lease_time = attr->val.integer;
			lease_time_set = 1;
		} else if (attr->attr->id == conf_attr_dhcp_renew_time) {
			ses->renew_time = attr->val.integer;
			renew_time_set = 1;
		} else if (attr->attr->id == conf_attr_l4_redirect_table)
			ses->l4_redirect_table = attr->val.integer;
		else if (attr->attr->id == conf_attr_l4_redirect_ipset) {
			if (attr->attr->type == ATTR_TYPE_STRING) {
				if (ses->l4_redirect_ipset && strcmp(ses->l4_redirect_ipset, attr->val.string)) {
					_free(ses->l4_redirect_ipset);
					ses->l4_redirect_ipset = _strdup(attr->val.string);
				}
			}
		}
	}

	if (lease_time_set && !renew_time_set)
		ses->renew_time = ses->lease_time / 2;
	else if (renew_time_set && ses->renew_time > ses->lease_time) {
		log_ppp_warn("ipoe: overriding renew time\n");
		ses->renew_time = ses->lease_time / 2;
	}

	//if (l4_redirect && !ses->l4_redirect) || (!l4_redirect && ses->l4_redirect))
	if (l4_redirect != ses->l4_redirect && ev->ses->state == AP_STATE_ACTIVE)
		ipoe_change_l4_redirect(ses, l4_redirect);
}

static int ipoe_rad_send_acct_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct ipoe_session *ses = container_of(rad, typeof(*ses), radius);

	if (!ses->relay_agent)
		return 0;

	if (conf_attr_dhcp_opt82 &&
		rad_packet_add_octets(pack, NULL, conf_attr_dhcp_opt82, ses->relay_agent->data, ses->relay_agent->len))
		return -1;

	if (conf_attr_dhcp_opt82_remote_id && ses->agent_remote_id &&
		rad_packet_add_octets(pack, NULL, conf_attr_dhcp_opt82_remote_id, ses->agent_remote_id + 1, *ses->agent_remote_id))
		return -1;

	if (conf_attr_dhcp_opt82_circuit_id && ses->agent_circuit_id &&
		rad_packet_add_octets(pack, NULL, conf_attr_dhcp_opt82_circuit_id, ses->agent_circuit_id + 1, *ses->agent_circuit_id))
		return -1;

	return 0;
}

static int ipoe_rad_send_auth_request(struct rad_plugin_t *rad, struct rad_packet_t *pack)
{
	struct ipoe_session *ses = container_of(rad, typeof(*ses), radius);

	if (ipoe_rad_send_acct_request(rad, pack))
		return -1;

	if (ses->yiaddr)
		rad_packet_add_ipaddr(pack, NULL, "Framed-IP-Address", ses->yiaddr);

	return 0;
}
#endif

static void ipoe_serv_release(struct ipoe_serv *serv)
{
	pthread_mutex_lock(&serv->lock);
	if (!list_empty(&serv->sessions)) {
		pthread_mutex_unlock(&serv->lock);
		return;
	}
	pthread_mutex_unlock(&serv->lock);

	if (serv->vid && !serv->need_close && !ap_shutdown) {
		if (serv->timer.tpd)
			triton_timer_mod(&serv->timer, 0);
		else
			triton_timer_add(&serv->ctx, &serv->timer, 0);

		return;
	}

	log_info2("ipoe: stop interface %s\n", serv->ifname);

	pthread_mutex_lock(&serv_lock);
	list_del(&serv->entry);
	pthread_mutex_unlock(&serv_lock);

	if (serv->dhcpv4)
		dhcpv4_free(serv->dhcpv4);

	if (serv->dhcpv4_relay) {
		ipoe_serv_del_addr(serv, serv->dhcpv4_relay->giaddr, 0);
		dhcpv4_relay_free(serv->dhcpv4_relay, &serv->ctx);
	}

	if (serv->arp)
		arpd_stop(serv->arp);

	while (!list_empty(&serv->disc_list)) {
		struct disc_item *d = list_entry(serv->disc_list.next, typeof(*d), entry);
		list_del(&d->entry);
		dhcpv4_packet_free(d->pack);
		mempool_free(d);
		__sync_sub_and_fetch(&stat_delayed_offer, 1);
	}

	while (!list_empty(&serv->req_list)) {
		struct request_item *r = list_first_entry(&serv->req_list, typeof(*r), entry);
		list_del(&r->entry);
		mempool_free(r);
	}

	if (serv->disc_timer.tpd)
		triton_timer_del(&serv->disc_timer);

	if (serv->timer.tpd)
		triton_timer_del(&serv->timer);

	if (serv->vid) {
		log_info2("ipoe: remove vlan %s\n", serv->ifname);
		iplink_vlan_del(serv->ifindex);
		ipoe_nl_add_vlan_mon_vid(serv->parent_ifindex, serv->vid);
	}

	triton_context_unregister(&serv->ctx);

	_free(serv->ifname);
	_free(serv);
}

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

	ipoe_serv_release(serv);
}

static void l4_redirect_ctx_close(struct triton_context_t *ctx)
{
	struct l4_redirect *n;

	pthread_rwlock_wrlock(&l4_list_lock);
	while (!list_empty(&l4_redirect_list)) {
		n = list_entry(l4_redirect_list.next, typeof(*n), entry);
		list_del(&n->entry);

		if (conf_l4_redirect_table)
			iprule_del(n->addr, conf_l4_redirect_table);

		if (conf_l4_redirect_ipset)
			ipset_del(conf_l4_redirect_ipset, n->addr);

		ipoe_nl_del_exclude(n->addr);

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
	cli_sendv(client,"  delayed: %u\r\n", stat_delayed_offer);

	return CLI_CMD_OK;
}

static void print_session_type(struct ap_session *s, char *buf)
{
	if (s->ctrl->type == CTRL_TYPE_IPOE) {
		struct ipoe_session *ses = container_of(s, typeof(*ses), ses);

		if (ses->UP)
			strcpy(buf, "up");
		else
			strcpy(buf, "dhcp");
	} else
		*buf = 0;
}

void __export ipoe_get_stat(unsigned int **starting, unsigned int **active)
{
	*starting = &stat_starting;
	*active = &stat_active;
}

static void __terminate(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REQUEST, 1);
}

static void ipoe_drop_sessions(struct ipoe_serv *serv, struct ipoe_session *skip)
{
	struct ipoe_session *ses;

	list_for_each_entry(ses, &serv->sessions, entry) {
		if (ses == skip)
			continue;

		ses->terminating = 1;
		if (ses->ifcfg) {
			ipoe_ifcfg_del(ses, 0);
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

static int get_offer_delay()
{
	struct delay *r, *prev = NULL;

	list_for_each_entry(r, &conf_offer_delay, entry) {
		if (!prev || stat_active >= r->conn_cnt) {
			prev = r;
			continue;
		}
		break;
	}

	if (prev)
		return prev->delay;

	return 0;
}

static int make_vlan_name(const char *parent, int svid, int cvid, char *name)
{
	char *ptr1 = name, *endptr = name + IFNAMSIZ;
	const char *ptr2 = conf_vlan_name;
	char svid_str[5], cvid_str[5], *ptr3;

#ifdef USE_LUA
	if (!memcmp(conf_vlan_name, "lua:", 4))
		return ipoe_lua_make_vlan_name(conf_vlan_name + 4, parent, svid, cvid, name);
#endif

	sprintf(svid_str, "%i", svid);
	sprintf(cvid_str, "%i", cvid);

	while (ptr1 < endptr && *ptr2) {
		if (ptr2[0] == '%' && ptr2[1] == 'I') {
			while (ptr1 < endptr && *parent)
				*ptr1++ = *parent++;
			ptr2 += 2;
		} else if (ptr2[0] == '%' && ptr2[1] == 'N') {
			ptr3 = cvid_str;
			while (ptr1 < endptr && *ptr3)
				*ptr1++ = *ptr3++;
			ptr2 += 2;
		} else if (ptr2[0] == '%' && ptr2[1] == 'P') {
			ptr3 = svid_str;
			while (ptr1 < endptr && *ptr3)
				*ptr1++ = *ptr3++;
			ptr2 += 2;
		} else
			*ptr1++ = *ptr2++;
	}

	if (ptr1 == endptr)
		return 1;

	*ptr1 = 0;

	return 0;
}

void ipoe_vlan_notify(int ifindex, int vid)
{
	struct conf_sect_t *sect = conf_get_section("ipoe");
	struct conf_option_t *opt;
	struct ifreq ifr;
	char *ptr;
	int len, r, svid;
	pcre *re = NULL;
	const char *pcre_err;
	char *pattern;
	int pcre_offset;
	char ifname[IFNAMSIZ];

	if (!sect)
		return;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;
	if (ioctl(sock_fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		log_error("ipoe: vlan-mon: failed to get interface name, ifindex=%i\n", ifindex);
		return;
	}

	svid = iplink_vlan_get_vid(ifindex);

	if (make_vlan_name(ifr.ifr_name, svid, vid, ifname)) {
		log_error("ipoe: vlan-mon: %s.%i: interface name is too long\n", ifr.ifr_name, vid);
		return;
	}

	log_info2("ipoe: create vlan %s parent %s\n", ifname, ifr.ifr_name);

	strcpy(ifr.ifr_name, ifname);
	len = strlen(ifr.ifr_name);

	if (iplink_vlan_add(ifr.ifr_name, ifindex, vid)) {
		log_warn("ipoe: vlan-mon: %s: failed to add vlan\n", ifr.ifr_name);
		return;
	}

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr, sizeof(ifr));
	ifr.ifr_flags |= IFF_UP;
	ioctl(sock_fd, SIOCSIFFLAGS, &ifr, sizeof(ifr));

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr, sizeof(ifr))) {
		log_error("ipoe: vlan-mon: %s: failed to get interface index\n", ifr.ifr_name);
		return;
	}

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "interface"))
			continue;
		if (!opt->val)
			continue;

		ptr = strchr(opt->val, ',');
		if (!ptr)
			ptr = strchr(opt->val, 0);

		if (ptr - opt->val > 3 && memcmp(opt->val, "re:", 3) == 0) {
			pattern = _malloc(ptr - (opt->val + 3) + 1);
			memcpy(pattern, opt->val + 3, ptr - (opt->val + 3));
			pattern[ptr - (opt->val + 3)] = 0;

			re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

			_free(pattern);

			if (!re)
				continue;

			r = pcre_exec(re, NULL, ifr.ifr_name, len, 0, 0, NULL, 0);
			pcre_free(re);

			if (r < 0)
				continue;

			add_interface(ifr.ifr_name, ifr.ifr_ifindex, opt->val, ifindex, vid);
		} else if (ptr - opt->val == len && memcmp(opt->val, ifr.ifr_name, len) == 0)
			add_interface(ifr.ifr_name, ifr.ifr_ifindex, opt->val, ifindex, vid);
	}
}

static void ipoe_serv_timeout(struct triton_timer_t *t)
{
	struct ipoe_serv *serv = container_of(t, typeof(*serv), timer);

	serv->need_close = 1;

	ipoe_serv_release(serv);
}

static void add_interface(const char *ifname, int ifindex, const char *opt, int parent_ifindex, int vid)
{
	char *str0 = NULL, *str, *ptr1, *ptr2;
	int end;
	struct ipoe_serv *serv;
	int opt_shared = conf_shared;
	int opt_dhcpv4 = 0;
	int opt_up = 0;
	int opt_mode = conf_mode;
	int opt_ifcfg = conf_ifcfg;
	int opt_nat = conf_nat;
	int opt_username = conf_username;
	int opt_ipv6 = conf_ipv6;
#ifdef USE_LUA
	char *opt_lua_username_func = NULL;
#endif
	const char *opt_relay = conf_relay;
	in_addr_t relay_addr = conf_relay ? inet_addr(conf_relay) : 0;
	in_addr_t opt_giaddr = 0;
	in_addr_t opt_src = conf_src;
	int opt_arp = conf_arp;
	struct ifreq ifr;

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
				opt_giaddr = inet_addr(ptr1);
			} else if (strcmp(str, "nat") == 0) {
				opt_nat = atoi(ptr1);
			} else if (strcmp(str, "src") == 0) {
				opt_src = inet_addr(ptr1);
			} else if (strcmp(str, "proxy-arp") == 0) {
				opt_arp = atoi(ptr1);
			} else if (strcmp(str, "ipv6") == 0) {
				opt_ipv6 = atoi(ptr1);
			} else if (strcmp(str, "username") == 0) {
				if (strcmp(ptr1, "ifname") == 0)
					opt_username = USERNAME_IFNAME;
#ifdef USE_LUA
					else if (strlen(ptr1) > 4 && memcmp(ptr1, "lua:", 4) == 0) {
					opt_username = USERNAME_LUA;
					opt_lua_username_func = _strdup(ptr1 + 4);
				}
#endif
				else
					log_error("ipoe: unknown username value '%s'\n", ptr1);
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

	if (opt_relay && !opt_giaddr && opt_dhcpv4) {
		struct sockaddr_in addr;
		int sock;
		socklen_t len = sizeof(addr);

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = relay_addr;
		addr.sin_port = htons(DHCP_SERV_PORT);

		sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

		if (connect(sock, &addr, sizeof(addr))) {
			log_error("dhcpv4: relay: %s: connect: %s\n", opt_relay, strerror(errno));
			goto out_err;
		}

		getsockname(sock, &addr, &len);
		opt_giaddr = addr.sin_addr.s_addr;

		close(sock);
	}

	if (opt_up)
		ipoe_nl_add_interface(ifindex);

	pthread_mutex_lock(&serv_lock);
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
			(serv->dhcpv4_relay->addr != relay_addr || serv->dhcpv4_relay->giaddr != opt_giaddr)) {
			if (serv->opt_ifcfg)
				ipoe_serv_del_addr(serv, serv->dhcpv4_relay->giaddr, 0);
			dhcpv4_relay_free(serv->dhcpv4_relay, &serv->ctx);
			serv->dhcpv4_relay = NULL;
		}

		if (!serv->dhcpv4_relay && serv->opt_dhcpv4 && opt_relay) {
			if (opt_ifcfg)
				ipoe_serv_add_addr(serv, opt_giaddr, 32);
			serv->dhcpv4_relay = dhcpv4_relay_create(opt_relay, opt_giaddr, &serv->ctx, (triton_event_func)ipoe_recv_dhcpv4_relay);
		}

		if (serv->arp && !conf_arp) {
			arpd_stop(serv->arp);
			serv->arp = NULL;
		} else if (!serv->arp && conf_arp)
			serv->arp = arpd_start(serv);

		serv->opt_up = opt_up;
		serv->opt_mode = opt_mode;
		serv->opt_ifcfg = opt_ifcfg;
		serv->opt_nat = opt_nat;
		serv->opt_src = opt_src;
		serv->opt_arp = opt_arp;
		serv->opt_username = opt_username;
		serv->opt_ipv6 = opt_ipv6;
#ifdef USE_LUA
		if (serv->opt_lua_username_func && (!opt_lua_username_func || strcmp(serv->opt_lua_username_func, opt_lua_username_func))) {
			_free(serv->opt_lua_username_func);
			serv->opt_lua_username_func = NULL;
		}

		if (!serv->opt_lua_username_func && opt_lua_username_func)
			serv->opt_lua_username_func = opt_lua_username_func;
		else if (opt_lua_username_func)
			_free(opt_lua_username_func);
#endif

		if (str0)
			_free(str0);

		pthread_mutex_unlock(&serv_lock);
		return;
	}
	pthread_mutex_unlock(&serv_lock);

	opt = strchr(opt, ',');
	if (opt)
		opt++;

	log_info2("ipoe: start interface %s (%s)\n", ifname, opt ? opt : "");

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);

	if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr)) {
		log_error("ipoe: '%s': ioctl(SIOCGIFHWADDR): %s\n", ifname, strerror(errno));
		return;
	}

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	serv = _malloc(sizeof(*serv));
	memset(serv, 0, sizeof(*serv));
	serv->ctx.close = ipoe_serv_close;
	serv->ctx.before_switch = log_switch;
	pthread_mutex_init(&serv->lock, NULL);
	serv->ifname = _strdup(ifname);
	serv->ifindex = ifindex;
	serv->opt_shared = opt_shared;
	serv->opt_dhcpv4 = opt_dhcpv4;
	serv->opt_up = opt_up;
	serv->opt_mode = opt_mode;
	serv->opt_ifcfg = opt_ifcfg;
	serv->opt_nat = opt_nat;
	serv->opt_src = opt_src;
	serv->opt_arp = opt_arp;
	serv->opt_username = opt_username;
	serv->opt_ipv6 = opt_ipv6;
#ifdef USE_LUA
	serv->opt_lua_username_func = opt_lua_username_func;
#endif
	serv->parent_ifindex = parent_ifindex = parent_ifindex;
	serv->vid = vid;
	serv->active = 1;
	INIT_LIST_HEAD(&serv->sessions);
	INIT_LIST_HEAD(&serv->addr_list);
	INIT_LIST_HEAD(&serv->disc_list);
	INIT_LIST_HEAD(&serv->req_list);
	memcpy(serv->hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	serv->disc_timer.expire = ipoe_serv_disc_timer;

	triton_context_register(&serv->ctx, NULL);

	if (serv->opt_dhcpv4) {
		serv->dhcpv4 = dhcpv4_create(&serv->ctx, serv->ifname, opt);
		if (serv->dhcpv4)
			serv->dhcpv4->recv = ipoe_recv_dhcpv4;

		if (opt_relay) {
			if (opt_ifcfg)
				ipoe_serv_add_addr(serv, opt_giaddr, 32);
			serv->dhcpv4_relay = dhcpv4_relay_create(opt_relay, opt_giaddr, &serv->ctx, (triton_event_func)ipoe_recv_dhcpv4_relay);
		}
	}

	if (serv->opt_arp)
		serv->arp = arpd_start(serv);

	if (vid) {
		serv->timer.expire = ipoe_serv_timeout;
		serv->timer.expire_tv.tv_sec = conf_vlan_timeout;
		triton_timer_add(&serv->ctx, &serv->timer, 0);
	}

	triton_context_wakeup(&serv->ctx);

	pthread_mutex_lock(&serv_lock);
	list_add_tail(&serv->entry, &serv_list);
	pthread_mutex_unlock(&serv_lock);

	if (str0)
		_free(str0);

	return;

parse_err:
	log_error("ipoe: failed to parse '%s'\n", opt);
out_err:
	_free(str0);
}

static void load_interface(const char *opt)
{
	const char *ptr;
	struct ifreq ifr;
	struct ipoe_serv *serv;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	if (ptr - opt >= sizeof(ifr.ifr_name))
		return;

	memcpy(ifr.ifr_name, opt, ptr - opt);
	ifr.ifr_name[ptr - opt] = 0;

	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->active)
			continue;

		if (!strcmp(serv->ifname, ifr.ifr_name)) {
			add_interface(serv->ifname, serv->ifindex, opt, 0, 0);
			return;
		}
	}

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("ipoe: '%s': ioctl(SIOCGIFINDEX): %s\n", ifr.ifr_name, strerror(errno));
		return;
	}

	add_interface(ifr.ifr_name, ifr.ifr_ifindex, opt, 0, 0);
}

static int __load_interface_re(int index, int flags, const char *name, struct iplink_arg *arg)
{
	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	add_interface(name, index, arg->opt, 0, 0);

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
	struct ipoe_serv *serv;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	pattern = _malloc(ptr - (opt + 3) + 1);
	memcpy(pattern, opt + 3, ptr - (opt + 3));
	pattern[ptr - (opt + 3)] = 0;

	re = pcre_compile2(pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);

	if (!re) {
		log_error("ipoe: '%s': %s at %i\r\n", pattern, pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = opt;

	iplink_list((iplink_list_func)__load_interface_re, &arg);

	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->active)
			continue;

		if (pcre_exec(re, NULL, serv->ifname, strlen(serv->ifname), 0, 0, NULL, 0) >= 0)
			add_interface(serv->ifname, serv->ifindex, opt, 0, 0);
	}

	pcre_free(re);
	_free(pattern);
}

static void load_interfaces(struct conf_sect_t *sect)
{
	struct ipoe_serv *serv;
	struct conf_option_t *opt;

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

	list_for_each_entry(serv, &serv_list, entry) {
		if (!serv->active && !serv->vid) {
			ipoe_drop_sessions(serv, NULL);
			triton_context_call(&serv->ctx, (triton_event_func)ipoe_serv_release, serv);
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

	ipoe_nl_add_net(addr, mask);

	return;

out_err:
	log_error("ipoe: failed to parse 'local-net=%s'\n", opt);
}

static void parse_bypass_net(const char *opt)
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

	ipoe_nl_add_bypass_net(addr, mask);

	return;

	out_err:
	log_error("ipoe: failed to parse 'bypass-net=%s'\n", opt);
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

static void load_bypass_nets(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;

	ipoe_nl_delete_bypass_nets();

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "bypass-net"))
			continue;
		if (!opt->val)
			continue;
		parse_bypass_net(opt->val);
	}
}

static void load_gw_addr(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;
	struct gw_addr *a;
	char addr[17];
	char *ptr;

	while (!list_empty(&conf_gw_addr)) {
		a = list_entry(conf_gw_addr.next, typeof(*a), entry);
		list_del(&a->entry);
		_free(a);
	}

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "gw-ip-address"))
			continue;
		if (!opt->val)
			continue;

		a = _malloc(sizeof(*a));
		ptr = strchr(opt->val, '/');
		if (ptr) {
			memcpy(addr, opt->val, ptr - opt->val);
			addr[ptr - opt->val] = 0;
			a->addr = inet_addr(addr);
			a->mask = atoi(ptr + 1);
		} else {
			a->addr = inet_addr(opt->val);
			a->mask = 32;
		}

		if (a->addr == 0xffffffff || a->mask < 1 || a->mask > 32) {
			log_error("ipoe: failed to parse '%s=%s'\n", opt->name, opt->val);
			_free(a);
			continue;
		}

		a->mask1 = ((1 << a->mask) - 1) << (32 - a->mask);
		list_add_tail(&a->entry, &conf_gw_addr);
	}
}

#ifdef RADIUS
static void parse_conf_rad_attr(const char *opt, int *val)
{
	struct rad_dict_attr_t *attr;

	opt = conf_get_opt("ipoe", opt);

	*val = 0;

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
	}
}

static void load_radius_attrs(void)
{
	parse_conf_rad_attr("attr-dhcp-client-ip", &conf_attr_dhcp_client_ip);
	parse_conf_rad_attr("attr-dhcp-router-ip", &conf_attr_dhcp_router_ip);
	parse_conf_rad_attr("attr-dhcp-mask", &conf_attr_dhcp_mask);
	parse_conf_rad_attr("attr-dhcp-lease-time", &conf_attr_dhcp_lease_time);
	parse_conf_rad_attr("attr-dhcp-renew-time", &conf_attr_dhcp_renew_time);
	parse_conf_rad_attr("attr-l4-redirect", &conf_attr_l4_redirect);
	parse_conf_rad_attr("attr-l4-redirect-table", &conf_attr_l4_redirect_table);
	parse_conf_rad_attr("attr-l4-redirect-ipset", &conf_attr_l4_redirect_ipset);
	conf_attr_dhcp_opt82 = conf_get_opt("ipoe", "attr-dhcp-opt82");
	conf_attr_dhcp_opt82_remote_id = conf_get_opt("ipoe", "attr-dhcp-opt82-remote-id");
	conf_attr_dhcp_opt82_circuit_id = conf_get_opt("ipoe", "attr-dhcp-opt82-circuit-id");
}
#endif

static void strip(char *str)
{
	char *ptr = str;
	char *endptr = strchr(str, 0);
	while (1) {
		ptr = strchr(ptr, ' ');
		if (ptr)
			memmove(ptr, ptr + 1, endptr - ptr - 1);
		else
			break;
	}
}

int parse_offer_delay(const char *str)
{
	char *str1;
	char *ptr1, *ptr2, *ptr3, *endptr;
	struct delay *r;

	while (!list_empty(&conf_offer_delay)) {
		r = list_entry(conf_offer_delay.next, typeof(*r), entry);
		list_del(&r->entry);
		_free(r);
	}

	if (!str)
		return 0;

	str1 = _strdup(str);
	strip(str1);

	ptr1 = str1;

	while (1) {
		ptr2 = strchr(ptr1, ',');
		if (ptr2)
			*ptr2 = 0;
		ptr3 = strchr(ptr1, ':');
		if (ptr3)
			*ptr3 = 0;

		r = _malloc(sizeof(*r));
		memset(r, 0, sizeof(*r));

		r->delay = strtol(ptr1, &endptr, 10);
		if (*endptr)
			goto out_err;

		if (list_empty(&conf_offer_delay))
			r->conn_cnt = 0;
		else {
			if (!ptr3)
				goto out_err;
			r->conn_cnt = strtol(ptr3 + 1, &endptr, 10);
			if (*endptr)
				goto out_err;
		}

		list_add_tail(&r->entry, &conf_offer_delay);

		if (!ptr2)
			break;

		ptr1 = ptr2 + 1;
	}

	_free(str1);
	return 0;

out_err:
	_free(str1);
	log_error("ipoe: failed to parse offer-delay\n");
	return -1;
}

static int parse_vlan_mon(const char *opt, long *mask)
{
	char *ptr, *ptr2;
	int vid, vid2;

	ptr = strchr(opt, ',');
	if (!ptr)
		ptr = strchr(opt, 0);

	if (*ptr == ',')
		memset(mask, 0xff, 4096/8);
	else if (*ptr == 0) {
		memset(mask, 0, 4096/8);
		return 0;
	} else
		goto out_err;

	while (1) {
		vid = strtol(ptr + 1, &ptr2, 10);
		if (vid <= 0 || vid >= 4096) {
			log_error("ipoe: vlan-mon=%s: invalid vlan %i\n", opt, vid);
			return -1;
		}

		if (*ptr2 == '-') {
			vid2 = strtol(ptr2 + 1, &ptr2, 10);
			if (vid2 <= 0 || vid2 >= 4096) {
				log_error("ipoe: vlan-mon=%s: invalid vlan %i\n", opt, vid2);
				return -1;
			}

			for (; vid < vid2; vid++)
				mask[vid / (8*sizeof(long))] &= ~(1lu << (vid % (8*sizeof(long))));
		}

		mask[vid / (8*sizeof(long))] &= ~(1lu << (vid % (8*sizeof(long))));

		if (*ptr2 == 0)
			break;

		if (*ptr2 != ',')
			goto out_err;

		ptr = ptr2;
	}

	return 0;

out_err:
	log_error("ipoe: vlan-mon=%s: failed to parse\n", opt);
	return -1;
}

static void add_vlan_mon(const char *opt, long *mask)
{
	const char *ptr;
	struct ifreq ifr;
	int ifindex;
	long mask1[4096/8/sizeof(long)];
	struct ipoe_serv *serv;

	for (ptr = opt; *ptr && *ptr != ','; ptr++);

	if (ptr - opt >= IFNAMSIZ) {
		log_error("ipoe: vlan-mon=%s: interface name is too long\n", opt);
		return;
	}

	memset(&ifr, 0, sizeof(ifr));

	memcpy(ifr.ifr_name, opt, ptr - opt);
	ifr.ifr_name[ptr - opt] = 0;

	if (ioctl(sock_fd, SIOCGIFINDEX, &ifr)) {
		log_error("ipoe: '%s': ioctl(SIOCGIFINDEX): %s\n", ifr.ifr_name, strerror(errno));
		return;
	}

	ifindex = ifr.ifr_ifindex;

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, mask, sizeof(mask1));
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->vid && serv->parent_ifindex == ifindex)
			mask1[serv->vid / (8*sizeof(long))] |= 1lu << (serv->vid % (8*sizeof(long)));
	}

	ipoe_nl_add_vlan_mon(ifindex, mask1, sizeof(mask1));
}

static int __load_vlan_mon_re(int index, int flags, const char *name, struct iplink_arg *arg)
{
	struct ifreq ifr;
	long mask1[4096/8/sizeof(long)];
	struct ipoe_serv *serv;

	if (pcre_exec(arg->re, NULL, name, strlen(name), 0, 0, NULL, 0) < 0)
		return 0;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, name);

	ioctl(sock_fd, SIOCGIFFLAGS, &ifr);

	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;

		ioctl(sock_fd, SIOCSIFFLAGS, &ifr);
	}

	memcpy(mask1, arg->arg1, sizeof(mask1));
	list_for_each_entry(serv, &serv_list, entry) {
		if (serv->vid && serv->parent_ifindex == index)
			mask1[serv->vid / (8*sizeof(long))] |= 1lu << (serv->vid % (8*sizeof(long)));
	}

	ipoe_nl_add_vlan_mon(index, mask1, sizeof(mask1));

	return 0;
}

static void load_vlan_mon_re(const char *opt, long *mask, int len)
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
		log_error("ipoe: '%s': %s at %i\r\n", pattern, pcre_err, pcre_offset);
		return;
	}

	arg.re = re;
	arg.opt = opt;
	arg.arg1 = mask;

	iplink_list((iplink_list_func)__load_vlan_mon_re, &arg);

	pcre_free(re);
	_free(pattern);

}

static void load_vlan_mon(struct conf_sect_t *sect)
{
	struct conf_option_t *opt;
	long mask[4096/8/sizeof(long)];

	ipoe_nl_del_vlan_mon(-1);

	list_for_each_entry(opt, &sect->items, entry) {
		if (strcmp(opt->name, "vlan-mon"))
			continue;

		if (!opt->val)
			continue;

		if (parse_vlan_mon(opt->val, mask))
			continue;

		if (strlen(opt->val) > 3 && !memcmp(opt->val, "re:", 3))
			load_vlan_mon_re(opt->val, mask, sizeof(mask));
		else
			add_vlan_mon(opt->val, mask);
	}
}


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
	} else
		conf_username = USERNAME_UNSET;

	opt = conf_get_opt("ipoe", "password");
	if (opt) {
		if (!strcmp(opt, "username"))
			conf_password = NULL;
		else if (!strcmp(opt, "empty"))
			conf_password = "";
		else
			conf_password = opt;
	} else
		conf_password = NULL;

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

	opt = conf_get_opt("ipoe", "renew-time");
	if (opt)
		conf_renew_time = atoi(opt);
	else
		conf_renew_time = conf_lease_time/2;

	opt = conf_get_opt("ipoe", "max-lease-time");
	if (opt)
		conf_lease_timeout = atoi(opt);
	else
		conf_lease_timeout = conf_lease_time;

	opt = conf_get_opt("ipoe", "unit-cache");
	if (opt)
		conf_unit_cache = atoi(opt);

	opt = conf_get_opt("ipoe", "l4-redirect-table");
	if (opt && atoi(opt) > 0)
		conf_l4_redirect_table = atoi(opt);
	else
		conf_l4_redirect_table = 0;

	conf_l4_redirect_ipset = conf_get_opt("ipoe", "l4-redirect-ipset");

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

	opt = conf_get_opt("ipoe", "nat");
	if (opt)
		conf_nat = atoi(opt);
	else
		conf_nat = 0;

	opt = conf_get_opt("ipoe", "src");
	if (opt)
		conf_src = inet_addr(opt);
	else
		conf_src = 0;

	opt = conf_get_opt("ipoe", "proxy-arp");
	if (opt)
		conf_arp = atoi(opt);
	else
		conf_arp = 0;

	if (conf_arp < 0 || conf_arp > 2) {
		log_error("ipoe: arp=%s: invalid value\n", opt);
		conf_arp = 0;
	}

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

	opt = conf_get_opt("ipoe", "relay-timeout");
	if (opt && atoi(opt) > 0)
		conf_relay_timeout = atoi(opt);
	else
		conf_relay_timeout = 3;

	opt = conf_get_opt("ipoe", "relay-retransmit");
	if (opt && atoi(opt) > 0)
		conf_relay_retransmit = atoi(opt);
	else
		conf_relay_retransmit = 3;

	opt = conf_get_opt("ipoe", "agent-remote-id");
	if (opt)
		conf_agent_remote_id = opt;
	else
		conf_agent_remote_id = NULL;

	opt = conf_get_opt("ipoe", "ipv6");
	if (opt)
		conf_ipv6 = atoi(opt);
	else
		conf_ipv6 = 0;

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

	opt = conf_get_opt("ipoe", "proto");
	if (opt && atoi(opt) > 0)
		conf_proto = atoi(opt);
	else
		conf_proto = 3;

	opt = conf_get_opt("ipoe", "vlan-timeout");
	if (opt && atoi(opt) > 0)
		conf_vlan_timeout = atoi(opt);
	else
		conf_vlan_timeout = 60;

	opt = conf_get_opt("ipoe", "offer-timeout");
	if (opt && atoi(opt) > 0)
		conf_offer_timeout = atoi(opt);
	else
		conf_offer_timeout = 10;

	conf_ip_pool = conf_get_opt("ipoe", "ip-pool");
	conf_l4_redirect_pool = conf_get_opt("ipoe", "l4-redirect-ip-pool");

	conf_vlan_name = conf_get_opt("ipoe", "vlan-name");
	if (!conf_vlan_name)
		conf_vlan_name = "%I.%N";

	opt = conf_get_opt("ipoe", "ip-unnumbered");
	if (opt)
		conf_ip_unnumbered = atoi(opt);
	else
		conf_ip_unnumbered = 1;

	opt = conf_get_opt("ipoe", "idle-timeout");
	if (opt)
		conf_idle_timeout = atoi(opt);
	else
		conf_idle_timeout = 0;

	opt = conf_get_opt("ipoe", "session-timeout");
	if (opt)
		conf_session_timeout = atoi(opt);
	else
		conf_session_timeout = 0;

	opt = conf_get_opt("ipoe", "soft-terminate");
	if (opt)
		conf_soft_terminate = atoi(opt);
	else
		conf_soft_terminate = 0;

	opt = conf_get_opt("ipoe", "check-mac-change");
	if (opt)
		conf_check_mac_change = atoi(opt);
	else
		conf_check_mac_change = 1;

	opt = conf_get_opt("ipoe", "calling-sid");
	if (opt) {
		if (!strcmp(opt, "mac"))
			conf_calling_sid = SID_MAC;
		else if (!strcmp(opt, "ip"))
			conf_calling_sid = SID_IP;
		else
			log_error("ipoe: failed to parse 'calling-sid=%s'\n", opt);
	} else
		conf_calling_sid = SID_MAC;

#ifdef RADIUS
	if (triton_module_loaded("radius"))
		load_radius_attrs();
#endif

	parse_offer_delay(conf_get_opt("ipoe", "offer-delay"));

	load_interfaces(s);
	load_local_nets(s);
	load_bypass_nets(s);
	load_vlan_mon(s);
	load_gw_addr(s);
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
	disc_item_pool = mempool_create(sizeof(struct disc_item));
	req_item_pool = mempool_create(sizeof(struct request_item));
	uc_pool = mempool_create(sizeof(struct unit_cache));

	triton_context_register(&l4_redirect_ctx, NULL);
	triton_context_wakeup(&l4_redirect_ctx);

	load_config();

	if (conf_l4_redirect_ipset)
		ipset_flush(conf_l4_redirect_ipset);

	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");
	cli_show_ses_register("ipoe-type", "IPoE session type", print_session_type);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

#ifdef RADIUS
	if (triton_module_loaded("radius")) {
		triton_event_register_handler(EV_RADIUS_ACCESS_ACCEPT, (triton_event_func)ev_radius_access_accept);
		triton_event_register_handler(EV_RADIUS_COA, (triton_event_func)ev_radius_coa);
	}
#endif

	connlimit_loaded = triton_module_loaded("connlimit");
	radius_loaded = triton_module_loaded("radius");
}

DEFINE_INIT(52, ipoe_init);
