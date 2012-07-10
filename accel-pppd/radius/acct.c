#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "linux_ppp.h"

#include "crypto.h"

#include "log.h"
#include "backup.h"
#include "ap_session_backup.h"
#include "radius_p.h"

#include "memdebug.h"

#define STAT_UPDATE_INTERVAL (10 * 60 * 1000)
#define INTERIM_SAFE_TIME 10

static int req_set_RA(struct rad_req_t *req, const char *secret)
{
	MD5_CTX ctx;
	
	if (rad_packet_build(req->pack, req->RA))
		return -1;

	MD5_Init(&ctx);
	MD5_Update(&ctx, req->pack->buf, req->pack->len);
	MD5_Update(&ctx, secret, strlen(secret));
	MD5_Final(req->pack->buf + 4, &ctx);

	return 0;
}

static void req_set_stat(struct rad_req_t *req, struct ap_session *ses)
{
	struct ifpppstatsreq ifreq;
	time_t stop_time;
	
	if (ses->stop_time)
		stop_time = ses->stop_time;
	else
		time(&stop_time);

	memset(&ifreq, 0, sizeof(ifreq));
	ifreq.stats_ptr = (void *)&ifreq.stats;
	strcpy(ifreq.ifr__name, ses->ifname);

	if (ses->ctrl->type != CTRL_TYPE_IPOE) {
		if (ioctl(sock_fd, SIOCGPPPSTATS, &ifreq)) {
			log_ppp_error("radius: failed to get ppp statistics: %s\n", strerror(errno));
			return;
		}

		if (ifreq.stats.p.ppp_ibytes < req->rpd->acct_input_octets)
			req->rpd->acct_input_gigawords++;
		req->rpd->acct_input_octets = ifreq.stats.p.ppp_ibytes;

		if (ifreq.stats.p.ppp_obytes < req->rpd->acct_output_octets)
			req->rpd->acct_output_gigawords++;
		req->rpd->acct_output_octets = ifreq.stats.p.ppp_obytes;

		rad_packet_change_int(req->pack, NULL, "Acct-Input-Octets", ifreq.stats.p.ppp_ibytes);
		rad_packet_change_int(req->pack, NULL, "Acct-Output-Octets", ifreq.stats.p.ppp_obytes);
		rad_packet_change_int(req->pack, NULL, "Acct-Input-Packets", ifreq.stats.p.ppp_ipackets);
		rad_packet_change_int(req->pack, NULL, "Acct-Output-Packets", ifreq.stats.p.ppp_opackets);
		rad_packet_change_int(req->pack, NULL, "Acct-Input-Gigawords", req->rpd->acct_input_gigawords);
		rad_packet_change_int(req->pack, NULL, "Acct-Output-Gigawords", req->rpd->acct_output_gigawords);
	}
	rad_packet_change_int(req->pack, NULL, "Acct-Session-Time", stop_time - ses->start_time);
}

static int rad_acct_read(struct triton_md_handler_t *h)
{
	struct rad_req_t *req = container_of(h, typeof(*req), hnd);
	struct rad_packet_t *pack;
	int r;
	unsigned int dt;

	if (req->reply) {
		rad_packet_free(req->reply);
		req->reply = NULL;
	}

	while (1) {
		r = rad_packet_recv(h->fd, &pack, NULL);

		if (pack) {
			rad_server_reply(req->serv);
			if (req->reply)
				rad_packet_free(req->reply);
			req->reply = pack;
			if (conf_interim_verbose) {
				log_ppp_info2("recv ");
				rad_packet_print(req->reply, req->serv, log_ppp_info2);
			}
		}

		if (r)
			break;
	}

	if (!req->reply)
		return 0;

	dt = (req->reply->tv.tv_sec - req->pack->tv.tv_sec) * 1000 + 
		(req->reply->tv.tv_nsec - req->pack->tv.tv_nsec) / 1000000;

	stat_accm_add(req->serv->stat_interim_query_1m, dt);
	stat_accm_add(req->serv->stat_interim_query_5m, dt);

	if (req->reply->code != CODE_ACCOUNTING_RESPONSE || req->reply->id != req->pack->id) {
		rad_packet_free(req->reply);
		req->reply = NULL;
	} else {
		if (req->timeout.tpd)
			triton_timer_del(&req->timeout);
	}

	return 0;
}

static void __rad_req_send(struct rad_req_t *req)
{
	while (1) {
		if (rad_server_req_enter(req)) {
			if (rad_server_realloc(req)) {
				if (conf_acct_timeout) {
					log_ppp_warn("radius:acct: no servers available, terminating session...\n");
					ap_session_terminate(req->rpd->ses, TERM_NAS_ERROR, 0);
				}
				break;
			}
			continue;
		}

		rad_req_send(req, conf_interim_verbose);
		if (!req->hnd.tpd) {
			triton_md_register_handler(req->rpd->ses->ctrl->ctx, &req->hnd);
			triton_md_enable_handler(&req->hnd, MD_MODE_READ);
		}

		rad_server_req_exit(req);

		break;
	}
}

static void rad_acct_timeout(struct triton_timer_t *t)
{
	struct rad_req_t *req = container_of(t, typeof(*req), timeout);
	time_t ts, dt;

	__sync_add_and_fetch(&req->serv->stat_interim_lost, 1);
	stat_accm_add(req->serv->stat_interim_lost_1m, 1);
	stat_accm_add(req->serv->stat_interim_lost_5m, 1);

	if (conf_acct_timeout == 0) {
		rad_server_timeout(req->serv);
		triton_timer_del(t);
		return;
	}

	time(&ts);

	dt = ts - req->rpd->acct_timestamp;

	if (dt > conf_acct_timeout) {
		rad_server_fail(req->serv);
		if (rad_server_realloc(req)) {
			log_ppp_warn("radius:acct: no servers available, terminating session...\n");
			ap_session_terminate(req->rpd->ses, TERM_NAS_ERROR, 0);
			return;
		}
		time(&req->rpd->acct_timestamp);
	}
	if (dt > conf_acct_timeout / 2) {
		req->timeout.period += 1000;
		triton_timer_mod(&req->timeout, 0);
	} else if (dt > conf_acct_timeout / 3) {
		if (req->timeout.period != conf_timeout * 2000) {
			req->timeout.period = conf_timeout * 2000;
			triton_timer_mod(&req->timeout, 0);
		}
	}

	if (conf_acct_delay_time) {
		req->pack->id++;	
		rad_packet_change_int(req->pack, NULL, "Acct-Delay-Time", dt);
		req_set_RA(req, req->serv->secret);
	}

	__rad_req_send(req);

	__sync_add_and_fetch(&req->serv->stat_interim_sent, 1);
}

static void rad_acct_interim_update(struct triton_timer_t *t)
{
	struct radius_pd_t *rpd = container_of(t, typeof(*rpd), acct_interim_timer);

	if (rpd->acct_req->timeout.tpd)
		return;

	if (rpd->session_timeout.expire_tv.tv_sec && 
			rpd->session_timeout.expire_tv.tv_sec - (time(NULL) - rpd->ses->start_time) < INTERIM_SAFE_TIME)
			return;

	req_set_stat(rpd->acct_req, rpd->ses);
	if (!rpd->acct_interim_interval)
		return;

	time(&rpd->acct_timestamp);
	rpd->acct_req->pack->id++;

	rad_packet_change_val(rpd->acct_req->pack, NULL, "Acct-Status-Type", "Interim-Update");
	if (conf_acct_delay_time)
		rad_packet_change_int(rpd->acct_req->pack, NULL, "Acct-Delay-Time", 0);
	req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret);

	__rad_req_send(rpd->acct_req);

	__sync_add_and_fetch(&rpd->acct_req->serv->stat_interim_sent, 1);

	rpd->acct_req->timeout.period = conf_timeout * 1000;
	triton_timer_add(rpd->ses->ctrl->ctx, &rpd->acct_req->timeout, 0);
}

int rad_acct_start(struct radius_pd_t *rpd)
{
	int i;
	time_t ts;
	unsigned int dt;
	
	if (!conf_accounting)
		return 0;

	if (!rpd->acct_req)
		rpd->acct_req = rad_req_alloc(rpd, CODE_ACCOUNTING_REQUEST, rpd->ses->username);

	if (!rpd->acct_req)
		return -1;

	if (rad_req_acct_fill(rpd->acct_req)) {
		log_ppp_error("radius:acct: failed to fill accounting attributes\n");
		goto out_err;
	}

	//if (rad_req_add_val(rpd->acct_req, "Acct-Status-Type", "Start", 4))
	//	goto out_err;
	//if (rad_req_add_str(rpd->acct_req, "Acct-Session-Id", rpd->ses->ionid, PPP_SESSIONID_LEN, 1))
	//	goto out_err;

	if (rpd->acct_req->reply) {
		rad_packet_free(rpd->acct_req->reply);
		rpd->acct_req->reply = NULL;
	}

	time(&rpd->acct_timestamp);
	
	if (req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret))
		goto out_err;

#ifdef USE_BACKUP
	if (rpd->ses->state != AP_STATE_RESTORE || !rpd->ses->backup->internal) {
#endif
		while (1) {

			if (rad_server_req_enter(rpd->acct_req)) {
				if (rad_server_realloc(rpd->acct_req)) {
					log_ppp_warn("radius:acct_start: no servers available\n");
					goto out_err;
				}
				if (req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret))
					goto out_err;
				continue;
			}

			for (i = 0; i < conf_max_try; i++) {
				if (conf_acct_delay_time) {
					time(&ts);
					rad_packet_change_int(rpd->acct_req->pack, NULL, "Acct-Delay-Time", ts - rpd->acct_timestamp);
					if (req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret))
						goto out_err;
				}

				if (rad_req_send(rpd->acct_req, conf_verbose))
					goto out_err;

				__sync_add_and_fetch(&rpd->acct_req->serv->stat_acct_sent, 1);

				rad_req_wait(rpd->acct_req, conf_timeout);

				if (!rpd->acct_req->reply) {
					if (conf_acct_delay_time)
						rpd->acct_req->pack->id++;
					__sync_add_and_fetch(&rpd->acct_req->serv->stat_acct_lost, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_1m, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_5m, 1);
					continue;
				}

				dt = (rpd->acct_req->reply->tv.tv_sec - rpd->acct_req->pack->tv.tv_sec) * 1000 + 
					(rpd->acct_req->reply->tv.tv_nsec - rpd->acct_req->pack->tv.tv_nsec) / 1000000;
				stat_accm_add(rpd->acct_req->serv->stat_acct_query_1m, dt);
				stat_accm_add(rpd->acct_req->serv->stat_acct_query_5m, dt);

				if (rpd->acct_req->reply->id != rpd->acct_req->pack->id || rpd->acct_req->reply->code != CODE_ACCOUNTING_RESPONSE) {
					rad_packet_free(rpd->acct_req->reply);
					rpd->acct_req->reply = NULL;
					rpd->acct_req->pack->id++;
					__sync_add_and_fetch(&rpd->acct_req->serv->stat_acct_lost, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_1m, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_5m, 1);
				} else
					break;
			}

			rad_server_req_exit(rpd->acct_req);

			if (rpd->acct_req->reply)
				break;

			rad_server_fail(rpd->acct_req->serv);
			if (rad_server_realloc(rpd->acct_req)) {
				log_ppp_warn("radius:acct_start: no servers available\n");
				goto out_err;
			}
			if (req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret))
				goto out_err;
		}
#ifdef USE_BACKUP
	}
#endif

	rpd->acct_req->hnd.read = rad_acct_read;

	triton_md_register_handler(rpd->ses->ctrl->ctx, &rpd->acct_req->hnd);
	if (triton_md_enable_handler(&rpd->acct_req->hnd, MD_MODE_READ))
		goto out_err;
	
	rpd->acct_req->timeout.expire = rad_acct_timeout;
	rpd->acct_req->timeout.period = conf_timeout * 1000;
	
	rpd->acct_interim_timer.expire = rad_acct_interim_update;
	rpd->acct_interim_timer.period = rpd->acct_interim_interval ? rpd->acct_interim_interval * 1000 : STAT_UPDATE_INTERVAL;
	if (rpd->acct_interim_interval && triton_timer_add(rpd->ses->ctrl->ctx, &rpd->acct_interim_timer, 0)) {
		triton_md_unregister_handler(&rpd->acct_req->hnd);
		triton_timer_del(&rpd->acct_req->timeout);
		goto out_err;
	}
	return 0;

out_err:
	rad_req_free(rpd->acct_req);
	rpd->acct_req = NULL;
	return -1;
}

void rad_acct_stop(struct radius_pd_t *rpd)
{
	int i;
	time_t ts;
	unsigned int dt;

	if (!rpd->acct_req || !rpd->acct_req->serv)
		return;

	if (rpd->acct_interim_timer.tpd)
		triton_timer_del(&rpd->acct_interim_timer);

	if (rpd->acct_req) {
		triton_md_unregister_handler(&rpd->acct_req->hnd);
		if (rpd->acct_req->timeout.tpd)
			triton_timer_del(&rpd->acct_req->timeout);

		switch (rpd->ses->terminate_cause) {
			case TERM_USER_REQUEST:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "User-Request");
				break;
			case TERM_SESSION_TIMEOUT:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "Session-Timeout");
				break;
			case TERM_ADMIN_RESET:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "Admin-Reset");
				break;
			case TERM_USER_ERROR:
			case TERM_AUTH_ERROR:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "User-Error");
				break;
			case TERM_NAS_ERROR:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "NAS-Error");
				break;
			case TERM_NAS_REQUEST:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "NAS-Request");
				break;
			case TERM_NAS_REBOOT:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "NAS-Reboot");
				break;
			case TERM_LOST_CARRIER:
				rad_packet_add_val(rpd->acct_req->pack, NULL, "Acct-Terminate-Cause", "Lost-Carrier");
				break;
		}
		rad_packet_change_val(rpd->acct_req->pack, NULL, "Acct-Status-Type", "Stop");
		req_set_stat(rpd->acct_req, rpd->ses);
		req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret);
		/// !!! rad_req_add_val(rpd->acct_req, "Acct-Terminate-Cause", "");
		
		if (rpd->acct_req->reply) {
			rad_packet_free(rpd->acct_req->reply);
			rpd->acct_req->reply = NULL;
		}
	
		time(&rpd->acct_timestamp);

		while (1) {

			if (rad_server_req_enter(rpd->acct_req)) {
				if (rad_server_realloc(rpd->acct_req)) {
					log_ppp_warn("radius:acct_stop: no servers available\n");
					break;
				}
				req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret);
				continue;
			}

			for(i = 0; i < conf_max_try; i++) {
				if (conf_acct_delay_time) {
					time(&ts);
					rad_packet_change_int(rpd->acct_req->pack, NULL, "Acct-Delay-Time", ts - rpd->acct_timestamp);
					rpd->acct_req->pack->id++;
					if (req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret))
						break;
				}
				if (rad_req_send(rpd->acct_req, conf_verbose))
					break;
				__sync_add_and_fetch(&rpd->acct_req->serv->stat_acct_sent, 1);
				rad_req_wait(rpd->acct_req, conf_timeout);
				if (!rpd->acct_req->reply) {
					__sync_add_and_fetch(&rpd->acct_req->serv->stat_acct_lost, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_1m, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_5m, 1);
					continue;
				}

				dt = (rpd->acct_req->reply->tv.tv_sec - rpd->acct_req->pack->tv.tv_sec) * 1000 + 
					(rpd->acct_req->reply->tv.tv_nsec - rpd->acct_req->pack->tv.tv_nsec) / 1000000;
				stat_accm_add(rpd->acct_req->serv->stat_acct_query_1m, dt);
				stat_accm_add(rpd->acct_req->serv->stat_acct_query_5m, dt);

				if (rpd->acct_req->reply->id != rpd->acct_req->pack->id || rpd->acct_req->reply->code != CODE_ACCOUNTING_RESPONSE) {
					rad_packet_free(rpd->acct_req->reply);
					rpd->acct_req->reply = NULL;
					__sync_add_and_fetch(&rpd->acct_req->serv->stat_acct_lost, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_1m, 1);
					stat_accm_add(rpd->acct_req->serv->stat_acct_lost_5m, 1);
				} else
					break;
			}

			rad_server_req_exit(rpd->acct_req);

			if (rpd->acct_req->reply)
				break;

			rad_server_fail(rpd->acct_req->serv);
			if (rad_server_realloc(rpd->acct_req)) {
				log_ppp_warn("radius:acct_stop: no servers available\n");
				break;
			}
			req_set_RA(rpd->acct_req, rpd->acct_req->serv->secret);
		}

		rad_req_free(rpd->acct_req);
		rpd->acct_req = NULL;
	}
}

