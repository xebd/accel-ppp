#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <utmp.h>

#include "ppp.h"
#include "events.h"
#include "triton.h"
#include "log.h"

#include "memdebug.h"


static void ev_ppp_started(struct ppp_t *ppp)
{
	logwtmp(ppp->ifname, ppp->username, ppp->ctrl->calling_station_id);
}

static void ev_ppp_finished(struct ppp_t *ppp)
{
	logwtmp(ppp->ifname, "", "");
}

static void init(void)
{
	triton_event_register_handler(EV_PPP_STARTED, (triton_event_func)ev_ppp_started);
	triton_event_register_handler(EV_PPP_FINISHED, (triton_event_func)ev_ppp_finished);
}

DEFINE_INIT(200, init);
