ADD_LIBRARY(pppd_compat SHARED pppd_compat.c)
ADD_LIBRARY(ippool SHARED ippool.c)
ADD_LIBRARY(sigchld SHARED sigchld.c)

INSTALL(TARGETS pppd_compat ippool sigchld
	LIBRARY DESTINATION usr/lib/accel-pptp
)

