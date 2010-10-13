ADD_LIBRARY(pppd_compat SHARED pppd_compat.c)
ADD_LIBRARY(ippool SHARED ippool.c)
ADD_LIBRARY(sigchld SHARED sigchld.c)
ADD_LIBRARY(shaper_tbf SHARED shaper_tbf.c)
TARGET_LINK_LIBRARIES(shaper_tbf nl)

INSTALL(TARGETS pppd_compat ippool sigchld
	LIBRARY DESTINATION usr/lib/accel-pptp
)

