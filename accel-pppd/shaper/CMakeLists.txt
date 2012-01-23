ADD_LIBRARY(shaper SHARED shaper.c limiter.c tc_core.c libnetlink.c)

INSTALL(TARGETS shaper
	LIBRARY DESTINATION lib/accel-ppp
)

