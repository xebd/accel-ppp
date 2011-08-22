ADD_LIBRARY(pppd_compat SHARED pppd_compat.c)
ADD_LIBRARY(ippool SHARED ippool.c)
ADD_LIBRARY(ipv6pool SHARED ipv6pool.c)
ADD_LIBRARY(sigchld SHARED sigchld.c)
ADD_LIBRARY(chap-secrets SHARED chap-secrets.c)

INSTALL(TARGETS pppd_compat ippool sigchld chap-secrets
	LIBRARY DESTINATION lib/accel-ppp
)

IF (SHAPER)
	ADD_LIBRARY(shaper_tbf SHARED shaper_tbf.c)
	IF (LIBNL_PREFIX)
		SET_PROPERTY(TARGET shaper_tbf PROPERTY COMPILE_FLAGS "-I${LIBNL_PREFIX}/include")
		SET_PROPERTY(TARGET shaper_tbf PROPERTY LINK_FLAGS "-L${LIBNL_PREFIX}/lib")
	ENDIF (LIBNL_PREFIX)
	TARGET_LINK_LIBRARIES(shaper_tbf nl m)
	INSTALL(TARGETS shaper_tbf LIBRARY DESTINATION lib/accel-ppp)
ENDIF (SHAPER)


IF (NETSNMP)
	ADD_SUBDIRECTORY(net-snmp)
ENDIF (NETSNMP)
