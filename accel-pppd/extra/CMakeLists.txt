ADD_LIBRARY(pppd_compat SHARED pppd_compat.c)
TARGET_LINK_LIBRARIES(pppd_compat sigchld)
ADD_LIBRARY(ippool SHARED ippool.c)
ADD_LIBRARY(ipv6pool SHARED ipv6pool.c)
ADD_LIBRARY(sigchld SHARED sigchld.c)
ADD_LIBRARY(chap-secrets SHARED chap-secrets.c)
ADD_LIBRARY(logwtmp SHARED logwtmp.c)
TARGET_LINK_LIBRARIES(logwtmp util)
ADD_LIBRARY(connlimit SHARED connlimit.c)

INSTALL(TARGETS pppd_compat ippool ipv6pool sigchld chap-secrets logwtmp connlimit
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
