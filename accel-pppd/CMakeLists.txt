SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fvisibility=hidden -fno-strict-aliasing -D_GNU_SOURCE -DPTHREAD_SPINLOCK -fPIC")

IF (NOT DEFINED LIB_SUFFIX)
	EXECUTE_PROCESS(
		COMMAND uname -m
		COMMAND tr -d '\n'
		OUTPUT_VARIABLE ARCH
	)
	message(STATUS "'"  ${ARCH}  "'")
	IF (ARCH STREQUAL x86_64)
		SET(LIB_SUFFIX 64)
	ENDIF (ARCH STREQUAL x86_64)
ENDIF (NOT DEFINED LIB_SUFFIX)


INCLUDE_DIRECTORIES(include)

IF (MEMDEBUG)
	ADD_DEFINITIONS(-DMEMDEBUG)
	IF (VALGRIND)
		ADD_DEFINITIONS(-DVALGRIND)
	ENDIF (VALGRIND)
ENDIF (MEMDEBUG)

IF (NOT DEFINED RADIUS)
	SET(RADIUS TRUE)
ENDIF (NOT DEFINED RADIUS)

IF (RADIUS)
	ADD_DEFINITIONS(-DRADIUS)
	ADD_SUBDIRECTORY(radius)
ENDIF (RADIUS)

ADD_SUBDIRECTORY(triton)
ADD_SUBDIRECTORY(ctrl)
ADD_SUBDIRECTORY(auth)
ADD_SUBDIRECTORY(logs)
ADD_SUBDIRECTORY(extra)
ADD_SUBDIRECTORY(ipv6)

IF (NOT DEFINED SHAPER)
	SET(SHAPER TRUE)
ENDIF (NOT DEFINED SHAPER)

IF (SHAPER)
	ADD_SUBDIRECTORY(shaper)
ENDIF (SHAPER)

ADD_EXECUTABLE(accel-pppd
	ppp/ppp.c
	ppp/ppp_ifcfg.c
	ppp/ppp_fsm.c
	ppp/ppp_lcp.c
	ppp/lcp_opt_mru.c
	ppp/lcp_opt_magic.c
	ppp/lcp_opt_pcomp.c
	ppp/lcp_opt_accomp.c
	ppp/ppp_auth.c
	ppp/ppp_ipcp.c
	ppp/ipcp_opt_ipaddr.c
	ppp/ipcp_opt_dns.c
	ppp/ipcp_opt_wins.c
	ppp/ipv6cp_opt_intfid.c
	ppp/ppp_ipv6cp.c
	ppp/ppp_ccp.c	
	ppp/ccp_mppe.c

	cli/std_cmd.c
	cli/show_sessions.c
	cli/telnet.c
	cli/tcp.c
	cli/cli.c

	libnetlink/libnetlink.c
	libnetlink/iputils.c
	libnetlink/genl.c

	pwdb.c
	ipdb.c

	iprange.c

	utils.c

	log.c
	main.c
	memdebug.c
)

TARGET_LINK_LIBRARIES(accel-pppd triton rt pthread ${crypto_lib} pcre)
set_property(TARGET accel-pppd PROPERTY CMAKE_SKIP_BUILD_RPATH FALSE)
set_property(TARGET accel-pppd PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET accel-pppd PROPERTY INSTALL_RPATH_USE_LINK_PATH FALSE)
set_property(TARGET accel-pppd PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp)

INSTALL(TARGETS accel-pppd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES accel-ppp.conf.5 DESTINATION share/man/man5)

IF (NOT DEFINED CPACK_TYPE)
	INSTALL(FILES accel-ppp.conf DESTINATION ${CMAKE_FIND_ROOT_PATH}/etc RENAME accel-ppp.conf.dist)

	INSTALL(CODE "EXECUTE_PROCESS(COMMAND mkdir -p ${CMAKE_FIND_ROOT_PATH}/var/log/accel-ppp)")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND mkdir -p ${CMAKE_FIND_ROOT_PATH}/var/run/accel-ppp)")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND 'echo 0 > ${CMAKE_FIND_ROOT_PATH}/var/run/accel-ppp/seq')")
ENDIF (NOT DEFINED CPACK_TYPE)

