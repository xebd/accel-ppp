INCLUDE(CheckLibraryExists)
INCLUDE(CheckIncludeFiles)

CHECK_LIBRARY_EXISTS(crypto MD5_Init "" HAVE_SSL)
IF (NOT HAVE_SSL)
	MESSAGE(FATAL_ERROR "openssl library not found")
ENDIF (NOT HAVE_SSL)

SET(CMAKE_REQUIRED_INCLUDES "openssl")
CHECK_INCLUDE_FILES("md5.h" HAVE_SSL)
IF (NOT HAVE_SSL)
	MESSAGE(FATAL_ERROR "openssl headers not found")
ENDIF (NOT HAVE_SSL)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fvisibility=hidden -fno-strict-aliasing -D_GNU_SOURCE -DPTHREAD_SPINLOCK -fPIC")

IF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT DEFINED IGNORE_GIT)
	EXECUTE_PROCESS(
		COMMAND git log
		COMMAND head -n1
		COMMAND awk "{print $2}"
		WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}
		OUTPUT_VARIABLE ACCEL_PPP_VERSION
	)
	STRING(STRIP ${ACCEL_PPP_VERSION} ACCEL_PPP_VERSION)
ELSE (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT DEFINED IGNORE_GIT)
	SET (ACCEL_PPP_VERSION 1.3.7)
ENDIF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT DEFINED IGNORE_GIT)

ADD_DEFINITIONS(-DACCEL_PPP_VERSION="${ACCEL_PPP_VERSION}")

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

ADD_EXECUTABLE(accel-pppd
	ppp/ppp.c
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
	ppp/ipv6cp_opt_intfid.c
	ppp/ppp_ipv6cp.c
	ppp/ppp_ccp.c	
	ppp/ccp_mppe.c

	cli/std_cmd.c
	cli/show_sessions.c
	cli/telnet.c
	cli/tcp.c
	cli/cli.c

	pwdb.c
	ipdb.c

	iprange.c

	utils.c

	log.c
	main.c
	memdebug.c
)

TARGET_LINK_LIBRARIES(accel-pppd triton rt pthread crypto pcre)
set_property(TARGET accel-pppd PROPERTY CMAKE_SKIP_BUILD_RPATH FALSE)
set_property(TARGET accel-pppd PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET accel-pppd PROPERTY INSTALL_RPATH_USE_LINK_PATH FALSE)
set_property(TARGET accel-pppd PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib/accel-ppp)

INSTALL(TARGETS accel-pppd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES accel-ppp.conf.5 DESTINATION share/man/man5)

IF (NOT DEFINED CPACK_TYPE)
	INSTALL(FILES accel-ppp.conf DESTINATION /etc RENAME accel-ppp.conf.dist)

	INSTALL(CODE "EXECUTE_PROCESS(COMMAND mkdir -p /var/log/accel-ppp)")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND mkdir -p /var/run/accel-ppp)")
	INSTALL(CODE "EXECUTE_PROCESS(COMMAND 'echo 0 > /var/run/accel-ppp/seq')")
ENDIF (NOT DEFINED CPACK_TYPE)

