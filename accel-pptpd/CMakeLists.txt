INCLUDE(CheckLibraryExists)
INCLUDE(CheckIncludeFiles)

CHECK_LIBRARY_EXISTS(crypto MD5_Init "" HAVE_SSL)
IF (NOT HAVE_SSL)
	MESSAGE(FATAL_ERROR "openssl library not found")
ENDIF (NOT HAVE_SSL)

CHECK_INCLUDE_FILES("openssl/md5.h" HAVE_SSL)
IF (NOT HAVE_SSL)
	MESSAGE(FATAL_ERROR "openssl headers not found")
ENDIF (NOT HAVE_SSL)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fvisibility=hidden -fno-strict-aliasing -D_GNU_SOURCE -DPTHREAD_SPINLOCK -DMEMDEBUG -fPIC")

IF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git)
	EXECUTE_PROCESS(
		COMMAND git log
		COMMAND head -n1
		COMMAND awk "{print $2}"
		WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}
		OUTPUT_VARIABLE ACCEL_PPTP_VERSION
	)
	STRING(STRIP ${ACCEL_PPTP_VERSION} ACCEL_PPTP_VERSION)
ELSE (EXISTS ${CMAKE_HOME_DIRECTORY}/.git)
	SET (ACCEL_PPTP_VERSION 1.3.2)
ENDIF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git)

ADD_DEFINITIONS(-DACCEL_PPTP_VERSION="${ACCEL_PPTP_VERSION}")

INCLUDE_DIRECTORIES(include)

IF (NOT DEFINED RADIUS)
	SET(RADIUS TRUE)
ENDIF (NOT DEFINED RADIUS)

IF (RADIUS)
	ADD_DEFINITIONS(-DRADIUS)
	ADD_SUBDIRECTORY(radius)
ENDIF (RADIUS)

IF (VALGRIND)
	ADD_DEFINITIONS(-DVALGRIND)
ENDIF (VALGRIND)

ADD_SUBDIRECTORY(triton)
ADD_SUBDIRECTORY(ctrl)
ADD_SUBDIRECTORY(auth)
ADD_SUBDIRECTORY(logs)
ADD_SUBDIRECTORY(extra)

ADD_EXECUTABLE(accel-pptpd
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

TARGET_LINK_LIBRARIES(accel-pptpd triton rt pthread crypto pcre)
set_property(TARGET accel-pptpd PROPERTY CMAKE_SKIP_BUILD_RPATH FALSE)
set_property(TARGET accel-pptpd PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET accel-pptpd PROPERTY INSTALL_RPATH_USE_LINK_PATH FALSE)
set_property(TARGET accel-pptpd PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib/accel-pptp)

INSTALL(TARGETS accel-pptpd
	RUNTIME DESTINATION sbin
)

INSTALL(FILES accel-pptp.conf DESTINATION /etc RENAME accel-pptp.conf.dist)
INSTALL(FILES accel-pptp.conf.5 DESTINATION share/man/man5)

INSTALL(CODE "EXECUTE_PROCESS(COMMAND mkdir -p /var/log/accel-pptp)")
INSTALL(CODE "EXECUTE_PROCESS(COMMAND mkdir -p /var/run/accel-pptp)")
INSTALL(CODE "EXECUTE_PROCESS(COMMAND 'echo 0 > /var/run/accel-pptp/seq')")

