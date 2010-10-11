SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fvisibility=hidden -D_GNU_SOURCE -DGCC_SPINLOCK -DMEMDEBUG")

INCLUDE_DIRECTORIES(include)

ADD_SUBDIRECTORY(triton)
ADD_SUBDIRECTORY(ctrl)
ADD_SUBDIRECTORY(auth)
ADD_SUBDIRECTORY(radius)
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

	pwdb.c
	ipdb.c

	iprange.c

	utils.c

	log.c
	main.c
	memdebug.c
)

TARGET_LINK_LIBRARIES(accel-pptpd triton rt pthread ssl crypto)
set_property(TARGET accel-pptpd PROPERTY CMAKE_SKIP_BUILD_RPATH FALSE)
set_property(TARGET accel-pptpd PROPERTY CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set_property(TARGET accel-pptpd PROPERTY INSTALL_RPATH_USE_LINK_PATH FALSE)
set_property(TARGET accel-pptpd PROPERTY INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/usr/lib/accel-pptp)

INSTALL(TARGETS accel-pptpd
	RUNTIME DESTINATION usr/sbin
)

INSTALL(FILES accel-pptp.conf DESTINATION /etc)
INSTALL(FILES accel-pptp.conf.5 DESTINATION usr/share/man/man5)

INSTALL(CODE "EXECUTE_PROCESS(COMMAND mkdir -p /var/log/accel-pptp)")

