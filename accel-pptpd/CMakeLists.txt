PROJECT (pptpd)
cmake_minimum_required(VERSION 2.6)

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
	ippool.c

	utils.c
	sigchld.c

	log.c
	main.c
	memdebug.c
)
TARGET_LINK_LIBRARIES(accel-pptpd triton rt pthread ssl)

