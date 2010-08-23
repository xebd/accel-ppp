PROJECT (pptpd)
cmake_minimum_required(VERSION 2.6)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

ADD_SUBDIRECTORY(triton)

ADD_EXECUTABLE(pptpd
	pptpd.c
	pptp.c
	log.c
	ppp.c
	ppp_fsm.c
	
	ppp_lcp.c
	lcp_opt_mru.c
	lcp_opt_magic.c
	lcp_opt_pcomp.c
	lcp_opt_accomp.c
	
	ppp_auth.c
	auth_pap.c
	
	ppp_ccp.c
	ppp_ipcp.c
	ipcp_opt_ipaddr.c
	ipcp_opt_dns.c
	
	pwdb.c
	ipdb.c
)
TARGET_LINK_LIBRARIES(pptpd pthread triton)
