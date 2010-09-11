PROJECT (pptpd)
cmake_minimum_required(VERSION 2.6)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fvisibility=hidden -D_GNU_SOURCE -DSPINLOCK_GCC")

INCLUDE_DIRECTORIES(include)

ADD_SUBDIRECTORY(triton)
ADD_SUBDIRECTORY(ctrl)
ADD_SUBDIRECTORY(auth)
ADD_SUBDIRECTORY(radius)
ADD_SUBDIRECTORY(logs)

ADD_EXECUTABLE(pptpd
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

	pwdb.c
	ipdb.c

	iprange.c
	ippool.c
	
	log.c
	main.c
)
TARGET_LINK_LIBRARIES(pptpd triton rt pthread ssl)

