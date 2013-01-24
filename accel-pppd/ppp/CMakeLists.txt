SET(target ppp)
SET(sources_c 
	ppp.c
	ppp_fsm.c
	ppp_lcp.c
	lcp_opt_mru.c
	lcp_opt_magic.c
	lcp_opt_pcomp.c
	lcp_opt_accomp.c
	ppp_auth.c
	ppp_ipcp.c
	ipcp_opt_ipaddr.c
	ipcp_opt_dns.c
	ipcp_opt_wins.c
	ppp_ccp.c	
)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_LIBRARY(${target} SHARED ${sources_c})

