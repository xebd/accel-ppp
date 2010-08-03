PROJECT (pptpd)
cmake_minimum_required(VERSION 2.6)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

ADD_SUBDIRECTORY(triton)

ADD_EXECUTABLE(pptpd
	pptpd.c
	ctrl.c
	log.c
	ppp.c
	ppp_fsm.c
	ppp_lcp.c
)
TARGET_LINK_LIBRARIES(pptpd pthread triton)