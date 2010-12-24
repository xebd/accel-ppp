INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_LIBRARY(pppoe SHARED
	pppoe.c
	mac_filter.c
	dpado.c
	cli.c
)

TARGET_LINK_LIBRARIES(pppoe crypto)

INSTALL(TARGETS pppoe LIBRARY DESTINATION lib/accel-pptp)
