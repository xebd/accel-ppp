INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

SET(sources
	pppoe.c
	mac_filter.c
	dpado.c
	cli.c
)

IF (RADIUS)
SET(sources ${sources} tr101.c)
ENDIF(RADIUS)

ADD_LIBRARY(pppoe SHARED ${sources})
TARGET_LINK_LIBRARIES(pppoe crypto)

INSTALL(TARGETS pppoe LIBRARY DESTINATION lib/accel-pptp)
