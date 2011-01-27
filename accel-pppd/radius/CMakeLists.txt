SET(sources
	stat_accm.c
	dict.c
	req.c
	packet.c
	auth.c
	acct.c
	dm_coa.c
	radius.c
)

ADD_DEFINITIONS(-DDICTIONARY="${CMAKE_INSTALL_PREFIX}/share/accel-ppp/radius/dictionary")

ADD_LIBRARY(radius SHARED ${sources})

INSTALL(TARGETS radius
	LIBRARY DESTINATION lib/accel-ppp
)
FILE(GLOB dict "${CMAKE_CURRENT_SOURCE_DIR}/dict/*")
INSTALL(FILES ${dict} DESTINATION share/accel-ppp/radius)
