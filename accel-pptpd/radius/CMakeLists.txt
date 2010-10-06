SET(sources
	radius.c
	dict.c
	req.c
	packet.c
	auth.c
	acct.c
	dm_coa.c
)

ADD_DEFINITIONS(-DDICT_PATH="${CMAKE_INSTALL_PREFIX}/usr/share/accel-pptp/dictionary")

ADD_LIBRARY(radius SHARED ${sources})

INSTALL(TARGETS radius
	LIBRARY DESTINATION usr/lib/accel-pptp
)
FILE(GLOB dict "${CMAKE_CURRENT_SOURCE_DIR}/dict/*")
INSTALL(FILES ${dict} DESTINATION usr/share/accel-pptp)

