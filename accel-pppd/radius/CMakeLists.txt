SET(sources
	stat_accm.c
	dict.c
	req.c
	packet.c
	auth.c
	acct.c
	serv.c
	dm_coa.c
	radius.c
)

IF (BACKUP)
	SET(sources ${sources} backup.c)
ENDIF (BACKUP)

ADD_DEFINITIONS(-DDICTIONARY="${CMAKE_INSTALL_PREFIX}/share/accel-ppp/radius/dictionary")

ADD_LIBRARY(radius SHARED ${sources})

INSTALL(TARGETS radius
	LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
)
FILE(GLOB dict "${CMAKE_CURRENT_SOURCE_DIR}/dict/*")
INSTALL(FILES ${dict} DESTINATION share/accel-ppp/radius)
