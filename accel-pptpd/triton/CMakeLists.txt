SET(sources_c 
	md.c
	timer.c
	triton.c
	conf_file.c
	loader.c
	log.c
	mempool.c
	event.c
)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_DEFINITIONS(-DMODULE_PATH="${CMAKE_INSTALL_PREFIX}/usr/lib/accel-pptp")

ADD_LIBRARY(triton SHARED ${sources_c})
TARGET_LINK_LIBRARIES(triton dl)

INSTALL(TARGETS triton
	LIBRARY DESTINATION usr/lib/accel-pptp
)
