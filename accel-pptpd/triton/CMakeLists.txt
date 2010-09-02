SET(target triton)
SET(sources_c 
	md.c
	timer.c
	triton.c
	conf_file.c
	loader.c
	log.c
)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
ADD_DEFINITIONS("-DUSE_SPINLOCK")

ADD_LIBRARY(${target} SHARED ${sources_c})

