SET(target triton)
SET(sources_c 
	md.c
	conf_file.c
	timer.c
	options.c
	loader.c
)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_LIBRARY(${target} STATIC ${sources_c})
