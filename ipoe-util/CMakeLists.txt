INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_HOME_DIRECTORY}/ipses)

if (LIBNL2)
	ADD_DEFINITIONS("-DLIBNL2")
endif (LIBNL2)

ADD_EXECUTABLE(ipses-create ipses-create.c)

ADD_EXECUTABLE(ipses-delete ipses-delete.c)

if (LIBNL2)
	TARGET_LINK_LIBRARIES(ipses-create nl nl-genl m)
	TARGET_LINK_LIBRARIES(ipses-delete nl nl-genl m)
else (LIBNL2)
	TARGET_LINK_LIBRARIES(ipses-create nl)
	TARGET_LINK_LIBRARIES(ipses-delete nl)
endif (LIBNL2)


