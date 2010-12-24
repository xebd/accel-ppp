INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_DEFINITIONS(-DDICTIONARY="${CMAKE_INSTALL_PREFIX}/usr/share/accel-pptp/l2tp/dictionary")

ADD_LIBRARY(l2tp SHARED
	l2tp.c
	dict.c
	packet.c
	#	netlink.c
)
#TARGET_LINK_LIBRARIES(l2tp nl nl-genl)

INSTALL(TARGETS l2tp LIBRARY DESTINATION lib/accel-pptp)

FILE(GLOB dict "${CMAKE_CURRENT_SOURCE_DIR}/dict/*")
INSTALL(FILES ${dict} DESTINATION share/accel-pptp/l2tp)

