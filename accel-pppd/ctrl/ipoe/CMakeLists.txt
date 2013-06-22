INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

SET(sources
	ipoe.c
	dhcpv4.c
	dhcpv4_options.c
	ipoe_netlink.c
	backup.c
	arp.c
)

IF (LUA)
	include(FindLua51)
	IF (NOT LUA51_FOUND)
		MESSAGE(FATAL_ERROR "lua not found")
	ENDIF (NOT LUA51_FOUND)
	INCLUDE_DIRECTORIES(${LUA_INCLUDE_DIR})
	ADD_DEFINITIONS(-DUSE_LUA)
	SET(sources ${sources} lua.c lua_lpack.c)
ENDIF (LUA)

ADD_LIBRARY(ipoe SHARED ${sources})
IF (LUA)
	TARGET_LINK_LIBRARIES(ipoe ${LUA_LIBRARIES})
ENDIF(LUA)

INSTALL(TARGETS ipoe LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp)
