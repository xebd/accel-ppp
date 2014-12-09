cmake_minimum_required(VERSION 2.6)
cmake_policy(SET CMP0005 NEW)
cmake_policy(SET CMP0003 OLD)

project(accel-ppp C)

include(cmake/cpack.cmake)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fno-strict-aliasing -D_GNU_SOURCE -fPIC -rdynamic")

IF (NOT DEFINED LIB_SUFFIX)
	EXECUTE_PROCESS(
		COMMAND uname -m
		COMMAND tr -d '\n'
		OUTPUT_VARIABLE ARCH
	)
	message(STATUS "'"  ${ARCH}  "'")
	IF (ARCH STREQUAL x86_64)
		SET(LIB_SUFFIX 64)
	ENDIF (ARCH STREQUAL x86_64)
ENDIF (NOT DEFINED LIB_SUFFIX)

IF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT IGNORE_GIT)
	EXECUTE_PROCESS(
		COMMAND git log --no-color
		COMMAND head -n1
		COMMAND awk "{print $2}"
		WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}
		OUTPUT_VARIABLE ACCEL_PPP_VERSION
	)
	STRING(STRIP ${ACCEL_PPP_VERSION} ACCEL_PPP_VERSION)
ELSE (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT IGNORE_GIT)
	SET (ACCEL_PPP_VERSION 1.9.0)
ENDIF (EXISTS ${CMAKE_HOME_DIRECTORY}/.git AND NOT IGNORE_GIT)

ADD_DEFINITIONS(-DACCEL_PPP_VERSION="${ACCEL_PPP_VERSION}")
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

if (NOT BUILD_DRIVER_ONLY)
	if (MEMDEBUG)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector -fstack-protector-all")
	endif (MEMDEBUG)

	if (NOT DEFINED CRYPTO)
		set(CRYPTO OPENSSL)
	endif (NOT DEFINED CRYPTO)

	if (CRYPTO STREQUAL OPENSSL)
		add_definitions(-DCRYPTO_OPENSSL)
		set(crypto_lib crypto ssl)
	elseif (CRYPTO STREQUAL TOMCRYPT)
		add_definitions(-DCRYPTO_TOMCRYPT)
		INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/crypto)
		set(crypto_lib tomcrypt internal-crypto)
	elseif (CRYPTO STREQUAL INTERNAL)
		INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/crypto)
		set(crypto_lib internal-crypto)
	else (CRYPTO STREQUAL OPENSSL)
		message(FATAL_ERROR "unknown CRYPTO type")
	endif (CRYPTO STREQUAL OPENSSL)
	
	add_subdirectory(accel-pppd)
	add_subdirectory(crypto)
	add_subdirectory(accel-cmd)
endif (NOT BUILD_DRIVER_ONLY)

if (BUILD_PPTP_DRIVER)
	add_subdirectory(drivers/pptp)
endif (BUILD_PPTP_DRIVER)

if (BUILD_IPOE_DRIVER)
	add_subdirectory(drivers/ipoe)
endif (BUILD_IPOE_DRIVER)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
