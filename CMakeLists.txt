cmake_minimum_required(VERSION 2.6)
cmake_policy(SET CMP0005 NEW)
cmake_policy(SET CMP0003 OLD)

project(accel-ppp C)

include(cmake/cpack.cmake)

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
		set(crypto_lib tomcrypt)
	elseif (CRYPTO STREQUAL INTERNAL)
		INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/crypto)
		set(crypto_lib internal-crypto)
	else (CRYPTO STREQUAL OPENSSL)
		message(FATAL_ERROR "unknown CRYPTO type")
	endif (CRYPTO STREQUAL OPENSSL)
	
	add_subdirectory(accel-pppd)
	add_subdirectory(crypto)
endif (NOT BUILD_DRIVER_ONLY)

if (BUILD_DRIVER OR BUILD_DRIVER_ONLY)
	add_subdirectory(drivers/pptp)
endif (BUILD_DRIVER OR BUILD_DRIVER_ONLY)

if (BUILD_IPOE_DRIVER)
	add_subdirectory(drivers/ipoe)
endif (BUILD_IPOE_DRIVER)
