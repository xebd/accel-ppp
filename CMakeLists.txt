cmake_minimum_required(VERSION 2.6)
cmake_policy(SET CMP0005 NEW)
cmake_policy(SET CMP0003 OLD)

PROJECT (accel-pptpd C)

include(cmake/cpack.cmake)

if (NOT BUILD_DRIVER_ONLY)
	ADD_SUBDIRECTORY(accel-pppd)
endif (NOT BUILD_DRIVER_ONLY)

if (BUILD_DRIVER OR BUILD_DRIVER_ONLY)
	ADD_SUBDIRECTORY(driver)
endif (BUILD_DRIVER OR BUILD_DRIVER_ONLY)

