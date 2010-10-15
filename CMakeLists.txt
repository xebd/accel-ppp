PROJECT (accel-pptpd C)
cmake_minimum_required(VERSION 2.6)

include(cmake/cpack.cmake)

if (NOT BUILD_DRIVER_ONLY)
	ADD_SUBDIRECTORY(accel-pptpd)
endif (NOT BUILD_DRIVER_ONLY)

if (BUILD_DRIVER OR BUILD_DRIVER_ONLY)
	ADD_SUBDIRECTORY(driver)
endif (BUILD_DRIVER OR BUILD_DRIVER_ONLY)

