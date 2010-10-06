PROJECT (accel-pptpd)
cmake_minimum_required(VERSION 2.6)

ADD_SUBDIRECTORY(accel-pptpd)

if (BUILD_DRIVER)
    ADD_SUBDIRECTORY(driver)
endif (BUILD_DRIVER)
