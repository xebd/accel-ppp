INCLUDE(InstallRequiredSystemLibraries)

string(REPLACE "." ";" VERSION_LIST ${ACCEL_PPP_VERSION})
list(GET VERSION_LIST 0 CPACK_PACKAGE_VERSION_MAJOR)
list(GET VERSION_LIST 1 CPACK_PACKAGE_VERSION_MINOR)
list(GET VERSION_LIST 2 CPACK_PACKAGE_VERSION_PATCH)

SET(CPACK_PACKAGE_NAME "accel-ppp")
SET(CPACK_PACKAGE_CONTACT "Dmitry Kozlov <xeb@mail.ru>")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "PPtP/L2TP/PPPoE/SSTP server for Linux")

SET(CPACK_PACKAGE_VENDOR "Dmitry Kozlov")
SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")

IF(CPACK_TYPE STREQUAL Debian5)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.7), libssl0.9.8 (>= 0.9.8), libpcre3 (>= 7.6)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Debian5)

IF(CPACK_TYPE STREQUAL Debian6)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.11.2), libssl0.9.8 (>= 0.9.8), libpcre3 (>= 8.02)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Debian6)

IF(CPACK_TYPE STREQUAL Debian7)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.13), libssl1.0.0 (>= 1.0.0), libpcre3 (>= 8.30)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Debian7)

IF(CPACK_TYPE STREQUAL Debian8)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.19), libssl1.0.0 (>= 1.0.1k), libpcre3 (>= 8.35)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Debian8)

IF(CPACK_TYPE STREQUAL Debian9)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.24), libssl1.0.2 (>= 1.0.2l), libpcre3 (>= 8.39)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Debian9)

IF(CPACK_TYPE STREQUAL Debian10)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.28), libssl1.1 (>= 1.1.1c), libpcre3 (>= 8.39)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Debian10)

IF(CPACK_TYPE STREQUAL Ubuntu16)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.23), libssl1.0.0 (>= 1.0.0), libpcre3 (>= 8.39)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Ubuntu16)

IF(CPACK_TYPE STREQUAL Ubuntu18)
	SET(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.24), libssl1.0.0 (>= 1.0.2n), libpcre3 (>= 8.39)")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/debian/debian.cmake)
ENDIF(CPACK_TYPE STREQUAL Ubuntu18)

IF(CPACK_TYPE STREQUAL Centos7)
	SET(CPACK_RPM_PACKAGE_LICENSE "GPL")
	SET(CPACK_RPM_PACKAGE_URL "http://accel-ppp.org")
	SET(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/sbin")
	SET(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.17, openssl-libs >= 1.0.2k, pcre >= 8.32")
	INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/centos/centos.cmake)
ENDIF()

IF(CPACK_TYPE STREQUAL Centos8)
        SET(CPACK_RPM_PACKAGE_LICENSE "GPL")
        SET(CPACK_RPM_PACKAGE_URL "http://accel-ppp.org")
        SET(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/sbin")
        SET(CPACK_RPM_PACKAGE_REQUIRES "glibc >= 2.28, openssl-libs >= 1.1.1, pcre >= 8.42")
        INCLUDE(${CMAKE_HOME_DIRECTORY}/cmake/centos/centos.cmake)
ENDIF()

INCLUDE(CPack)
