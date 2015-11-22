IF (DEFINED DPDK)
    ADD_LIBRARY(net-dpdk SHARED dpdk.c)

    INSTALL(TARGETS net-dpdk
        LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
    )
ENDIF()
