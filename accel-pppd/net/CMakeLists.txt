IF (DEFINED DPDK)
    ADD_LIBRARY(net-accel-dp SHARED dp.c)

    INSTALL(TARGETS net-accel-dp
        LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
    )
ENDIF()
