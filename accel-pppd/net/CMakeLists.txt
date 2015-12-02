IF (DEFINED DPDK)
    ADD_LIBRARY(net-dp SHARED dp.c)

    INSTALL(TARGETS net-dp
        LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
    )
ENDIF()
