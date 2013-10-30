SET(sources
	agent.c
	sessionTable.c
	sessionTable_data_access.c
	sessionTable_data_get.c
	sessionTable_data_set.c
	sessionTable_interface.c
	statCore.c
	statL2TP.c
	statPPP.c
	statPPPOE.c
	statPPTP.c
	statIPOE.c
	terminate.c
	shutdown.c
	exec_cli.c
)

ADD_LIBRARY(net-snmp SHARED ${sources})
TARGET_LINK_LIBRARIES(net-snmp netsnmpagent netsnmphelpers netsnmpmibs
netsnmp)

IF (NETSNMP_PREFIX)
	SET_PROPERTY(TARGET net-snmp PROPERTY COMPILE_FLAGS "-I${NETSNMP_PREFIX}/include")
	SET_PROPERTY(TARGET net-snmp PROPERTY LINK_FLAGS "-L${NETSNMP_PREFIX}/lib")
ENDIF (NETSNMP_PREFIX)

INSTALL(TARGETS net-snmp
	LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
)
