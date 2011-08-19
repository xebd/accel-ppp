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
	terminate.c
	shutdown.c
)

ADD_LIBRARY(net-snmp SHARED ${sources})
TARGET_LINK_LIBRARIES(net-snmp netsnmpagent netsnmphelpers netsnmpmibs
netsnmp)

INSTALL(TARGETS net-snmp
	LIBRARY DESTINATION lib/accel-ppp
)
