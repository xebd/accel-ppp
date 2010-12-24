ADD_LIBRARY(log_file SHARED log_file.c)
TARGET_LINK_LIBRARIES(log_file rt)

ADD_LIBRARY(log_tcp SHARED log_tcp.c)

INSTALL(TARGETS log_file log_tcp
	LIBRARY DESTINATION lib/accel-pptp
)

IF(LOG_PGSQL)
	ADD_LIBRARY(log_pgsql SHARED log_pgsql.c)
	TARGET_LINK_LIBRARIES(log_pgsql pq)
	INSTALL(TARGETS log_pgsql
		LIBRARY DESTINATION lib/accel-pptp
	)
ENDIF(LOG_PGSQL)

