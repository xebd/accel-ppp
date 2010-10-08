ADD_LIBRARY(log_file SHARED log_file.c)
TARGET_LINK_LIBRARIES(log_file aio)

INSTALL(TARGETS log_file
	LIBRARY DESTINATION usr/lib/accel-pptp
)

IF(LOG_PGSQL)
	ADD_LIBRARY(log_pgsql SHARED log_pgsql.c)
	TARGET_LINK_LIBRARIES(log_pgsql pq)
	INSTALL(TARGETS log_pgsql
		LIBRARY DESTINATION usr/lib/accel-pptp
	)
ENDIF(LOG_PGSQL)

