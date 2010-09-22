ADD_LIBRARY(log_file SHARED log_file2.c)
ADD_LIBRARY(log_pgsql SHARED log_pgsql.c)
TARGET_LINK_LIBRARIES(log_pgsql pq)

