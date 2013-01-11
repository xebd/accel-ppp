SET(sources_c 
	md.c
	timer.c
	triton.c
	conf_file.c
	loader.c
	log.c
	mempool.c
	event.c
)

INCLUDE(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(timerfd_create HAVE_TIMERFD)

IF (HAVE_TIMERFD)
	ADD_DEFINITIONS(-DHAVE_TIMERFD)
ELSE (HAVE_TIMERFD)
	INCLUDE (CheckCSourceCompiles)
	CHECK_C_SOURCE_COMPILES("
	#include <sys/syscall.h>
	int main()
	{
		syscall(SYS_timerfd_create);
	}" HAVE_SYSCALL)
	IF (NOT HAVE_SYSCALL)
		MESSAGE(FATAL_ERROR "Your system is too old and is not supported by accel-ppp, sorry...")
	ENDIF (NOT HAVE_SYSCALL)
	SET(sources_c ${sources_c} timerfd.c)
ENDIF (HAVE_TIMERFD)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

ADD_DEFINITIONS(-DMODULE_PATH="${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}/accel-ppp")

ADD_LIBRARY(triton SHARED ${sources_c})
TARGET_LINK_LIBRARIES(triton dl)

INSTALL(TARGETS triton
	LIBRARY DESTINATION lib${LIB_SUFFIX}/accel-ppp
)
