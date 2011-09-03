IF (CRYPTO STREQUAL INTERNAL)

	SET(sources
		crypto.c
		md4.c
		md5.c
		sha1.c
		des.c
	)

	ADD_LIBRARY(internal-crypto SHARED ${sources})

	INSTALL(TARGETS internal-crypto
		LIBRARY DESTINATION lib/accel-ppp
	)

ENDIF (CRYPTO STREQUAL INTERNAL)
