SET(target radius)
SET(sources
	radius.c
	dict.c
	req.c
	packet.c
)

ADD_LIBRARY(radius SHARED ${sources})

