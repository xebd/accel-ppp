SET(target radius)
SET(sources
	radius.c
	dict.c
)

ADD_LIBRARY(radius SHARED ${sources})

