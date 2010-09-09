SET(target radius)
SET(sources
	radius.c
	dict.c
	req.c
	packet.c
	auth.c
	acct.c
	dm_coa.c
)

ADD_LIBRARY(radius SHARED ${sources})

