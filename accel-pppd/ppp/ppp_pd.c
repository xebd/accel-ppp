#include "ppp.h"

#include "memdebug.h"

int ppp_store_pd(struct ppp_t *ppp, pd_key_t key, void *data)
{
	struct ppp_pd_t *pd;

	list_for_each_entry(pd, &ppp->pd_list, entry)
		if (pd->key == key)
			return -1;


}
