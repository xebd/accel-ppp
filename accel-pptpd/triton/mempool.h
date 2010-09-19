#ifndef __TRITON_MEMPOOL_H
#define __TRITON_MEMPOOL_H

#include <stdint.h>

struct mempool_stat_t
{
	uint32_t allocated;	
	uint32_t available;
};

typedef void * mempool_t;
mempool_t *mempool_create(int size);
void mempool_free(void*);
struct mempool_stat_t mempool_get_stat(void);

#ifdef MEMDEBUG
void *mempool_alloc_md(mempool_t*, const char *fname, int line);
#define mempool_alloc(pool) mempool_alloc_md(pool, __FILE__, __LINE__)
#else
void *mempool_alloc(mempool_t*);
#endif

#endif

