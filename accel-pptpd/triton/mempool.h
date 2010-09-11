#ifndef __TRITON_MEMPOOL_H
#define __TRITON_MEMPOOL_H

typedef void * mempool_t;
mempool_t *mempool_create(int size);
void *mempool_alloc(mempool_t*);
void mempool_free(void*);

#endif

