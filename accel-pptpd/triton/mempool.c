#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "triton_p.h"

#include "memdebug.h"

struct _mempool_t
{
	struct list_head entry;
	int size;
	struct list_head items;
	spinlock_t lock;
	uint64_t magic;
};

struct _item_t
{
	struct _mempool_t *owner;
	struct list_head entry;
	uint64_t magic;
	char ptr[0];
};

static LIST_HEAD(pools);
static spinlock_t pools_lock = SPINLOCK_INITIALIZER;

__export mempool_t *mempool_create(int size)
{
	struct _mempool_t *p = _malloc(sizeof(*p));

	memset(p, 0, sizeof(*p));
	INIT_LIST_HEAD(&p->items);
	spinlock_init(&p->lock);
	p->size = size;
	p->magic = (uint64_t)random() * (uint64_t)random();

	spin_lock(&pools_lock);
	list_add_tail(&p->entry, &pools);
	spin_unlock(&pools_lock);

	return (mempool_t *)p;
}

#ifndef MEMDEBUG
__export void *mempool_alloc(mempool_t *pool)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;
	uint32_t size = sizeof(*it) + p->size;

	spin_lock(&p->lock);
	if (!list_empty(&p->items)) {
		it = list_entry(p->items.next, typeof(*it), entry);
		list_del(&it->entry);
		spin_unlock(&p->lock);
		
		__sync_fetch_and_sub(&triton_stat.mempool_available, size);
		
		return it->ptr;
	}
	spin_unlock(&p->lock);

	it = _malloc(size);
	if (!it) {
		triton_log_error("mempool: out of memory\n");
		return NULL;
	}
	it->owner = p;
	it->magic = p->magic;

	__sync_fetch_and_add(&triton_stat.mempool_allocated, size);

	return it->ptr;
}
#endif

void __export *mempool_alloc_md(mempool_t *pool, const char *fname, int line)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;
	uint32_t size = sizeof(*it) + p->size;

	spin_lock(&p->lock);
	if (!list_empty(&p->items)) {
		it = list_entry(p->items.next, typeof(*it), entry);
		list_del(&it->entry);
		spin_unlock(&p->lock);
		
		__sync_fetch_and_sub(&triton_stat.mempool_available, size);
		
		return it->ptr;
	}
	spin_unlock(&p->lock);

	it = md_malloc(size, fname, line);
	if (!it) {
		triton_log_error("mempool: out of memory\n");
		return NULL;
	}
	it->owner = p;
	it->magic = p->magic;

	__sync_fetch_and_add(&triton_stat.mempool_allocated, size);

	return it->ptr;
}


__export void mempool_free(void *ptr)
{
	struct _item_t *it = container_of(ptr, typeof(*it), ptr);
	uint32_t size = sizeof(*it) + it->owner->size;

	if (it->magic != it->owner->magic) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}
	spin_lock(&it->owner->lock);
	list_add_tail(&it->entry,&it->owner->items);
	spin_unlock(&it->owner->lock);

	__sync_fetch_and_add(&triton_stat.mempool_available, size);
}

void sigclean(int num)
{
	struct _mempool_t *p;
	struct _item_t *it;
	uint32_t size;

	triton_log_error("mempool: clean\n");

	spin_lock(&pools_lock);
	list_for_each_entry(p, &pools, entry) {
		size = sizeof(*it) + p->size;
		spin_lock(&p->lock);
		while (!list_empty(&p->items)) {
			it = list_entry(p->items.next, typeof(*it), entry);
			list_del(&it->entry);
			_free(it);
			__sync_fetch_and_sub(&triton_stat.mempool_allocated, size);
			__sync_fetch_and_sub(&triton_stat.mempool_available, size);
		}
		spin_unlock(&p->lock);
	}
	spin_unlock(&pools_lock);
}

static void __init init(void)
{
	signal(35, sigclean);
}

