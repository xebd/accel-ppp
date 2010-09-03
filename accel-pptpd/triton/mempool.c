#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "triton_p.h"

struct _mempool_t
{
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

mempool_t *mempool_create(int size)
{
	struct _mempool_t *p = malloc(sizeof(*p));

	memset(p, 0, sizeof(*p));
	INIT_LIST_HEAD(&p->items);
	spinlock_init(&p->lock);
	p->size = size;
	p->magic = (uint64_t)random() * (uint64_t)random();

	return (mempool_t *)p;
}

void *mempool_alloc(mempool_t *pool)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;

	spin_lock(&p->lock);
	if (!list_empty(&p->items)) {
		it = list_entry(p->items.next, typeof(*it), entry);
		list_del(&it->entry);
		spin_unlock(&p->lock);
		return it->ptr;
	}
	spin_unlock(&p->lock);
	it = malloc(sizeof(*it) + p->size);
	it->owner = p;
	it->magic = p->magic;
	return it->ptr;
}

void mempool_free(void *ptr)
{
	struct _item_t *it = container_of(ptr, typeof(*it), ptr);

	if (it->magic != it->owner->magic) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}
	spin_lock(&it->owner->lock);
	list_add_tail(&it->entry,&it->owner->items);
	spin_unlock(&it->owner->lock);
}

