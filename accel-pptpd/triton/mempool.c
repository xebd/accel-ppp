#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "triton_p.h"

#include "memdebug.h"

#define MAGIC1 0x2233445566778899llu

struct _mempool_t
{
	struct list_head entry;
	int size;
	struct list_head items;
#ifdef MEMDEBUG
	struct list_head ditems;
#endif
	spinlock_t lock;
	uint64_t magic;
};

struct _item_t
{
	struct _mempool_t *owner;
	struct list_head entry;
#ifdef MEMDEBUG
	const char *fname;
	int line;
#endif
	uint64_t magic2;
	uint64_t magic1;
	char ptr[0];
};

static LIST_HEAD(pools);
static spinlock_t pools_lock = SPINLOCK_INITIALIZER;

mempool_t __export *mempool_create(int size)
{
	struct _mempool_t *p = _malloc(sizeof(*p));

	memset(p, 0, sizeof(*p));
	INIT_LIST_HEAD(&p->items);
#ifdef MEMDEBUG
	INIT_LIST_HEAD(&p->ditems);
#endif
	spinlock_init(&p->lock);
	p->size = size;
	p->magic = (uint64_t)random() * (uint64_t)random();

	spin_lock(&pools_lock);
	list_add_tail(&p->entry, &pools);
	spin_unlock(&pools_lock);

	return (mempool_t *)p;
}

#ifndef MEMDEBUG
void __export *mempool_alloc(mempool_t *pool)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;
	uint32_t size = sizeof(*it) + p->size + 8;

	spin_lock(&p->lock);
	if (!list_empty(&p->items)) {
		it = list_entry(p->items.next, typeof(*it), entry);
		list_del(&it->entry);
		spin_unlock(&p->lock);
		
		__sync_fetch_and_sub(&triton_stat.mempool_available, size);
		
		it->magic1 = MAGIC1;

		return it->ptr;
	}
	spin_unlock(&p->lock);

	it = _malloc(size);
	if (!it) {
		triton_log_error("mempool: out of memory\n");
		return NULL;
	}
	it->owner = p;
	it->magic1 = MAGIC1;
	it->magic2 = p->magic;
	*(uint64_t*)(it->data + p->size) = it->magic2;

	__sync_fetch_and_add(&triton_stat.mempool_allocated, size);

	return it->ptr;
}
#endif

void __export *mempool_alloc_md(mempool_t *pool, const char *fname, int line)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;
	uint32_t size = sizeof(*it) + p->size + 8;

	spin_lock(&p->lock);
	if (!list_empty(&p->items)) {
		it = list_entry(p->items.next, typeof(*it), entry);
		list_del(&it->entry);
		list_add(&it->entry, &p->ditems);
		spin_unlock(&p->lock);

		it->fname = fname;
		it->line = line;
		
		__sync_fetch_and_sub(&triton_stat.mempool_available, size);
		
		it->magic1 = MAGIC1;

		return it->ptr;
	}
	spin_unlock(&p->lock);

	it = md_malloc(size, fname, line);
	if (!it) {
		triton_log_error("mempool: out of memory\n");
		return NULL;
	}
	it->owner = p;
	it->magic2 = p->magic;
	it->magic1 = MAGIC1;
	it->fname = fname;
	it->line = line;
	*(uint64_t*)(it->ptr + p->size) = it->magic2;

	spin_lock(&p->lock);
	list_add(&it->entry, &p->ditems);
	spin_unlock(&p->lock);

	__sync_fetch_and_add(&triton_stat.mempool_allocated, size);

	return it->ptr;
}


void __export mempool_free(void *ptr)
{
	struct _item_t *it = container_of(ptr, typeof(*it), ptr);
	uint32_t size = sizeof(*it) + it->owner->size + 8;

#ifdef MEMDEBUG
	if (it->magic1 != MAGIC1) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}

	if (it->magic2 != it->owner->magic) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}

	if (it->magic2 != *(uint64_t*)(it->ptr + it->owner->size)) {
		triton_log_error("mempool: memory corruption detected");
		abort();
	}

	it->magic1 = 0;
#endif

	spin_lock(&it->owner->lock);
#ifdef MEMDEBUG
	list_del(&it->entry);
#endif
	list_add_tail(&it->entry,&it->owner->items);
	spin_unlock(&it->owner->lock);

	__sync_fetch_and_add(&triton_stat.mempool_available, size);
}

void __export mempool_clean(mempool_t *pool)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;
	uint32_t size = sizeof(*it) + p->size + 8;

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

#ifdef MEMDEBUG
void __export mempool_show(mempool_t *pool)
{
	struct _mempool_t *p = (struct _mempool_t *)pool;
	struct _item_t *it;

	spin_lock(&p->lock);
	list_for_each_entry(it, &p->ditems, entry)
		triton_log_error("%s:%i %p\n", it->fname, it->line, it->ptr);
	spin_unlock(&p->lock);
}
#endif

void sigclean(int num)
{
	struct _mempool_t *p;
	struct _item_t *it;
	uint32_t size;

	triton_log_error("mempool: clean\n");

	spin_lock(&pools_lock);
	list_for_each_entry(p, &pools, entry) {
		size = sizeof(*it) + p->size + 8;
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

