#include <unistd.h>

#include "triton.h"
#include "fdtrash.h"

static void fdtrash_close(struct triton_context_t *ctx)
{
	triton_context_unregister(ctx);
}

struct triton_context_t ctx = {
	.close = fdtrash_close,
};

static void __close(void *arg)
{
	close((long)arg);
}

void __export fdtrash_add(long fd)
{
	triton_context_call(&ctx, (triton_event_func)__close, (void *)fd);
}

static void init()
{
	triton_context_register(&ctx, NULL);
	triton_context_wakeup(&ctx);
}

DEFINE_INIT(10, init);
