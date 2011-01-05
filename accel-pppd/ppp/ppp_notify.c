#include "ppp.h"

static LIST_HEAD(notified_list);

void __export ppp_register_notified(struct ppp_notified_t *n)
{
	list_add_tail(&n->entry, &notified_list);
}

void __export ppp_unregister_notified(struct ppp_notified_t *n)
{
	list_del(&n->entry);
}

void ppp_notify_starting(struct ppp_t *ppp)
{
	struct ppp_notified_t *n;

	list_for_each_entry(n, &notified_list, entry) {
		if (n->starting)
			n->starting(n, ppp);
	}
}

void ppp_notify_started(struct ppp_t *ppp)
{
	struct ppp_notified_t *n;

	list_for_each_entry(n, &notified_list, entry) {
		if (n->started)
			n->started(n, ppp);
	}
}

void ppp_notify_finished(struct ppp_t *ppp)
{
	struct ppp_notified_t *n;

	list_for_each_entry(n, &notified_list, entry) {
		if (n->finished)
			n->finished(n, ppp);
	}
}

void ppp_notify_finishing(struct ppp_t *ppp)
{
	struct ppp_notified_t *n;

	list_for_each_entry(n, &notified_list, entry) {
		if (n->finishing)
			n->finishing(n, ppp);
	}
}

