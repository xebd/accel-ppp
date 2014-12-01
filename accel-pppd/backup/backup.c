#include <stdlib.h>
#include <string.h>

#include "triton.h"
#include "log.h"
#include "events.h"
#include "ap_session.h"
#include "backup.h"

#ifdef USE_BACKUP

static LIST_HEAD(storage_list);
static LIST_HEAD(module_list);

struct backup_tag __export *backup_add_tag(struct backup_mod *m, uint8_t id, int internal, const void *data, size_t size)
{
	struct backup_tag *t;

	t = m->data->storage->alloc_tag(m->data, size);
	if (!t)
		return NULL;

	t->id = id;
	t->internal = internal;
	t->size = size;
	memcpy(t->data, data, size);

	list_add_tail(&t->entry, &m->tag_list);

	return t;
}

void backup_add_fd(struct backup_mod *m, int fd)
{
	if (m->data->storage->add_fd)
		m->data->storage->add_fd(m->data, fd);
}

struct backup_mod __export *backup_find_mod(struct backup_data *d, uint8_t mod_id)
{
	struct backup_mod *m;

	list_for_each_entry(m, &d->mod_list, entry) {
		if (m->id == mod_id)
			return m;
	}

	return NULL;
}

struct backup_tag __export *backup_find_tag(struct backup_data *d, uint8_t mod_id, uint8_t tag_id, int internal)
{
	struct backup_mod *m = backup_find_mod(d, mod_id);
	struct backup_tag *t;

	if (!m)
		return NULL;

	list_for_each_entry(t, &m->tag_list, entry) {
		if (t->id == tag_id && t->internal == internal)
			return t;
	}

	return NULL;
}

void __export backup_free(struct backup_data *data)
{
	struct backup_mod *m;
	struct backup_tag *t;

	while (!list_empty(&data->mod_list)) {
		m = list_entry(data->mod_list.next, typeof(*m), entry);
		while (!list_empty(&m->tag_list)) {
			t = list_entry(m->tag_list.next, typeof(*t), entry);
			list_del(&t->entry);
			data->storage->free_tag(data, t);
		}
		list_del(&m->entry);
		data->storage->free_mod(m);
	}
	data->storage->free(data);
}

int __export backup_save_session(struct ap_session *ses)
{
	struct backup_storage *storage;
	struct backup_module *module;
	struct backup_data *d;
	struct backup_mod *m;
	int r, f1 = 0, f2;

	list_for_each_entry(storage, &storage_list, entry) {
		d = storage->create(ses);
		if (!d)
			continue;

		//d->ses = ses;

		f2 = 0;

		list_for_each_entry(module, &module_list, entry) {
			if (!module->save)
				continue;

			m = storage->alloc_mod(d);
			if (!m) {
				f2 = 1;
				break;
			}

			m->data = d;
			m->id = module->id;
			r = module->save(ses, m);
			if (r == -2) {
				storage->free_mod(m);
				continue;
			}

			list_add_tail(&m->entry, &d->mod_list);

			if (r == -1) {
				f2 = 1;
				break;
			}
		}

		if (f2)
			backup_free(d);
		else {
			f1 = 1;
			if (storage->commit)
				storage->commit(d);
			ses->backup = d;
		}
	}

	return !f1;
}

/*int backup_restore_internal(void)
{
	struct backup_storage *storage;

	list_for_each_entry(storage, &storage_list, entry) {
		if (storage->restore_internal) {
			if (storage->check_integrity())
				continue;
			storage->restore_internal();
			return 0;
		}
	}

	return -1;
}

void backup_restore_external(void)
{
	struct backup_storage *storage;

	list_for_each_entry(storage, &storage_list, entry) {
		if (storage->restore_external) {
			if (storage->check_integrity())
				continue;
			storage->restore_external();
			return;
		}
	}
}*/

static void __restore_session(struct ap_session *ses)
{
	struct backup_module *module;
	struct backup_mod *m;
	struct backup_module *ctrl = NULL;

	list_for_each_entry(module, &module_list, entry) {
		if (module->ctrl_start)
			ctrl = module;
		if (module->restore) {
			m = backup_find_mod(ses->backup, module->id);
			if (!m)
				continue;
			module->restore(ses, m);
		}
	}

	log_ppp_info1("session restored\n");

	if (ctrl)
		ctrl->ctrl_start(ses);
	else {
		triton_event_fire(EV_CTRL_STARTING, ses);
		triton_event_fire(EV_CTRL_STARTED, ses);

		ap_session_starting(ses);
		ap_session_activate(ses);
	}
}

void __export backup_restore_session(struct backup_data *d)
{
	struct backup_module *module;
	struct backup_mod *m;
	struct ap_session *ses;

	list_for_each_entry(module, &module_list, entry) {
		if (module->ctrl_restore) {
			m = backup_find_mod(d, module->id);
			if (!m)
				continue;
			ses = module->ctrl_restore(m);
			ses->backup = d;
			d->ses = ses;
			ses->state = AP_STATE_RESTORE;
			triton_context_call(ses->ctrl->ctx, (triton_event_func)__restore_session, ses);
			break;
		}
	}
}


void __export backup_register_module(struct backup_module *m)
{
	list_add_tail(&m->entry, &module_list);
}

void __export backup_register_storage(struct backup_storage *s)
{
	list_add_tail(&s->entry, &storage_list);
}

void backup_restore_fd()
{

}

void backup_restore(int internal)
{
	struct backup_storage *storage;
	struct backup_module *module;

	list_for_each_entry(storage, &storage_list, entry) {
		if (storage->restore)
			storage->restore(internal);
	}

	list_for_each_entry(module, &module_list, entry) {
		if (module->restore_complete)
			module->restore_complete();
	}
}

#endif
