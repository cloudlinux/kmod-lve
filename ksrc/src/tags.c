#include <linux/list.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/profile.h>

#include "lve_internal.h"
#include "lve_debug.h"
#include "lve_os_compat.h"
#include "tags.h"

static struct kmem_cache *switch_cache;

/*
 * allocate and attach tag to current process
 */
struct switch_data *
switch_tag_attach(struct task_struct *task)
{

	struct switch_data *ptr;

	if (!try_module_get(THIS_MODULE)) {
		return NULL;
	}

	ptr = lve_call(kmem_cache_alloc(switch_cache, GFP_KERNEL),
			LVE_FAIL_ALLOC_SWITCH, NULL);
	if (ptr == NULL) {
		module_put(THIS_MODULE);
		goto out;
	}
	memset(ptr, 0, sizeof(*ptr));
	ptr->sw_magic = SWITCH_MAGIC;
	ptr->sw_owner = THIS_MODULE;
	ptr->sw_task = task;
	atomic_set(&ptr->sw_refcnt, 1);
	LVE_TAG_SET(task, ptr);

	LVE_DBG("Tag alloc %p - %p\n", task, ptr);
out:
	return ptr;
}

void switch_free(struct switch_data *sw_data)
{
	BUG_ON(sw_data->sw_magic != SWITCH_MAGIC);

 	if (sw_data->sw_from) {
 		struct light_ve *lve = sw_data->sw_from;

		LVE_DBG("Tag free lve id=%d\n", lve->lve_id);
		if ((sw_data->sw_flags & LVE_ENTER_NO_MAXENTER) == 0) {
			spin_lock(&lve->lve_stats.enter_lock);
			--lve->lve_stats.st_enters;
			spin_unlock(&lve->lve_stats.enter_lock);
		}
		light_ve_put(lve);
	}

	module_put(sw_data->sw_owner);
	kmem_cache_free(switch_cache, sw_data);
}

void switch_tag_fork(struct task_struct * task)
{
	struct switch_data *sw_data;

	sw_data = LVE_TAG_GET(current);
	if (sw_data == NULL) {
		LVE_TAG_CLEAR(task);
		return;
	}

	LVE_TAG_SET(task, sw_data);
}

int switch_init(void)
{
	int ret = 0;

	switch_cache = lve_call(lve_kmem_cache_create("switch_data",
			sizeof(struct switch_data),	0, 0, NULL),
			LVE_FAIL_ALLOC_SWITCH_CACHE, NULL) ;
	if (switch_cache == NULL) {
		LVE_ERR("can't create switch_cache\n");
		ret = -ENOMEM;
	}

	return ret;
}

void switch_fini(void)
{
	if (lve_kmem_cache_destroy(switch_cache))
		LVE_ERR("MEMORY LEAK!\n");
}
