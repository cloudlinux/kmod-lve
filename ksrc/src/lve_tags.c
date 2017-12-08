#include <linux/list.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/profile.h>
#include <linux/kthread.h>

#include "lve_internal.h"
#include "lve_debug.h"
#include "resource.h"
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

void switch_tag_account(struct switch_data *sw_data, struct light_ve *ve)
{
	BUG_ON(ve == NULL);
	sw_data->sw_from = ve;
	atomic_inc(&ve->lve_tags);
}

void switch_tag_release(const struct switch_data *sw_data)
{
	struct light_ve *ve = sw_data->sw_from;

	BUG_ON(ve == NULL);
	if (!atomic_dec_return(&ve->lve_tags))
		wake_up(&ve->lve_tags_wq);
}

void switch_free(struct switch_data *sw_data)
{
	BUG_ON(sw_data->sw_magic != SWITCH_MAGIC);

 	if (sw_data->sw_from) {
 		struct light_ve *lve = sw_data->sw_from;

		LVE_DBG("Tag free lve id=%d\n", lve->lve_id);
		if ((sw_data->sw_flags & LVE_ENTER_NO_MAXENTER) == 0)
			lve_ep_uncharge(lve);
		light_ve_put(lve);
		/* under this implementation the
		 * light_ve_put call above is never final */
		switch_tag_release(sw_data);
	}

	lve_namespace_free(&sw_data->sw_ns);

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

static struct task_struct *tag_list_thread;
static spinlock_t tag_release_lock;
static LIST_HEAD(tag_release_list);
static DECLARE_WAIT_QUEUE_HEAD(tag_release_wait);

void tag_free_delayed(struct switch_data *sw_data)
{
	spin_lock(&tag_release_lock);
	list_add_tail(&sw_data->sw_list, &tag_release_list);
	spin_unlock(&tag_release_lock);

	wake_up(&tag_release_wait);
}

static void tag_list_handle(void)
{
	unsigned long flags;
	struct switch_data *sw_data, *sw_next;
	LIST_HEAD(list);

	spin_lock_irqsave(&tag_release_lock, flags);
	list_splice_init(&tag_release_list, &list);
	spin_unlock_irqrestore(&tag_release_lock, flags);

	list_for_each_entry_safe(sw_data, sw_next, &list, sw_list) {
		switch_free(sw_data);
	}
}

static int tag_list_handler(void *data)
{
	while (!kthread_should_stop()) {
		wait_event_interruptible(tag_release_wait,
					 !list_empty(&tag_release_list) ||
					 kthread_should_stop());
		tag_list_handle();
	}

	/* We may have raced and missed a few tags added before kthread_stop */
	tag_list_handle();

	return 0;
}

static int tag_thread_init(void)
{
	spin_lock_init(&tag_release_lock);

	tag_list_thread = kthread_create(tag_list_handler, NULL,
					 "lve_tag_thread");
	if (IS_ERR(tag_list_thread)) {
		int rc = PTR_ERR(tag_list_thread);
		LVE_ERR("failed to create lve_tag_thread, rc=%d\n", rc);
		return rc;
	}

	wake_up_process(tag_list_thread);

	return 0;
}

static int tag_thread_fini(void)
{
	kthread_stop(tag_list_thread);
	return 0;
}

int switch_init(void)
{
	int ret;

	switch_cache = lve_call(kmem_cache_create("switch_data",
			sizeof(struct switch_data),	0, 0, NULL),
			LVE_FAIL_ALLOC_SWITCH_CACHE, NULL) ;
	if (switch_cache == NULL) {
		LVE_ERR("can't create switch_cache\n");
		ret = -ENOMEM;
		goto out;
	}

	ret = tag_thread_init();
	if (ret != 0)
		kmem_cache_destroy(switch_cache);

out:
	return ret;
}

void switch_fini(void)
{
	tag_thread_fini();

	kmem_cache_destroy(switch_cache);
}
