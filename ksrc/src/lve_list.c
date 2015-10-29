#include <linux/list.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/radix-tree.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/kthread.h>

#include "lve_debug.h"
#include "lve_internal.h"
#include "light_ve.h"
#include "resource.h"

#if RHEL_MAJOR < 7
#define is_special_task(p) \
	(!((p)->flags & PF_THREAD_BOUND))
#else
#define is_special_task(p) (0)
#endif

void _lve_add_list(struct light_ve *ve_new);

static struct task_struct *lve_init_task;
static LIST_HEAD(lve_init_list);
static LIST_HEAD(lve_cleanup_list);
static spinlock_t lve_init_lock;
static spinlock_t lve_cleanup_lock;
static DECLARE_WAIT_QUEUE_HEAD(lve_init_wait);
struct kmem_cache *lve_struct;

static int lve_submit_to_init(struct light_ve *ptr);
static int lve_submit_to_cleanup(struct light_ve *ptr);

/**
 create containers in separate thread with administrative rights
 to avoid problems with permissions checks (in CL6) and EBUSY (in CL5).
 LVE create a similar to create a inode. container locked after creation with LVE_BIT_INIT
 flag and waiting on that bit until creation will finished.
 if initialization failed, container marked by flag LVE_BIT_ERROR and unlinked from tree,
 so next access will start from creation new container for that id.
 */

static void lve_stat_init(struct light_ve *lve)
{
	memset(&lve->lve_stats, 0, sizeof(lve->lve_stats));
	spin_lock_init(&lve->lve_stats.enter_lock);
}

static int lve_first_init(struct light_ve *ve)
{
	struct lvp_ve_private *lvp;
	int rc;

/*
 * Here we can't get lvp from current context, because all work threads
 * executes in container with veid == 0.
 */
	rc = lve_resources_init(ve);
	if (rc < 0) {
		LVE_ERR("res init %d\n", rc);
		goto out;
	}

	lvp = ve->lve_lvp;
	rc = lve_resources_setup(ve, lvp->lvp_default->lve_limits);
	if (rc < 0) {
		LVE_ERR("res setup %d\n", rc);
		goto out;
	}
	ve->lve_custom = 0;
	lve_stat_init(ve);
	lve_stats_dir_init(ve);
out:
	if (rc) {
		set_bit(LVE_BIT_ERROR, &ve->lve_bit_flag);
	} else {
		write_lock_irq(&lvp->lvp_lock);
		_lve_add_list(ve);
		write_unlock_irq(&lvp->lvp_lock);
	}

	clear_bit(LVE_BIT_INIT, &ve->lve_bit_flag);
	smp_mb__after_clear_bit();
	wake_up_bit(&ve->lve_bit_flag, LVE_BIT_INIT);

	if (rc)
		lve_unlink(ve->lve_lvp, LVE_UNLINK_VE, ve);

	return rc;
}

static void lve_final_cleanup(struct light_ve *ptr)
{
	LVE_DBG("enter, ve id=%d\n", ptr->lve_id);
	lve_resources_free(ptr);
	kmem_cache_free(lve_struct, ptr);
}

static int lve_add_to_first_init(struct light_ve *ve)
{
	if (ve == NULL) {
		LVE_ERR("ve == NULL\n");
		return -EINVAL;
	}

	spin_lock(&lve_init_lock);
	list_add_tail(&ve->lve_init_link, &lve_init_list);
	spin_unlock(&lve_init_lock);
	wake_up(&lve_init_wait);

	return 0;
}

static int lve_add_to_final_cleanup(struct light_ve *ve)
{
	if (ve == NULL) {
		LVE_ERR("ve == NULL\n");
		return -EINVAL;
	}

	spin_lock(&lve_cleanup_lock);
	list_add_tail(&ve->lve_init_link, &lve_cleanup_list);
	spin_unlock(&lve_cleanup_lock);
	wake_up(&lve_init_wait);

	return 0;
}

static void lve_flush_cleanup_list(void)
{
	struct light_ve *ve;

	while (!list_empty(&lve_cleanup_list)) {
		spin_lock(&lve_cleanup_lock);
		ve = list_first_entry(&lve_cleanup_list, struct light_ve, lve_init_link);
		list_del(&ve->lve_init_link);
		spin_unlock(&lve_cleanup_lock);
		LVE_DBG("cleanup lve id=%d\n", ve->lve_id);
		lve_final_cleanup(ve);
	}
}

static void lve_flush_init_list(void)
{
	struct light_ve *ve;

	while (!list_empty(&lve_init_list)) {
		spin_lock(&lve_init_lock);
		ve = list_first_entry(&lve_init_list, struct light_ve, lve_init_link);
		list_del(&ve->lve_init_link);
		spin_unlock(&lve_init_lock);
		LVE_DBG("adding lve with id %d\n", ve->lve_id);
		lve_first_init(ve);
	}
}

int lve_init_thread(void *data)
{
	while (!kthread_should_stop() || !list_empty(&lve_cleanup_list)) {
		wait_event_interruptible(lve_init_wait, (!list_empty(&lve_init_list) ||
			!list_empty(&lve_cleanup_list) || kthread_should_stop()));
		lve_flush_cleanup_list();
		lve_flush_init_list();
	}

	BUG_ON(!list_empty(&lve_init_list));
	BUG_ON(!list_empty(&lve_cleanup_list));

	return 0;
}

static int lve_init_threads_init(void)
{
	spin_lock_init(&lve_init_lock);
	spin_lock_init(&lve_cleanup_lock);
	lve_init_task = kthread_create(lve_init_thread, NULL, "lve_init_thread");
	if (IS_ERR(lve_init_task)) {
		LVE_ERR("Can't create lve_init_thread, err: %lu", PTR_ERR(lve_init_task));
		return PTR_ERR(lve_init_task);
	}
	wake_up_process(lve_init_task);

	return 0;
}

static int lve_init_threads_fini(void)
{
	kthread_stop(lve_init_task);
	return 0;
}

int
lve_list_init()
{
	int ret = 0;
	lve_struct = lve_call(lve_kmem_cache_create("lve_struct",
			      sizeof(struct light_ve) + os_context_private_sz(),
			      0, 0, NULL), LVE_FAIL_ALLOC_LVE_CACHE, NULL);
	if (lve_struct == NULL) {
		LVE_ERR("Can't create cache lve_struct!\n");
		return -ENOMEM;
	}

	ret = lve_call(lve_init_threads_init(),
		       LVE_FAIL_INIT_THRDS_INIT, -ENOMEM);
	if (ret)
		goto threads_err;

	return 0;

threads_err:
	if (lve_kmem_cache_destroy(lve_struct))
		LVE_ERR("Memory leak in lve structs\n");

	return ret;

#if 0
err:
	lve_list_fini();
	return -ENOMEM;
#endif
}

void
lve_list_fini()
{
	lve_init_threads_fini();

	if (lve_kmem_cache_destroy(lve_struct)) {
		LVE_ERR("Memory leak in lve structs\n");
	}
}

void
lve_last_put(struct light_ve *ptr)
{
	BUG_ON(!list_empty(&ptr->lve_link));
	if (ptr->lve_id != ROOT_LVE)
		lve_submit_to_cleanup(ptr);
	else
		/* Do not submit lve_default - no sense cause
		* the module is about to be unloaded */
		lve_final_cleanup(ptr);
}

static int __lve_wait_init(void *word)
{
	schedule();
	return 0;
}

static void lve_wait_to_init(struct light_ve *lve)
{
	wait_on_bit(&lve->lve_bit_flag, LVE_BIT_INIT, __lve_wait_init, TASK_INTERRUPTIBLE);
}

struct light_ve *
_lve_find(uint32_t ve_id)
{
	struct light_ve *lve;
	struct lvp_ve_private *lvp;
	lvp = TASK_VE_PRIVATE(current);

	lve = lve_call(radix_tree_lookup(&lvp->lvp_list_tree, ve_id),
			LVE_FAIL_LVE_LOOKUP, NULL);
	if (lve)
		light_ve_get(lve);

	return lve;
}

struct light_ve *
lve_find(uint32_t ve_id)
{
	struct light_ve *ve;
	struct lvp_ve_private *lvp;

	lvp = TASK_VE_PRIVATE(current);
	read_lock_irq(&lvp->lvp_lock);
	ve = _lve_find(ve_id);
	read_unlock_irq(&lvp->lvp_lock);
	if (ve) {
		lve_wait_to_init(ve);
		if (test_bit(LVE_BIT_ERROR, &ve->lve_bit_flag)) {
			light_ve_put(ve);
			ve = NULL;
		}
	}

	return ve;
}

void _lve_add_list(struct light_ve *ve_new)
{
	struct light_ve *ve;
	struct list_head *ve_prev;
	struct lvp_ve_private *lvp = ve_new->lve_lvp;

	ve_prev = &lvp->lvp_list;
	list_for_each_entry(ve, &lvp->lvp_list, lve_link) {
		BUG_ON(ve->lve_id == ve_new->lve_id);
		if (ve->lve_id > ve_new->lve_id) {
			list_add(&ve_new->lve_link, ve_prev);
			return;
		}
		ve_prev = &ve->lve_link;
	}
	list_add(&ve_new->lve_link, ve_prev);
}


static struct light_ve *
_lve_add(struct light_ve *ve_new)
{
	int rc;
	struct lvp_ve_private *lvp = TASK_VE_PRIVATE(current);

	rc = lve_call(radix_tree_insert(&lvp->lvp_list_tree, ve_new->lve_id,
			ve_new), LVE_FAIL_LVE_INSRT, -ENOMEM);
	/* We could race with adding something ...*/
	if (rc == -EEXIST)
		return _lve_find(ve_new->lve_id);
	if (rc < 0)
		return ERR_PTR(rc);
	light_ve_get(ve_new);

	return ve_new;
}

static void kill_all_threads(uint32_t ve_id, uint32_t lve_id)
{
	struct task_struct *t, *p;
	uint64_t nid = NODEID_ENCODE(ve_id, lve_id);

	/* XXX: should we lock cgroups? */
	read_lock(&tasklist_lock);
	lve_do_each_thread(t, p) {
		if (p == current)
			continue;

		if (lve_node_id(p) == nid) {
			/* A workaround for buggy kthread code which uses
			 * INTERRUPTIBLE kernel wait loops, but does
			 * not attempt to handle signals, e.g. balloon
			 */
			if (p->mm == NULL) {
				if (is_special_task(p))
					LVE_ERR("not going to kill thread %d "
						"(%s)\n", lve_task_pid(p),
						p->comm);
				continue;
			}

			force_sig(SIGKILL, p);
		}
	} lve_while_each_thread(t, p);
	read_unlock(&tasklist_lock);
}

/* remove lve from lists and kill its threads */
static void lve_clean(struct light_ve *ve, struct list_head *list)
{
	struct light_ve *tree_ve;

	LVE_DBG("cleaning ve %d\n", ve->lve_id);
	tree_ve = radix_tree_delete(&ve->lve_lvp->lvp_list_tree, ve->lve_id);
	BUG_ON(tree_ve != ve);

	list_del_init(&ve->lve_link);
	list_add(&ve->lve_init_link, list);

	ve->lve_unlinked = 1;
	smp_mb();
	/* Let's kill the threads before we release
	 * the lvp_lock. This would allow us to avoid
	 * killing threads from a fresh ve with the
	 * same id. */
#ifdef LVE_PER_VE
	kill_all_threads(ve->lve_lvp->lvp_ve->veid, ve->lve_id);
#else
	kill_all_threads(0, ve->lve_id);
#endif
}

/*
 *  lve_unlink_generic unlinks a specific ve, all ves or default ves.
 *
 *  target = LVE_UNLINK_VE, LVE_UNLINK_ALL, LVE_UNLINK_DEFAULT
 *  ve  = ve for LVE_UNLINK_VE
 */

void lve_unlink(struct lvp_ve_private *lvp, enum lve_unlink_target target,
		struct light_ve *v)
{
	struct light_ve *ve, *tree_ve;
	
	LIST_HEAD(list);

	LVE_DBG("target=%d ve_id=%d\n", target, v ? (int)v->lve_id : -1);

	write_lock_irq(&lvp->lvp_lock);
	if (target == LVE_UNLINK_VE) {
		tree_ve = radix_tree_lookup(&lvp->lvp_list_tree, v->lve_id);

		/* We may have got unlinked in a race condition */
		if (unlikely(tree_ve == NULL)) {
			BUG_ON(!list_empty(&v->lve_link));
			BUG_ON(!v->lve_unlinked);
		} else {
			lve_clean(v, &list);
		}
	} else {
		struct list_head *pos, *next;
		list_for_each_safe(pos, next, &lvp->lvp_list) {
			ve = list_entry(pos, struct light_ve, lve_link);

			if (target == LVE_UNLINK_DEFAULT &&
			    ve->lve_custom)
				continue;

			lve_clean(ve, &list);
		}
	}
	write_unlock_irq(&lvp->lvp_lock);

	while (!list_empty(&list)) {
		int rc;

		ve = list_first_entry(&list, struct light_ve, lve_init_link);
		list_del_init(&ve->lve_init_link);

		lve_stats_dir_fini(ve);
		rc = lve_resources_unlink(ve);
		if (rc != 0) {
			LVE_ERR("unlink failed for %d\n", ve->lve_id);
			BUG();
		}
		light_ve_put(ve);
	}
}

static int lve_submit_to_init(struct light_ve *ptr)
{
	return lve_add_to_first_init(ptr);
}

static int lve_submit_to_cleanup(struct light_ve *ptr)
{
	return lve_add_to_final_cleanup(ptr);
}

struct light_ve *lve_alloc(struct lvp_ve_private *lvp, uint32_t ve_id)
{
	struct light_ve *ve;

	LVE_DBG("allocating ve=%d\n", (int)ve_id);

	ve = lve_call(kmem_cache_zalloc(lve_struct, GFP_KERNEL),
					LVE_FAIL_ALLOC_VE, NULL);
	if (!ve) {
		LVE_ERR("Can't allocate memory for new VE %u\n", ve_id);
		return ERR_PTR(-ENOMEM);
	}

	ve->lve_id = ve_id;
	ve->lve_bit_flag |= 1 << LVE_BIT_INIT;
	INIT_LIST_HEAD(&ve->lve_link);
	atomic_set(&ve->lve_refcnt, 1);
	ve->lve_lvp = lvp;

	return ve;
}

static struct light_ve *__lve_init(struct lvp_ve_private *lvp, struct light_ve *ve)
{
	struct light_ve *old_ve;

	if (lve_call(radix_tree_preload(GFP_KERNEL),
			LVE_FAIL_RDXT_PRELOAD, -ENOMEM)) {
		old_ve = ERR_PTR(-ENOMEM);
		goto out;
	}
	write_lock_irq(&lvp->lvp_lock);
	old_ve = _lve_add(ve);
	if (old_ve == ve)
		lve_submit_to_init(ve);
	write_unlock_irq(&lvp->lvp_lock);
	radix_tree_preload_end();
	if (old_ve != ve) {
		LVE_DBG("create race for %d\n", (int)ve->lve_id);
		light_ve_put(ve);
		ve = old_ve;
	}

	if (!IS_ERR(ve)) {
		lve_wait_to_init(ve);
		if (test_bit(LVE_BIT_ERROR, &ve->lve_bit_flag)) {
			old_ve = ERR_PTR(-EINVAL);
			goto out;
		}
	}
	return ve;
out:
	light_ve_put(ve);
	return old_ve;
}

struct light_ve *
lve_find_or_alloc(uint32_t ve_id)
{
	struct light_ve *ve;

	ve = lve_find(ve_id);
	if (ve)
		return ve;
	ve = lve_alloc(TASK_VE_PRIVATE(current), ve_id);
	if (!IS_ERR(ve))
		return __lve_init(TASK_VE_PRIVATE(current), ve);

	return ve;
}
