#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/module.h>

#include "lve_kmod_c.h"
#include "lve_debug.h"
#include "lve_internal.h"
#include "light_ve.h"
#include "lve_os_compat.h"
#include "resource.h"

struct rw_semaphore lvp_sem;
LIST_HEAD(lvp_list);

struct lvp_ve_private *root_lvp;
static struct kmem_cache *lvp_cache;

void lvp_fini(struct lvp_ve_private *lvp)
{
	if (lvp == NULL) {
		LVE_ERR("lvp is NULL\n");
		return;
	}

	lve_unlink(lvp, LVE_UNLINK_ALL, NULL);

	lve_stats_dir_fini(lvp->lvp_default);

#ifdef HAVE_EXEC_NOTIFIER
	lvp_exec_fini(lvp);
#endif
	os_lvp_fini(lvp);
	lvp_proc_fini(lvp);
#ifndef LVE_PER_VE
	if (lvp->lvp_id != ROOT_LVP)
		lve_resources_unlink(lvp->lvp_default);
#endif
	light_ve_put(lvp->lvp_default);
}

void lvp_free(struct lvp_ve_private *lvp)
{
	kmem_cache_free(lvp_cache, lvp);
	module_put(THIS_MODULE);
}

static struct lvp_ve_private *__lvp_find(uint32_t id)
{
	struct lvp_ve_private *lvp;

	list_for_each_entry(lvp, &lvp_list, lvp_link) {
		if (lvp->lvp_id == id) {
			LVE_DBG("lvp id=%u already exists list\n", lvp->lvp_id);
			return lvp;
		}
	}

	return NULL;
}

static int lvp_insert(struct lvp_ve_private *lvp)
{
	int ret = 0;
	struct lvp_ve_private *tmp = NULL;

	down_write(&lvp_sem);
	tmp = __lvp_find(lvp->lvp_id);
	if (tmp != NULL) {
		ret = -EEXIST;
	} else {
		list_add_tail(&lvp->lvp_link, &lvp_list);
		lvp_get(lvp);
	}
	up_write(&lvp_sem);
	return ret;
}


#ifndef LVE_PER_VE
struct lvp_ve_private *lvp_find(uint32_t id)
{
	struct lvp_ve_private *ret;

	down_write(&lvp_sem);
	ret = __lvp_find(id);
	if (ret != NULL)
		lvp_get(ret);
	up_write(&lvp_sem);
	return ret;

}

static struct lvp_ve_private *lvp_remove(uint32_t id)
{
	struct lvp_ve_private *lvp = NULL;
	lvp = __lvp_find(id);
	if (lvp != NULL) {
		list_del_init(&lvp->lvp_link);
		lvp_put(lvp);
	}
	return lvp;
}
#else
struct lvp_ve_private *lvp_find(uint32_t id)
{
	struct lvp_ve_private *lvp = TASK_VE_PRIVATE(current);
	if (id != lvp->lvp_id)
		return NULL;

	lvp_get(root_lvp);
	return root_lvp;
}
#endif

struct lvp_ve_private *lvp_alloc(uint32_t id, void *data)
{
	struct lvp_ve_private *lvp;
	int ret;

	lvp = lve_call(kmem_cache_alloc(lvp_cache, GFP_KERNEL),
			LVE_FAIL_ALLOC_LVP, NULL);
	if (lvp == NULL) {
		return NULL;
	}

	if (!try_module_get(THIS_MODULE)) {
		LVE_ERR("Can't get module !\n");
		kmem_cache_free(lvp_cache, lvp);
		return NULL;
	}

	memset(lvp, 0, sizeof(struct lvp_ve_private) + os_lvp_private_sz());

	INIT_LIST_HEAD(&lvp->lvp_lve_list);
	INIT_LIST_HEAD(&lvp->lvp_link);
	INIT_RADIX_TREE(&lvp->lvp_lve_list_tree, GFP_ATOMIC);
	rwlock_init(&lvp->lvp_lock);
	atomic_set(&lvp->lvp_usage, 0);
	lvp->lvp_id = id;

	lvp->lvp_default = lve_alloc(lvp, SELF_LVE);
	if (IS_ERR(lvp->lvp_default)) {
		lvp_free(lvp);
		return NULL;
	}

	lvp->lvp_def_limits[LIM_CPU] = 10;
	lvp->lvp_def_limits[LIM_IO] = 0;
	lvp->lvp_def_limits[LIM_IOPS] = 0;
	lvp->lvp_def_limits[LIM_ENTER] = 10;
	lvp->lvp_def_limits[LIM_MEMORY] = 0;
	lvp->lvp_def_limits[LIM_CPU_WEIGHT] = 100;

	lve_namespace_init(lvp->lvp_default);
	lve_stat_init(&lvp->lvp_default->lve_stats);
	lve_net_init(lvp->lvp_default);

#ifdef HAVE_EXEC_NOTIFIER
	lvp_exec_init(lvp);
#endif

	if (lvp_proc_init(lvp) < 0)
		goto err;

	if (os_lvp_init(lvp, data) < 0)
		goto err;

	lve_stats_dir_init(lvp->lvp_default);

#ifndef LVE_PER_VE
	if (lvp->lvp_id != ROOT_LVP) {
		ret = lve_namespace_setup(root_lvp, lvp->lvp_default);
		if (ret != 0)
			goto err;
	}
#endif

	ret = lvp_insert(lvp);
	if (ret == -EEXIST) {
		LVE_ERR("lvp id=%u is exists\n", id);
		goto err;
	}

	return lvp;
err:
	lvp_fini(lvp);
	return NULL;
}

int lve_lvp_init()
{
	init_rwsem(&lvp_sem);

	lvp_cache = lve_call(kmem_cache_create("lvp_cache",
			sizeof(struct lvp_ve_private) + os_lvp_private_sz(),
			0, 0, NULL), LVE_FAIL_ALLOC_LVP_CACHE, NULL);
	if (lvp_cache == NULL)
		return -ENOMEM;

	root_lvp = lvp_alloc(0, NULL);
	if (root_lvp == NULL)
		return -ENOMEM;

	/* Decrement the reference for root_lvp */
	module_put(THIS_MODULE);

	return 0;
}

void lvp_root_fini()
{
	if (root_lvp) {
		lvp_put(root_lvp);
		lvp_fini(root_lvp);
	}
}

void lve_lvp_fini()
{
	if (lvp_cache == NULL) {
		LVE_ERR("lvp_cache is NULL\n");
		return;
	}

	kmem_cache_destroy(lvp_cache);
}

int lvp_destroy(uint32_t id)
{
#ifndef LVE_PER_VE
	struct lvp_ve_private *lvp = NULL;

	if (id == ROOT_LVP)
		return -EINVAL;

	down_write(&lvp_sem);
	lvp = lvp_remove(id);
	if (lvp != NULL)
		lvp_fini(lvp);
	up_write(&lvp_sem);
	return lvp != NULL ? 0 : -ESRCH ;
#else
	return -ENOSYS;
#endif
}

