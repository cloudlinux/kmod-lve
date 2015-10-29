#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/nsproxy.h>

#include "lve_kmod_c.h"
#include "lve_debug.h"
#include "lve_internal.h"
#include "light_ve.h"
#include "tags.h"
#include "lve_os_compat.h"
#include "resource.h"
#include "tags.h"
#include "lve_global_params.h"

struct lvp_ve_private *root_lvp;
struct kmem_cache *lvp_cache;

#ifndef HAVE_VE_PROC_ROOT
struct proc_dir_entry *lve_procfs_root(struct lvp_ve_private *lvp)
{
	/* TODO */
	return NULL;
}
#endif

void lvp_fini(struct lvp_ve_private *lvp)
{
	lve_unlink(lvp, LVE_UNLINK_ALL, NULL);
#ifdef HAVE_EXEC_NOTIFIER
	lvp_exec_fini(lvp);
#endif
	os_lvp_fini(lvp);
	lvp_proc_fini(lvp);
	light_ve_put(lvp->lvp_default);
}

void lvp_free(struct lvp_ve_private *lvp)
{
	kmem_cache_free(lvp_cache, lvp);
}

void lvp_destroy(struct lvp_ve_private *lvp)
{
	lvp_fini(lvp);
	lvp_free(lvp);
}

struct lvp_ve_private *lvp_alloc(uint32_t id, void *data)
{
	struct lvp_ve_private *lvp;

	lvp = lve_call(kmem_cache_alloc(lvp_cache, GFP_KERNEL),
			LVE_FAIL_ALLOC_LVP, NULL);
	if (lvp == NULL)
		return NULL;
	memset(lvp, 0, sizeof(struct lvp_ve_private) + os_lvp_private_sz());

	INIT_LIST_HEAD(&lvp->lvp_list);
	INIT_RADIX_TREE(&lvp->lvp_list_tree, GFP_ATOMIC);
	rwlock_init(&lvp->lvp_lock);
	lvp->lvp_id = id;

	lvp->lvp_default = lve_alloc(lvp, 0);
	if (lvp->lvp_default == NULL) {
		kmem_cache_free(lvp_cache, lvp);
		return NULL;
	}

	lvp->lvp_default->lve_limits[LIM_CPU] = 10;
	lvp->lvp_default->lve_limits[LIM_IO] = 0;
	lvp->lvp_default->lve_limits[LIM_IOPS] = 0;
	lvp->lvp_default->lve_limits[LIM_ENTER] = 10;
	lvp->lvp_default->lve_limits[LIM_MEMORY] = 0;
	lvp->lvp_default->lve_limits[LIM_CPU_WEIGHT] = 1024;

	rwlock_init(&lvp->lvp_default->lve_ns_lock);

#ifdef HAVE_EXEC_NOTIFIER
	lvp_exec_init(lvp);
#endif

	if (lvp_proc_init(lvp) < 0)
		goto err;

	if (os_lvp_init(lvp, data) < 0)
		goto err;

	return lvp;
err:
	lvp_destroy(lvp);
	return NULL;
}

int
lve_resources_init(struct light_ve *ve)
{
	int rc = 0;

	/* XXX should be we have share NS with top root ? */
	rc = lve_namespace_init(ve);
	if (rc)
		goto out;

	rc = os_resource_init(ve);
out:
	return rc;
}

int
lve_resources_free(struct light_ve *ve)
{
	int rc  = 0;

	lve_namespace_fini(ve);
	os_resource_fini(ve->lve_id, lve_private(ve));

	return rc;
}

int
lve_resources_unlink(struct light_ve *ve)
{
	return os_resource_unlink(ve->lve_id, lve_private(ve));
}

int lve_resources_setup(struct light_ve *lve, lve_limits_t limits)
{
	uint32_t custom = 0;

	/** limits lock */
	if (lve->lve_limits[LIM_CPU] != limits[LIM_CPU]) {
		custom |= CUST_CPU;
		lve->lve_limits[LIM_CPU] = limits[LIM_CPU];
	}

	if (lve->lve_limits[LIM_CPUS] != limits[LIM_CPUS]) {
		custom |= CUST_CPU | CUST_CPUS; /* recalc rate */
		if (limits[LIM_CPUS] < 1 || limits[LIM_CPUS] > num_online_cpus())
			limits[LIM_CPUS] = num_online_cpus();
		lve->lve_limits[LIM_CPUS] = limits[LIM_CPUS];
	}

	if (lve->lve_limits[LIM_ENTER] != limits[LIM_ENTER]) {
		custom |= CUST_ENTER;
		lve->lve_limits[LIM_ENTER] = limits[LIM_ENTER];
	}

	if (lve->lve_limits[LIM_IO] != limits[LIM_IO]) {
		custom |= CUST_IO;
		lve->lve_limits[LIM_IO] = limits[LIM_IO];
	}

	if (lve->lve_limits[LIM_IOPS] != limits[LIM_IOPS]) {
		custom |= CUST_IOPS;
		lve->lve_limits[LIM_IOPS] = limits[LIM_IOPS];
	}

	if (lve->lve_limits[LIM_MEMORY] != limits[LIM_MEMORY]) {
		custom |= CUST_MEM;
		lve->lve_limits[LIM_MEMORY] = limits[LIM_MEMORY];
	}

	if (lve->lve_limits[LIM_CPU_WEIGHT] != limits[LIM_CPU_WEIGHT]) {
		custom |= CUST_CPU_WEIGHT;
		lve->lve_limits[LIM_CPU_WEIGHT] = limits[LIM_CPU_WEIGHT];
	}

	if (lve->lve_limits[LIM_MEMORY_PHY] != limits[LIM_MEMORY_PHY]) {
		custom |= CUST_MEM_PHY;
		lve->lve_limits[LIM_MEMORY_PHY] = limits[LIM_MEMORY_PHY];
	}

	if (lve->lve_limits[LIM_NPROC] != limits[LIM_NPROC]) {
		custom |= CUST_NPROC;
		lve->lve_limits[LIM_NPROC] = limits[LIM_NPROC];
	}

	if (custom) {
		/* XXX need compare with default limits */
		lve->lve_custom = 1;
	}

	if (custom)
		return os_resource_setup(lve_private(lve), lve->lve_limits, custom);
	else
		return 0;
}

int lve_resource_push(struct task_struct *task, struct light_ve *ve, uint32_t sw_flags)
{
	int rc = 0;

	rc = os_cpu_enter(task, lve_private(ve));
	if (rc)
		goto out;

	if ((sw_flags & LVE_ENTER_NO_UBC) == 0) {
		rc = os_resource_push(task, lve_private(ve));
		if (rc) {
			LVE_ERR("os_resource_push failed with %d\n", rc);
			goto out;
		}
	}

	if (sw_flags & LVE_ENTER_NAMESPACE) {
		rc = lve_namespace_enter(task, ve);
		if (rc)
			LVE_ERR("lve_namespace_enter failed with %d\n", rc);
	}

out:
	return rc;
}

void lve_resource_usage(struct light_ve *lve, struct lve_usage *buf)
{
	memset(buf, 0, sizeof(*buf));

	if (lve->lve_id == ROOT_LVE)
		return;

	buf->data[RES_ENTER].data = lve->lve_stats.st_enters;
	buf->data[RES_ENTER].fail = lve->lve_stats.st_err_enters;
	return os_resource_usage(lve_private(lve), buf);
}

void lve_resource_usage_clear(struct light_ve *lve)
{
	if (lve->lve_id == ROOT_LVE)
		return;

	return os_resource_usage_clear(lve_private(lve));
}

uint64_t lve_node_id(struct task_struct *task)
{
	struct switch_data *sw_data;
	uint32_t lve_id = 0;

	sw_data = LVE_TAG_GET(task);
	if (sw_data != NULL && sw_data->sw_from != NULL)
		lve_id = sw_data->sw_from->lve_id;

	if (sw_data != NULL)
		LVE_TAG_PUT(sw_data);

	return NODEID_ENCODE(task_veid(task), lve_id);
}

void lve_resource_fail(struct task_struct * task, int resource)
{
	struct switch_data * sw_data;

	sw_data = LVE_TAG_GET(task);
	if (sw_data == NULL) {
		LVE_WARN("task %p without tag\n", task);
		return;
	}

	sw_data->sw_failmask |= resource;
	LVE_TAG_PUT(sw_data);
}

int lve_res_init()
{
	int ret;

	lvp_cache = lve_call(lve_kmem_cache_create("lvp_cache",
			sizeof(struct lvp_ve_private) + os_lvp_private_sz(),
			0, 0, NULL), LVE_FAIL_ALLOC_LVP_CACHE, NULL);
	if (lvp_cache == NULL)
		return -ENOMEM;

	ret = os_global_init();
	if (ret != 0)
		goto out_lvp_kmem;

	root_lvp = lvp_alloc(0, NULL);
	if (root_lvp != NULL) {
		lve_set_param_callbacks();
		return 0;
	}

	ret = -ENOMEM;
	lvp_destroy(root_lvp);
out_lvp_kmem:
	if (lve_kmem_cache_destroy(lvp_cache))
		LVE_ERR("MEMORY LEAK!\n");

	return ret;
}

void lve_res_fini()
{
	os_global_fini();

	lvp_destroy(root_lvp);

	if (lve_kmem_cache_destroy(lvp_cache))
		LVE_ERR("MEMORY LEAK!\n");
}
