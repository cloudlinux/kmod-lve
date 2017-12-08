#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/mount.h>

#include <linux/cgroup.h>

#include <linux/cpuset.h>
#include <linux/ve_proto.h>
#include <linux/freezer.h>
#include <linux/mmgang.h>
#include <linux/swap.h>
#include <linux/mm.h>
#include <bc/beancounter.h>

#include "lve_kmod_c.h"
#include "lve-api.h"
#include "kernel_exp.h"
#include "openvz_cgroups.h"
#include "cgroup_lib.h"
#include "ubc_lib.h"
#include "resource.h"
#include "lve_debug.h"
#include "light_ve.h"
#include "lve_internal.h"
#include "openvz_iolimits.h"
#include "mm.h"

struct params cpu_params[] = {
	[ PARAM_CPU_STAT ] = { "cpuacct.usage", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPU_LIMIT] = { "cpu.rate", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPU_CHWT ] = { "cpu.shares", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPUS_LIMIT ] = { "cpu.nr_cpus", &cmnt[CPU_SUBSYS].mnt_root }
};

unsigned int os_context_private_sz(void)
{
	return sizeof(struct c_private);
}

unsigned int os_lvp_private_sz(void)
{
	return sizeof(struct lvp_private);
}

void os_resource_usage(struct c_private *private, struct lve_usage *buf)
{
	int precharge[UB_RESOURCES];
	__s64 data;

	data = cgrp_param_get(private->cpu_filps[PARAM_CPU_STAT]);
	if(data > 0) {
		LVE_DBG("cpu usage "LPU64"\n", data);
		buf->data[RES_CPU].data = data;
	}

	if (!private->lve_ub)
		return;

	lve_sync_ub_usage(private->lve_ub);
	lve_ub_prechange_snapshot(private->lve_ub, precharge);

	ubc_mem_stat(private->lve_ub, &buf->data[RES_MEM], precharge);
	ubc_phys_mem_stat(private->lve_ub, &buf->data[RES_MEM_PHY], precharge);
	ubc_nproc_stat(private->lve_ub, &buf->data[RES_NPROC], precharge);

	buf->data[RES_IO].data = ovz_get_io_usage(private->lve_ub) >> 10;
	buf->data[RES_IOPS].data = ovz_get_iops_usage(private->lve_ub);
}

void os_resource_usage_clear(struct c_private *private)
{
	cgrp_param_set_u64(private->cpu_filps[PARAM_CPU_STAT], 0);
}

#ifndef LVE_PER_VE
static int os_resource_extra_init(struct c_private *lcontext, char *name)
{
	struct cgroup *_lve_ub_cgroup_root = lve_get_ub_cgroup_root();
	struct cgroup *_lve_mem_cgroup_root = cmnt[MEM_SUBSYS].cgrp_root;
	struct cgroup *_lve_blk_cgroup_root = cmnt[BLK_SUBSYS].cgrp_root;
	struct cgroup *_lve_freezer_cgroup_root = cmnt[FREEZER_SUBSYS].cgrp_root;

	if (_lve_mem_cgroup_root) {
#ifdef HAVE_IN_UB_MEMCG_ATTACH
		struct user_beancounter *old_ub = set_exec_ub(lcontext->lve_ub);
		current->in_ub_memcg_attach = 1;
#endif
		lcontext->cgrp[CG_MEM_GRP] = lve_cgroup_kernel_open(_lve_mem_cgroup_root,
					LVE_CGRP_CREAT, name);
		if (IS_ERR(lcontext->cgrp[CG_MEM_GRP])) {
			LVE_ERR("can't create mem_cgroup\n");
			lcontext->cgrp[CG_MEM_GRP] = NULL;
		}
		LVE_DBG("mem_cgroup=%p\n", lcontext->cgrp[CG_MEM_GRP]);
#ifdef HAVE_IN_UB_MEMCG_ATTACH
		current->in_ub_memcg_attach = 0;
		lcontext->lve_ub = set_exec_ub(old_ub);
#endif
	}

	if (_lve_ub_cgroup_root) {
		lcontext->cgrp[CG_UB_GRP] = lve_cgroup_kernel_open(_lve_ub_cgroup_root,
						LVE_CGRP_CREAT, name);
		if (IS_ERR(lcontext->cgrp[CG_UB_GRP])) {
			LVE_ERR("can't create ub_cgroup\n");
			lcontext->cgrp[CG_UB_GRP] = NULL;
		}
		LVE_DBG("ub_cgroup=%p\n", lcontext->cgrp[CG_UB_GRP]);
	}

	if (_lve_blk_cgroup_root) {
		lcontext->cgrp[CG_BLK_GRP] = lve_cgroup_kernel_open(_lve_blk_cgroup_root,
						LVE_CGRP_CREAT, name);
		if (IS_ERR(lcontext->cgrp[CG_BLK_GRP])) {
			LVE_ERR("can't create blkio cgroup\n");
			lcontext->cgrp[CG_BLK_GRP] = NULL;
		}
		LVE_DBG("blkio cgrp=%p\n", lcontext->cgrp[CG_BLK_GRP]);
	}

	if (_lve_freezer_cgroup_root != NULL) {
		lcontext->cgrp[CG_FREEZER_GRP] = lve_cgroup_kernel_open(_lve_freezer_cgroup_root,
						CGRP_CREAT, name);
		if (IS_ERR(lcontext->cgrp[CG_FREEZER_GRP])) {
			LVE_ERR("can't create freezer_cgroup\n");
			lcontext->cgrp[CG_FREEZER_GRP] = NULL;
		}
		LVE_DBG("create freezer_cgroup=%p, name %s\n",
			lcontext->cgrp[CG_FREEZER_GRP], name);
	}

	return 0;
}
#endif

int os_resource_init(struct light_ve *ve __attribute__((unused)))
{
#ifndef LVE_PER_VE
	struct lvp_ve_private *lvp = ve->lve_lvp;
	int id = NODEID_ENCODE(lvp->lvp_id, ve->lve_id);
	struct cgroup *cgrp = NULL;
	struct c_private *lcontext = lve_private(ve);
	struct lvp_private *lvpp = os_lvp_private(lvp);
	char name[MAX_GRP_NAMESZ];

	snprintf(name, sizeof(name), "lve%u", id);
	cgrp = lve_call(lve_cgroup_kernel_open(lvpp->lve_cpu_root, LVE_CGRP_CREAT |
				LVE_CGRP_EXCL, name), LVE_FAIL_CGRP_OPEN,
				ERR_PTR(-EEXIST));
	if (IS_ERR(cgrp)) {
		LVE_ERR("lve_cpu_root %s err %ld\n",
			name, PTR_ERR(cgrp));
		return PTR_ERR(cgrp);
	}
	lcontext->cgrp[CG_CPU_GRP] = cgrp;
	LVE_DBG("cpu group %p\n", cgrp);

	lcontext->lve_ub = lve_call(lve_get_beancounter_byuid(id, 1),
				LVE_FAIL_GET_UB_BYUID, NULL);
	if (lcontext->lve_ub == NULL) {
		LVE_ERR("can't create UBC for context %u\n", id);
		return -ENOMEM;
	}

	os_resource_extra_init(lcontext, name);

	cgrp_populate_dir(lcontext->cgrp[CG_CPU_GRP], lcontext->cpu_filps,
		cpu_params, ARRAY_SIZE(cpu_params));

	init_beancounter_nolimits(lcontext->lve_ub);

	ub_set_shortage_cb(lcontext->lve_ub, ubc_shortage);
#endif
	return 0;
}

int os_resource_unlink(uint32_t id, struct c_private *lcontext)
{
	int i;
	char name[MAX_GRP_NAMESZ] = {0};

	LVE_ENTER("(id=%u, lcontext=%p)\n", id, lcontext);
	lcontext->unlink_id = get_unlink_id();

	snprintf(name, sizeof(name)-1, UNLINK_FORMAT, lcontext->unlink_id);

	for (i = 0; i < CG_MAX_GRP; i++) {
		if (lcontext->cgrp[i] != NULL)
			cgrp_obfuscate(lcontext->cgrp[i], name);
	}

#ifdef HAVE_UB_CGROUP
	if (lcontext->lve_ub != NULL && blkio_grp(lcontext->lve_ub) != NULL)
		cgrp_obfuscate(blkio_grp(lcontext->lve_ub), name);
#endif

	return 0;
}

static void lve_cgroup_release(uint32_t id, char *name, struct cgroup *cgrp)
{
	lve_cgroup_kernel_close(cgrp);
	if (id != ROOT_LVE)
		lve_cgroup_kernel_remove(cgrp->parent, name);
}

int os_resource_fini(struct light_ve *ve)
{
	int rc = 0;
	int i;
	uint32_t id = ve->lve_id;
	struct c_private *lcontext = lve_private(ve);
	char name[MAX_GRP_NAMESZ] = {0};

	LVE_ENTER("(id=%u, lcontext=%p)\n", id, lcontext);

	snprintf(name, sizeof(name)-1, UNLINK_FORMAT, lcontext->unlink_id);

	for (i = 0; i < ARRAY_SIZE(cpu_params); i++) {
		if (lcontext->cpu_filps[i] != NULL) {
			cgrp_param_release(lcontext->cpu_filps[i]);
			lcontext->cpu_filps[i] = NULL;
		}
	}

	for (i = 0; i < CG_MAX_GRP; i++) {
		if (lcontext->cgrp[i] != NULL) {
			lve_cgroup_release(id, name, lcontext->cgrp[i]);
			lcontext->cgrp[i] = LVE_POISON_PTR;
		}
	}

#ifndef LVE_PER_VE
	if (lcontext->lve_ub) {
		ub_set_shortage_cb(lcontext->lve_ub, NULL);
		put_beancounter(lcontext->lve_ub);
		lcontext->lve_ub = LVE_POISON_PTR;
	}
#endif

	return rc;
}

int os_resource_setup(struct c_private *lcontext, int32_t new,
		      enum lve_limits custom)
{
	int rc = 0;
#ifndef LVE_PER_VE
	int lim;

	switch (custom) {
	case LIM_CPUS:
		LVE_DBG("set cpu affinity to %d\n", new);
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPUS_LIMIT],
				new), LVE_FAIL_WRT_CPUS_LIM, -EINVAL);
		break;
	case LIM_CPU:
		/*
		 * DIV_ROUND_UP needs for case when new[LIM_CPU] is
		 * lesser than 10, in such case divide without round up
		 * produce zero limit.
		 */
		lim = DIV_ROUND_UP(new, 10) * 1024 / 1000;
		LVE_DBG("set fairshed rate to %u\n", lim);
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPU_LIMIT], lim),
				LVE_FAIL_WRT_CPU_LIM, -EINVAL);
		break;
	case LIM_CPU_WEIGHT:
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPU_CHWT],
				new*1024/100), LVE_FAIL_WRT_CPU_CHWT, -EINVAL);
		break;
	case LIM_IO:
		rc = lve_call(ovz_set_io_limit(lcontext->lve_ub,
				new << 10, 0),
				LVE_FAIL_IO_SET_LIM, -ENOMEM);
		break;
	case LIM_IOPS:
		rc = lve_call(ovz_set_iops_limit(lcontext->lve_ub,
				new, 0),
				LVE_FAIL_IO_SET_LIM, -ENOMEM);
		break;
	case LIM_MEMORY:
		rc = ubc_set_res(lcontext->lve_ub, LVE_MEM_LIMIT_RES, new);
		if (rc)
			LVE_ERR("ubc set virtual memory limit %d\n", rc);
		break;
	case LIM_MEMORY_PHY:
		rc = ubc_set_res(lcontext->lve_ub, LVE_MEM_PHY_LIMIT_RES, new);
		if (rc)
			LVE_ERR("ubc set phys memory limit %d\n", rc);
		break;
	case LIM_NPROC:
		rc = ubc_set_res(lcontext->lve_ub, LVE_NPROC_LIMIT_RES, new);
		if (rc)
			LVE_ERR("ubc set nproc limit %d\n", rc);
		break;
	case LIM_ENTER:
		/* no special handling in this layer */
		break;
	default:
		BUG();
	}
#endif
	return rc;
}

#include <linux/cred.h>
/* mostly copy&paste from audio_write()/lve-kernel-el6 */
static int os_set_dac_override(void)
{
	struct cred *new;

	if (cap_raised(current_cap(), CAP_DAC_OVERRIDE))
		return -EALREADY;

	new = prepare_creds();
	cap_raise(new->cap_effective, CAP_DAC_OVERRIDE);
	commit_creds(new);

	return 0;
}

static void os_clear_dac_override(void)
{
	struct cred *new = prepare_creds();

	cap_lower(new->cap_effective, CAP_DAC_OVERRIDE);
	commit_creds(new);
}

/* enter to memory / io control usage */
int os_resource_push(struct task_struct *task, struct c_private *lcontext)
{
	int rc = 0, rc2;

	if (lcontext->lve_ub == NULL)
		return 0;
	rc2 = os_set_dac_override();

	rc = lve_call(lve_ub_attach_task(lcontext->lve_ub, task),
			LVE_FAIL_UB_ATTACH_TASK, -ENOMEM);

	if (rc2 == 0)
		os_clear_dac_override();

	if (rc != 0)
		LVE_ERR("push ub failed\n");

	return rc;
}

int os_cpu_enter(struct task_struct *task, struct c_private *lcontext)
{
	int rc = 0;

#ifndef LVE_PER_VE
	rc = lve_call(lve_cgroup_kernel_attach(lcontext->cgrp[CG_CPU_GRP], task),
			LVE_FAIL_CGRP_ATTACH_TSK, -ENOMEM);
	if (rc != 0) {
		LVE_ERR("cpu attach task failed with %d\n", rc);
		goto out;
	}
out:
#endif /* LVE_PER_VE */

	return rc;
}

static int os_lvp_cpu_init(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);
	char name[MAX_GRP_NAMESZ];

	/** XXX hack until we will have a 2 level cpu scheduler */
	if (lvp->lvp_id == 0)
		lvpp->lve_cpu_root = cmnt[CPU_SUBSYS].cgrp_root;

	snprintf(name, sizeof(name), "%d", lvp->lvp_id);
	/* We hold a reference to the parent CPU cgroup so it exists */
	c->cgrp[CG_CPU_GRP] = lve_cgroup_kernel_open(cmnt[CPU_SUBSYS].cgrp_root, 0,
					name);
	if (IS_ERR(c->cgrp[CG_CPU_GRP])) {
		LVE_ERR("Can't open cgroup %s, err %lu \n", name,
			PTR_ERR(c->cgrp[CG_CPU_GRP]));
		return PTR_ERR(c->cgrp[CG_CPU_GRP]);
	}

	c->lve_ub = lve_get_beancounter_byuid(lvp->lvp_id, 1);
	if (c->lve_ub == NULL) {
		lve_cgroup_kernel_close(c->cgrp[CG_CPU_GRP]);
		LVE_ERR("Can't allocate UBC for LVP %s\n", name);
		return -ENOMEM;
	}

	if (lvp->lvp_id != 0) {
		lvpp->lve_cpu_root = c->cgrp[CG_CPU_GRP];
	}

	atomic_inc(&lvpp->lve_cpu_root->count);

	LVE_DBG("cpu root %p host %p\n", lvpp->lve_cpu_root,
			cmnt[CPU_SUBSYS].cgrp_root);

	return 0;
}

static void os_lvp_cpu_fini(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);

	/** XXX hack until we will have a 2 level cpu scheduler */
	if (lvp->lvp_id == 0) {
		lvpp->lve_cpu_root = c->cgrp[CG_CPU_GRP];
	}

	if (lvpp->lve_cpu_root)
		lve_cgroup_kernel_close(lvpp->lve_cpu_root);
	put_beancounter(c->lve_ub);
}

static int os_global_cpu_init(void)
{
	/* We don't take a reference here, so won't need to drop it */
	cmnt[CPU_SUBSYS].cgrp_root = lve_cgroup_get_root(cmnt[CPU_SUBSYS].mnt_root);
	BUG_ON(cmnt[CPU_SUBSYS].cgrp_root == NULL);
	return 0;
}

static void os_global_cpu_fini(void)
{
}

static int os_global_mem_init(void)
{
	cmnt[MEM_SUBSYS].cgrp_root = lve_cgroup_get_root(cmnt[MEM_SUBSYS].mnt_root);
	BUG_ON(cmnt[MEM_SUBSYS].cgrp_root == NULL);
	return 0;
}

static void os_global_mem_fini(void)
{
}

static int os_lvp_io_init(struct lvp_ve_private *lvp)
{
	if (lvp->lvp_id != ROOT_LVP) {
		struct c_private *c = lve_private(lvp->lvp_default);
		return ovz_io_limits_init(c->lve_ub);
	}

	return 0;
}

static void os_lvp_io_fini(struct lvp_ve_private *lvp)
{
}

static int os_global_io_init(void)
{
	cmnt[BLK_SUBSYS].cgrp_root = lve_cgroup_get_root(cmnt[BLK_SUBSYS].mnt_root);
	BUG_ON(cmnt[BLK_SUBSYS].cgrp_root == NULL);

	return ovz_iolimits_init();
}

static void os_global_io_fini(void)
{
	ovz_iolimits_exit();
}

static int os_global_freezer_init(void)
{
#ifndef LVE_PER_VE
	cmnt[FREEZER_SUBSYS].cgrp_root = lve_cgroup_get_root(cmnt[FREEZER_SUBSYS].mnt_root);
	BUG_ON(cmnt[FREEZER_SUBSYS].cgrp_root == NULL);

#endif
	return 0;
}

static void os_global_freezer_fini(void)
{
	/* TODO ??? */
}

static int os_lvp_freezer_init(struct lvp_ve_private *lvp)
{
#ifndef LVE_PER_VE
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);
	struct cgroup *cgrp_root = cmnt[FREEZER_SUBSYS].cgrp_root;

	BUG_ON(cgrp_root == NULL);

	/* Use root freezer cgroup */
	atomic_inc(&cgrp_root->count);
	lvpp->lve_freezer_root = cgrp_root;

	c->cgrp[CG_FREEZER_GRP] =  lvpp->lve_freezer_root;

#endif
	return 0;
}

static void os_lvp_freezer_fini(struct lvp_ve_private *lvp)
{
#ifndef LVE_PER_VE
	struct lvp_private *lvpp = os_lvp_private(lvp);
	lve_cgroup_kernel_close(lvpp->lve_freezer_root);
#endif
}

int os_freezer_enter(struct task_struct *task, struct c_private *lcontext)
{
	int rc = 0;

#ifndef LVE_PER_VE
	rc = lve_call(lve_cgroup_kernel_attach(lcontext->cgrp[CG_FREEZER_GRP], task),
			LVE_FAIL_CGRP_ATTACH_TSK, -ENOMEM);
	if (rc < 0) {
		LVE_ERR("freezer: attach task failed with %d\n", rc);
		goto out;
	}
out:
#endif
	return rc;
}

int os_freezer_freeze(struct light_ve *ve)
{
	int rc = -ENOSYS;
#ifndef LVE_PER_VE
	struct c_private *c = lve_private(ve);
	struct cgroup *cgrp = c->cgrp[CG_FREEZER_GRP];
	unsigned long reclaim_est = 0UL, reclaim_total = 0UL;

	LVE_DBG("freezer: lve_id = %u\n", ve->lve_id);

	/* Temporarily disable SWAP limit */
	rc = ubc_set_res(c->lve_ub, UB_SWAPPAGES, 0);
	if (rc < 0) {
		LVE_ERR("freezer: failed to update swappages limit, rc=%d\n", rc);
		return rc;
	}

	rc = lve_freezer_change_state(cgrp, CGROUP_FROZEN);
	if (rc < 0) {
		LVE_ERR("freezer: cannot freeze all the tasks in the LVE, rc = %d\n", rc);
		lve_freezer_change_state(cgrp, CGROUP_THAWED);
		return rc;
	}

	/* TODO: may be wait some time for tasks to be frozen */

	reclaim_est = c->lve_ub->ub_parms[UB_PHYSPAGES].limit;

	while (reclaim_total < reclaim_est) {
		unsigned long reclaim_iter = lve_try_to_free_gang_pages(get_ub_gs(c->lve_ub),
						GFP_HIGHUSER_MOVABLE);
		if (reclaim_iter == 0UL) {
			LVE_DBG("freezer: the reclaiming is finished\n");
			break;
		}

		reclaim_total += reclaim_iter;
	}

	LVE_DBG("freezer: reclaimed %lu pages total\n", reclaim_total);

	/* Put the limits back */
	rc = init_beancounter_swap_limits(c->lve_ub);
	if (rc < 0)
		LVE_ERR("freezer: failed to update swappages limit, rc=%d\n", rc);

#endif
	return rc;
}

int os_freezer_thaw(struct light_ve *ve)
{
#ifndef LVE_PER_VE
	struct c_private *c = lve_private(ve);
	struct cgroup *cgrp = c->cgrp[CG_FREEZER_GRP];
	struct cgroup_iter it;
	struct task_struct *tsk;

	LVE_DBG("freezer: lve_id = %u\n", ve->lve_id);

	cgroup_iter_start(cgrp, &it);

	while ((tsk = cgroup_iter_next(cgrp, &it)) != NULL) {
		struct mm_struct *mm = tsk->mm;
		struct vm_area_struct *vma;

		/*
		 * Its safe to unlock here, because:
		 * 1. The cgroup cannot be destroyed as we hold a refernce
		 * 2. Frozen tasks cannot leave the cgroup, so current "tsk" is in safety
		 * 3. In case of concurrent "enter" new tasks are added to the list,
		 * which is serialized with cgroup_iter_next() by css_set_lock.
		 */
		read_unlock(&lve_css_set_lock);

		down_read(&mm->mmap_sem);
		for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
			/*
			 * Skip file-backed and shared mem. vma's to avoid faulting
			 * of previously absent pages (before freezing), so let them
			 * fault on-demand.
			 *
			 * This can be especially harmful when large memory mapped files
			 * are used. If a process mmap'ed a large region, for instance a few gigs,
			 * but actualy pinned a couple pages at the moment of freezing, then
			 * forced pre-faulting of a whole mmap'ed region would be nosense.
			 *
			 * Note: VM_IO and VM_PFNMAP are filetered in __get_user_pages()
			 */
			if (vma->vm_file != NULL) {
				LVE_DBG("skip file-backed or shared mem. VMA: [0x%lx - 0x%lx]\n",
					vma->vm_start, vma->vm_end);
				continue;
			}

			if (make_pages_present_ext(mm, vma->vm_start,
							vma->vm_end, NULL) < 0) {
				LVE_DBG("cannot make VMA present: [0x%lx - 0x%lx]\n",
					vma->vm_start, vma->vm_end);

			}
		}

		up_read(&mm->mmap_sem);
		read_lock(&lve_css_set_lock);
	}
	cgroup_iter_end(cgrp, &it);

	lve_freezer_change_state(cgrp, CGROUP_THAWED);

	return 0;
#else
	return -ENOSYS;
#endif
}

int os_lvp_init(struct lvp_ve_private *lvp, void *data)
{
	int rc;
#ifdef LVE_PER_VE
	struct ve_struct *env = data;
#endif

	rc = os_lvp_cpu_init(lvp);
	if (rc < 0)
		return rc;

	rc = os_lvp_io_init(lvp);
	if (rc < 0)
		goto out_io;

	rc = os_lvp_freezer_init(lvp);
	if (rc < 0)
		goto out_io;
#ifdef LVE_PER_VE
	if (env == NULL)
		env = get_ve0();

	env->lve = lvp;
	lvp->lvp_ve = env;
#endif

	return 0;

out_io:
	os_lvp_cpu_fini(lvp);
	return rc;
}

void os_lvp_fini(struct lvp_ve_private *lvp)
{
	os_lvp_freezer_fini(lvp);
	os_lvp_io_fini(lvp);
	os_lvp_cpu_fini(lvp);
}

int os_global_init(void)
{
	int rc;

	LVE_ENTER("os_global_init");

	memset(cmnt, 0, sizeof(*cmnt) * NR_SUBSYS);

	rc = mount_cgroup_root_fs(cmnt);
	if (rc)
		return rc;

#ifdef LVE_PER_VE
	mutex_lock(&ve_list_lock);
#endif
	os_global_cpu_init();
	os_global_mem_init();
	os_global_io_init();
	os_global_freezer_init();
#ifdef LVE_PER_VE
	init_ve_init_exit_chain();

	mutex_unlock(&ve_list_lock);
#endif
	return 0;
}

void os_global_fini(void)
{
#ifdef LVE_PER_VE
	cleanup_ve_init_exit_chain();

	get_ve0()->lve = NULL;
	root_lvp->lvp_ve = NULL;
#endif
	/* XXX need destroy all LVP */
	os_global_freezer_fini();
	os_global_io_fini();
	os_global_mem_fini();
	os_global_cpu_fini();

	umount_cgroup_root_fs(cmnt);
}
