#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/ve_proto.h>
#include <linux/mount.h>

#include <linux/cgroup.h>
#include <linux/cpuset.h>
#include <linux/memcontrol.h>
#include <linux/freezer.h>
#include <linux/swap.h>
#include <bc/beancounter.h>
#include <linux/virtinfo.h>

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

static bool lve_kill_on_shrink = 1;
module_param(lve_kill_on_shrink, bool, 0644);

struct params cpu_params[] = {
	[ PARAM_CPU_STAT ] = { "cpuacct.usage", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPU_LIMIT] = { "cpu.rate", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPU_CHWT ] = { "cpu.shares", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPUS_LIMIT ] = { "cpu.nr_cpus", &cmnt[CPUSET_SUBSYS].mnt_root }
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
static int os_mem_cgroup_disable_swappiness(struct cgroup *mem_cgrp)
{
	int ret = 0;

	if (mem_swappiness == true)
		ret = cgrp_param_open_write_string(cmnt[MEM_SUBSYS].mnt_root,
			mem_cgrp, "memory.swappiness", "0", 1);
	return ret;
}

static int os_mem_disable_swapping(struct c_private *lcontext)
{
	struct cgroup_subsys_state *css;
	int rc;

	css = lve_ub_get_css(lcontext->lve_ub, UB_MEM_CGROUP);
	rc = os_mem_cgroup_disable_swappiness(css->cgroup);
	css_put(css);

	return rc;
}

static int os_resource_extra_init(struct c_private *lcontext, char *name)
{
	struct cgroup *_lve_freezer_cgroup_root = cmnt[FREEZER_SUBSYS].cgrp_root;
	int rc;

	rc = os_mem_disable_swapping(lcontext);
	if (rc < 0)
		LVE_WARN("failed to disable swapping, physmem can swap out\n");

	if (_lve_freezer_cgroup_root) {
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

#if !defined(LVE_PER_VE)
static int os_cpuset_init(struct vfsmount *mnt, struct cgroup *cgrp)
{
	char buf[128];
	int count, rc1, rc2;

	count = cpulist_scnprintf(buf, sizeof(buf), cpu_active_mask);
	if (count < sizeof(buf) - 1) {
		rc1 = cgrp_param_open_write_string(mnt, cgrp, "cpuset.cpus",
						   buf, count);
	} else {
		LVE_ERR("cpu list is too large\n");
		rc1 = -E2BIG;
	}

	count = nodelist_scnprintf(buf, sizeof(buf), node_states[N_MEMORY]);
	if (count < sizeof(buf) - 1) {
		rc2 = cgrp_param_open_write_string(mnt, cgrp, "cpuset.mems",
						   buf, count);
	} else {
		LVE_ERR("node list is too large\n");
		rc2 = -E2BIG;
	}

	return rc1 ?: rc2;
}
#endif

int os_resource_init(struct light_ve *ve __attribute__((unused)))
{
#ifndef LVE_PER_VE
	struct lvp_ve_private *lvp = ve->lve_lvp;
	uint32_t id = NODEID_ENCODE(lvp->lvp_id, ve->lve_id);
	struct cgroup *cgrp = NULL;
	struct c_private *lcontext = lve_private(ve);
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);
	char name[MAX_GRP_NAMESZ];


	lcontext->flags = get_flags();
	snprintf(name, sizeof(name)-1 , LVE_FMT, id);
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

	lcontext->cgrp[CG_CPUSET_GRP] = NULL;

	if ((lvp->lvp_id == ROOT_LVP) || (lvp->lvp_id > ROOT_LVP && ve->lve_id == ROOT_LVE)) {
		cgrp = lve_call(lve_cgroup_kernel_open(lvpp->lve_cpuset_root,
				LVE_CGRP_CREAT | LVE_CGRP_EXCL, name),
				LVE_FAIL_CGRP_OPEN, ERR_PTR(-EEXIST));
		if (IS_ERR(cgrp)) {
			LVE_ERR("lve_cpuset_root %s err %ld\n",
				name, PTR_ERR(cgrp));
			return PTR_ERR(cgrp);
		}
		lcontext->cgrp[CG_CPUSET_GRP] = cgrp;
		os_cpuset_init(cmnt[CPUSET_SUBSYS].mnt_root, cgrp);
		/* XXXX need to have a guaranted it on reseller cpuset */
	}
	LVE_DBG("cpuset group %p\n", lcontext->cgrp[CG_CPUSET_GRP]);

#ifndef HAVE_SUB_UBC
	/* like native OpenVZ */
	lcontext->lve_ub = lve_call(lve_get_beancounter_by_name(name, 1),
				LVE_FAIL_GET_SUB_UB_BYUID, NULL);
#else
	lcontext->lve_ub = lve_call(get_sub_beancounter_by_name(c->lve_ub, name, 1),
				LVE_FAIL_GET_SUB_UB_BYUID, NULL);
#endif
	if (IS_ERR_OR_NULL(lcontext->lve_ub)) {
		LVE_ERR("can't create UBC for context %u, err %ld\n",
			id, PTR_ERR(lcontext->lve_ub));
		return -ENOMEM;
	}
	os_resource_extra_init(lcontext, name);

	cgrp_populate_dir(lcontext->cgrp[CG_CPU_GRP], lcontext->cpu_filps,
		cpu_params, ARRAY_SIZE(cpu_params));

	/* no init ubc nolimit needs as it done as part of ubc creation */

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

	cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPUS_LIMIT], 0);
	cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPU_LIMIT], 0);

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

static void lve_cgroup_release(char *name, struct cgroup *cgrp, int flags)
{
	lve_cgroup_kernel_close(cgrp);
	if (flags == LVE_CGRP_CREAT) {
		int ret = lve_cgroup_kernel_remove(cgrp->parent, name);
		LVE_DBG("cgroup %s is removed, ret=%d\n", name, ret);
	}
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
			lve_cgroup_release(name, lcontext->cgrp[i],
				lcontext->flags);
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
	struct light_ve *lve = os_lve(lcontext);
	struct light_ve *reseller = NULL;

	/* Check if we are changing limits for a reseller */
	if (lve != lve->lve_lvp->lvp_default)
		reseller = lve->lve_lvp->lvp_default;

	switch (custom) {
	case LIM_CPU:
		if (reseller && reseller->lve_limits[LIM_CPU] != 0)
			lim = min(new, reseller->lve_limits[LIM_CPU]);
		else
			lim = new;
		/*
		 * DIV_ROUND_UP needs for case when new[LIM_CPU] is
		 * lesser than 10, in such case divide without round up
		 * produce zero limit.
		 */
		lim = DIV_ROUND_UP(lim, 10) * 1024 / 1000;
		LVE_DBG("set fairshed rate to %u\n", lim);
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPU_LIMIT], lim),
				LVE_FAIL_WRT_CPU_LIM, -EINVAL);
		break;
	case LIM_CPUS:
		if (reseller && reseller->lve_limits[LIM_CPUS] != 0)
			lim = min(new, reseller->lve_limits[LIM_CPUS]);
		else
			lim = new;
		LVE_DBG("set cpu affinity to %d\n",lim);
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPUS_LIMIT],
				lim), LVE_FAIL_WRT_CPUS_LIM, -EINVAL);
		break;
	case LIM_CPU_WEIGHT:
		if (reseller && reseller->lve_limits[LIM_CPU_WEIGHT] != 0)
			lim = min(new, reseller->lve_limits[LIM_CPU_WEIGHT]);
		else
			lim = new;
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPU_CHWT],
				lim *1024/100), LVE_FAIL_WRT_CPU_CHWT, -EINVAL);
		break;
	case LIM_IO:
		rc = lve_call(ovz_set_io_limit(lcontext->lve_ub,
				new << 10, 0),
				LVE_FAIL_IO_SET_LIM, -ENOMEM);
		break;
	case LIM_IOPS:
		lve_call(ovz_set_iops_limit(lcontext->lve_ub,
			 new, 0),
			 LVE_FAIL_IO_SET_LIM, -ENOMEM);
		break;
	case LIM_MEMORY:
		LVE_DBG("set mem to %u\n", new);
		rc = ubc_set_res(lcontext->lve_ub, LVE_MEM_LIMIT_RES, new);
		if (rc)
			LVE_ERR("ubc set virtual memory limit %d\n", rc);
		break;
	case LIM_MEMORY_PHY:
		LVE_DBG("set phy mem to %u\n", new);
		rc = ubc_set_res(lcontext->lve_ub, LVE_MEM_PHY_LIMIT_RES, new);
		if (rc)
			LVE_ERR("ubc set phys memory limit %d\n", rc);

		if (rc != -EBUSY || !lve_kill_on_shrink)
			break;

		LVE_WARN("lve %u threads will be killed to reduce physmem"
			 " usage below the new limit\n", lve->lve_id);
		lve_kill_all_threads(0, lve->lve_id);
		schedule_timeout_killable(msecs_to_jiffies(10));

		rc = ubc_set_res(lcontext->lve_ub, LVE_MEM_PHY_LIMIT_RES, new);

		break;
	case LIM_NPROC:
		LVE_DBG("set nproc to %u\n", new);
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

static int __lve_ub_attach_task(struct user_beancounter *ub, struct task_struct *tsk)
{
	int ret = 0;
	struct user_beancounter *old_ub = tsk->task_bc.exec_ub;
	struct cgroup_subsys_state *css;

	if (ub == old_ub)
		goto out;

	css = lve_ub_get_css(ub, UB_MEM_CGROUP);
	ret = lve_cgroup_kernel_attach(css->cgroup, tsk);
	css_put(css);
	if (ret)
		goto out;
	ret = lve_cgroup_kernel_attach(ub->css.cgroup, tsk);
	if (ret)
		goto fail_ub;
out:
	return ret;
fail_ub:
	css = lve_ub_get_css(old_ub, UB_MEM_CGROUP);
	lve_cgroup_kernel_attach(css->cgroup, tsk);
	css_put(css);
	goto out;
}

/* enter to memory / io control usage */
int os_resource_push(struct task_struct *task, struct c_private *lcontext)
{
	int rc = 0, rc2;

	if (lcontext->lve_ub == NULL)
		return 0;
	rc2 = os_set_dac_override();

	rc = lve_call(__lve_ub_attach_task(lcontext->lve_ub, task),
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
	rc = lve_call(lve_cgroup_kernel_attach(lcontext->cgrp[CG_CPUSET_GRP], task),
			LVE_FAIL_CGRP_ATTACH_TSK, -ENOMEM);
	if (rc != 0)
		LVE_ERR("cpuset attach task failed with %d\n", rc);
out:
#endif /* LVE_PER_VE */

	return rc;
}

static int os_lvp_cpu_init(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);
	char name[MAX_GRP_NAMESZ];


	memset(name, 0, sizeof(name));

	/** XXX hack until we will have a 2 level cpu scheduler */
	if (lvp->lvp_id == ROOT_LVP) {
		/* ubc0 name is fixed. */
		snprintf(name, sizeof(name)-1, "%u", lvp->lvp_id);

		lvpp->lve_cpu_root = cmnt[CPU_SUBSYS].cgrp_root;
		lvpp->lve_cpuset_root = cmnt[CPUSET_SUBSYS].cgrp_root;

		c->cgrp[CG_CPU_GRP] = lvpp->lve_cpu_root;
		atomic_inc(&c->cgrp[CG_CPU_GRP]->count);

		c->cgrp[CG_CPUSET_GRP] = lvpp->lve_cpuset_root;
		atomic_inc(&c->cgrp[CG_CPUSET_GRP]->count);

		c->flags = 0;

		goto out_lvpp_ref;
	}
	snprintf(name, sizeof(name)-1, LVP_FMT, lvp->lvp_id);

	c->flags = get_flags();
	/* We hold a reference to the parent CPU cgroup so it exists */
	c->cgrp[CG_CPU_GRP] = lve_cgroup_kernel_open(cmnt[CPU_SUBSYS].cgrp_root,
		c->flags, name);
	if (IS_ERR(c->cgrp[CG_CPU_GRP])) {
		LVE_ERR("Can't open cgroup %s, err %lu \n", name,
			PTR_ERR(c->cgrp[CG_CPU_GRP]));
		return PTR_ERR(c->cgrp[CG_CPU_GRP]);
	}

	c->cgrp[CG_CPUSET_GRP] = lve_cgroup_kernel_open(cmnt[CPUSET_SUBSYS].cgrp_root,
		c->flags, name);
	if (IS_ERR(c->cgrp[CG_CPUSET_GRP])) {
		LVE_ERR("Can't open cgroup %s, err %lu\n", name,
			PTR_ERR(c->cgrp[CG_CPUSET_GRP]));
		lve_cgroup_kernel_close(c->cgrp[CG_CPU_GRP]);
		return PTR_ERR(c->cgrp[CG_CPUSET_GRP]);
	}

	cgrp_populate_dir(c->cgrp[CG_CPU_GRP], c->cpu_filps,
		cpu_params, ARRAY_SIZE(cpu_params));
out_lvpp_ref:
	c->lve_ub = lve_get_beancounter_by_name(name, 1);
	if (IS_ERR_OR_NULL(c->lve_ub)) {
		lve_cgroup_kernel_close(c->cgrp[CG_CPU_GRP]);
		lve_cgroup_kernel_close(c->cgrp[CG_CPUSET_GRP]);

		LVE_ERR("Can't allocate UBC for LVP %s\n", name);
		return -ENOMEM;
	}

	if (lvp->lvp_id != 0) {
		lvpp->lve_cpu_root = c->cgrp[CG_CPU_GRP];
		lvpp->lve_cpuset_root = c->cgrp[CG_CPUSET_GRP];
	}
	atomic_inc(&lvpp->lve_cpu_root->count);
	atomic_inc(&lvpp->lve_cpuset_root->count);

	LVE_DBG("cpu root %p host %p\n", lvpp->lve_cpu_root,
			cmnt[CPU_SUBSYS].cgrp_root);

	LVE_DBG("cpuset root %p host %p\n", lvpp->lve_cpuset_root,
			cmnt[CPU_SUBSYS].cgrp_root);

	return 0;
}

static void os_lvp_cpu_fini(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);

	/** XXX hack until we will have a 2 level cpu scheduler */
	if (lvp->lvp_id == ROOT_LVP) {
		lvpp->lve_cpu_root = c->cgrp[CG_CPU_GRP];
		lvpp->lve_cpuset_root = c->cgrp[CG_CPUSET_GRP];
	}

	if (lvpp->lve_cpu_root)
		lve_cgroup_kernel_close(lvpp->lve_cpu_root);
	if (lvpp->lve_cpuset_root)
		lve_cgroup_kernel_close(lvpp->lve_cpuset_root);

	put_beancounter(c->lve_ub);
}

static int os_global_cpu_init(void)
{
	/* We don't take a reference here, so won't need to drop it */
	cmnt[CPU_SUBSYS].cgrp_root = lve_cgroup_get_root(cmnt[CPU_SUBSYS].mnt_root);
	BUG_ON(cmnt[CPU_SUBSYS].cgrp_root == NULL);

	cmnt[CPUSET_SUBSYS].cgrp_root = lve_cgroup_get_root(cmnt[CPUSET_SUBSYS].mnt_root);
	BUG_ON(cmnt[CPUSET_SUBSYS].cgrp_root == NULL);

	return 0;
}

static void os_global_cpu_fini(void)
{
}

static int os_global_mem_init(void)
{
#ifndef LVE_PER_VE
	int ret;
#endif

	cmnt[MEM_SUBSYS].cgrp_root = lve_cgroup_get_root(cmnt[MEM_SUBSYS].mnt_root);
	BUG_ON(cmnt[MEM_SUBSYS].cgrp_root == NULL);

#ifndef LVE_PER_VE
	ret = cgrp_param_open_write_string(cmnt[MEM_SUBSYS].mnt_root,
			cmnt[MEM_SUBSYS].cgrp_root, "memory.use_hierarchy", "1",
			1);
	if (ret < 0)
		LVE_ERR("can't set cgroup hierarchy\n");
#endif

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

static int os_lvp_mem_init(struct lvp_ve_private *lvp)
{
	struct c_private *c = lve_private(lvp->lvp_default);
	int rc;

	rc = os_mem_disable_swapping(c);
	if (rc < 0)
		LVE_WARN("failed to disable swapping, physmem can swap out\n");

	return 0;
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

	/* Use root cgroup */
	atomic_inc(&cgrp_root->count);
	lvpp->lve_freezer_root = cgrp_root;

	c->cgrp[CG_FREEZER_GRP] =  lvpp->lve_freezer_root;
#endif
	return 0;
}

static void os_lvp_freezer_fini(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	lve_cgroup_kernel_close(lvpp->lve_freezer_root);
}

int os_freezer_enter(struct task_struct *task, struct c_private *lcontext)
{
	int rc = 0;

#ifndef LVE_PER_VE
	rc = lve_call(lve_cgroup_kernel_attach(lcontext->cgrp[CG_FREEZER_GRP], task),
			LVE_FAIL_CGRP_ATTACH_TSK, -ENOMEM);
	if (rc != 0) {
		LVE_ERR("freezer: attach task failed with %d\n", rc);
		goto out;
	}

out:
#endif
	return rc;
}

static int freezer_change_state(struct cgroup *cgrp, bool freeze)
{
	int rc = 0;
	/*
	 * We need to wait until tasks enter "refrigerator"
	 *
	 * TODO: the total amount of time should be proportional
	 * to tasks count in the cgroup, leave it a const for now.
	 */
	int wait_count = 10;
	const char *str = freeze ? "FROZEN" : "THAWED";
	const char *freezer_param = "freezer.state";

	/* Should be big enough to contain "FREEZING" */
	char buf[10];
	struct vfsmount *mnt = cmnt[FREEZER_SUBSYS].mnt_root;

	rc = cgrp_param_open_write_string(mnt, cgrp, freezer_param,
						str, strlen(str));
	if (rc < 0 || !freeze)
		goto out;

	while (wait_count--) {
		rc = cgrp_param_open_read_string(mnt, cgrp, freezer_param,
							buf, sizeof(buf));
		if (rc < 0)
			goto out;

		if (strncmp(buf, "FROZEN", strlen("FROZEN")) == 0)
			goto out;

		schedule_timeout_killable(msecs_to_jiffies(10));
	}

	rc = -EBUSY;
out:
	return rc;
}

int os_freezer_freeze(struct light_ve *ve)
{
	int rc = -ENOSYS;
#ifndef LVE_PER_VE
	struct c_private *c = lve_private(ve);
	struct cgroup *cgrp = c->cgrp[CG_FREEZER_GRP];
	struct mem_cgroup *memcg = c->cgrp[CG_MEM_GRP] ?
		lve_mem_cgroup_from_cont(c->cgrp[CG_MEM_GRP]) : NULL;

	unsigned long reclaim_est = 0UL, reclaim_total = 0UL;

	LVE_DBG("freezer: lve_id = %u\n", ve->lve_id);

	/* Temporarely disable SWAP limit */
	rc = ubc_set_res(c->lve_ub, UB_SWAPPAGES, 0);
	if (rc < 0) {
		LVE_ERR("freezer: failed to update swappages limit, rc=%d\n", rc);
		return rc;
	}

	rc = freezer_change_state(cgrp, true);
	if (rc < 0) {
		LVE_ERR("freezer: cannot change freezer state, rc = %d\n", rc);
		return freezer_change_state(cgrp, false);
	}

	reclaim_est = c->lve_ub->ub_parms[UB_PHYSPAGES].limit;

	while (memcg && reclaim_total < reclaim_est) {
		unsigned long reclaim_iter = lve_try_to_free_mem_cgroup_pages(memcg,
						reclaim_est - reclaim_total,
						GFP_KERNEL, 0);
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

	freezer_change_state(cgrp, false);
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

	rc = os_lvp_mem_init(lvp);
	if (rc < 0)
		goto out_mem;

	if (lvp->lvp_id == ROOT_LVP) {
		rc = os_lvp_freezer_init(lvp);
		if (rc < 0)
			goto out_io;
	}
#ifdef LVE_PER_VE
	if (env == NULL)
		env = get_ve0();

	env->lve = lvp;
	lvp->lvp_ve = env;
#endif

	return 0;
out_mem:
	os_lvp_io_fini(lvp);
out_io:
	os_lvp_cpu_fini(lvp);
	return rc;
}

void os_lvp_fini(struct lvp_ve_private *lvp)
{
	if (lvp->lvp_id == ROOT_LVP) {
		os_lvp_freezer_fini(lvp);
		os_lvp_io_fini(lvp);
	}
	os_lvp_cpu_fini(lvp);
}

static struct static_key *key = &memcg_kmem_enabled_key;

static inline void os_static_key_slow_inc(void)
{
	atomic_inc(&key->enabled);
}

static inline void os_static_key_slow_dec(void)
{
	atomic_dec(&key->enabled);
}

#ifdef VIRTINFO_MEM_FAILCNT
static int os_memcg_phys_pages_failcnt_cb(void *arg)
{
	unsigned long failcnt = (unsigned long)arg;
	LVE_DBG("failcnt=%lu\n", failcnt);
	lve_resource_fail(current, LVE_RESOURCE_FAIL_MEM_PHY);
	return 0;
}

static int os_memcg_ncall(struct vnotifier_block *self,
	unsigned long event, void *arg, int old_ret)
{
	int ret = 0;

	switch (event) {
	case VIRTINFO_MEM_FAILCNT:
		ret = os_memcg_phys_pages_failcnt_cb(arg);
		break;
	default:
		break;
	}
	return ret;
}

static struct vnotifier_block os_memcg_nb = {
	.notifier_call = os_memcg_ncall,
};
#endif /* VIRTINFO_MEM_FAILCNT */

static int os_memcg_nb_init(void)
{
#ifdef VIRTINFO_MEM_FAILCNT
	virtinfo_notifier_register(VITYPE_GENERAL, &os_memcg_nb);
#endif
	return 0;
}

static void os_memcg_nb_fini(void)
{
#ifdef VIRTINFO_MEM_FAILCNT
	virtinfo_notifier_unregister(VITYPE_GENERAL, &os_memcg_nb);
#endif
}

int os_global_init(void)
{
	int rc;

	LVE_ENTER("os_global_init");
	os_static_key_slow_inc();

	memset(cmnt, 0, sizeof(*cmnt) * NR_SUBSYS);

	rc = mount_cgroup_root_fs(cmnt);
	if (rc)
		return rc;

#ifdef LVE_PER_VE
	mutex_lock(&ve_list_lock);
	if (nr_ve > 1) {
		mutex_unlock(&ve_list_lock);
		umount_cgroup_root_fs(cmnt);
		os_static_key_slow_dec();
		LVE_ERR("modlve need load before container start\n");
		return -ENOSYS;
	}
#endif

	os_global_cpu_init();
	os_global_mem_init();
	os_global_io_init();

	os_memcg_nb_init();

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

	os_memcg_nb_fini();

	umount_cgroup_root_fs(cmnt);
	os_static_key_slow_dec();
	ub_fini_cgroup();
}
