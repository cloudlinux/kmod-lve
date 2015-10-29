#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/ve_proto.h>
#include <linux/module.h>
#include <linux/mount.h>

#include <linux/cgroup.h>

#include <linux/cpuset.h>

#include <bc/beancounter.h>

#include "../lve_kmod_c.h"
#include "lve-api.h"
#include "../kernel_exp.h"
#include "openvz_cgroups.h"
#include "openvz_cgroups_imp.h"
#include "cgroup_lib.h"
#include "../resource.h"
#include "../lve_debug.h"
#include "../light_ve.h"
#include "../lve_internal.h"

#ifdef HAVE_UB_CGROUP
#define blkio_grp(ubc)	((ubc)->ub_cgroup)
#endif

struct cgrp_mount cmnt[NR_SUBSYS];

static int (*os_io_set_limit)(struct user_beancounter *ub,
				unsigned speed, unsigned burst);
static int (*os_iops_set_limit)(struct user_beancounter *ub,
				unsigned speed, unsigned burst);

static unsigned long long (*os_io_get_usage)(struct user_beancounter *ub);
static unsigned long long (*os_iops_get_usage)(struct user_beancounter *ub);

struct params cpu_params[] = {
#ifdef CONFIG_CGROUP_CPUACCT
	[ PARAM_CPU_STAT ] = { "cpuacct.usage", &cmnt[CPU_SUBSYS].mnt_root },
#endif
	[ PARAM_CPU_LIMIT] = { "cpu.rate", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPU_CHWT ] = { "cpu.shares", &cmnt[CPU_SUBSYS].mnt_root },
	[ PARAM_CPUS_LIMIT ] = { "cpu.nr_cpus",
#if RHEL_MAJOR > 6
	&cmnt[CPUSET_SUBSYS].mnt_root
#else
	&cmnt[CPU_SUBSYS].mnt_root
#endif
	}
};

static unsigned long lve_swappages = 0;

unsigned int os_context_private_sz(void)
{
	return sizeof(struct c_private);
}

unsigned int os_lvp_private_sz(void)
{
	return sizeof(struct lvp_private);
}

#if defined(HAVE_LOADAVG_PTR)
int os_loadavg_global(struct light_ve *host)
{
	int load = 0;
	struct cgroup_iter it;
	struct task_struct *tsk;
	struct c_private *c = lve_private(host);
	struct cgroup *cgrp = c->cgrp[CG_CPU_GRP];

	cgroup_iter_start(cgrp, &it);
	while ((tsk = cgroup_iter_next(cgrp, &it))) {
		switch (tsk->state) {
		case TASK_RUNNING:
			load++;
			break;
		case TASK_UNINTERRUPTIBLE:
			load++;
			break;
		}
	}
	cgroup_iter_end(cgrp, &it);

	return load;
}

int os_loadavg_count(struct light_ve *ve)
{
	int load = 0;
	struct c_private *c = lve_private(ve);
	struct cgroup *cgrp = c->cgrp[CG_CPU_GRP];
	struct cgroup_iter it;
	struct task_struct *tsk;

	cgroup_iter_start(cgrp, &it);
	while ((tsk = cgroup_iter_next(cgrp, &it))) {
		switch (tsk->state) {
		case TASK_RUNNING:
			load++;
			goto out;
		case TASK_UNINTERRUPTIBLE:
			load++;
			goto out;
		}
	}
out:
	cgroup_iter_end(cgrp, &it);

	return load;
}

#endif

static unsigned long ubc_stat(struct user_beancounter *ub, int index, int *precharge)
{
	unsigned long held;

	held = ub->ub_parms[index].held;
	held = (held > precharge[index]) ? (held - precharge[index]) : 0;

	return held;
}

static void ubc_mem_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge)
{
	res->data = ubc_stat(ub, LVE_MEM_LIMIT_RES, precharge);
	res->fail = ub->ub_parms[LVE_MEM_LIMIT_RES].failcnt;
}

static void ubc_phys_mem_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge)
{
#ifndef HAVE_UB_GET_MEM_CGROUP_PARMS
	res->data = ubc_stat(ub, LVE_MEM_PHY_LIMIT_RES, precharge);
	res->fail = ub->ub_parms[LVE_MEM_PHY_LIMIT_RES].failcnt;
#else
	struct ubparm physpages;

	lve_ub_get_mem_cgroup_parms(ub, &physpages, NULL, NULL);

	LVE_DBG("physpages held=%lu maxheld=%lu failcnt=%lu\n",
			physpages.held, physpages.maxheld, physpages.failcnt);

	res->data = physpages.held;
	res->fail = physpages.failcnt;
#endif
}

static void ubc_nproc_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge)
{
	res->data = ubc_stat(ub, LVE_NPROC_LIMIT_RES, precharge);
	res->fail = ub->ub_parms[LVE_NPROC_LIMIT_RES].failcnt;
}

void os_resource_usage(struct c_private *private, struct lve_usage *buf)
{
	int precharge[UB_RESOURCES];
	__s64 data;

	if (!private->lve_ub)
		return;

#ifdef CONFIG_CGROUP_CPUACCT
	data = cgrp_param_get(private->cpu_filps[PARAM_CPU_STAT]);
	if(data > 0) {
		LVE_DBG("cpu usage "LPU64"\n", data);
		buf->data[RES_CPU].data = data;
	}
#endif

	lve_sync_ub_usage(private->lve_ub);
	lve_ub_prechange_snapshot(private->lve_ub, precharge);

	ubc_mem_stat(private->lve_ub, &buf->data[RES_MEM], precharge);
	ubc_phys_mem_stat(private->lve_ub, &buf->data[RES_MEM_PHY], precharge);
	ubc_nproc_stat(private->lve_ub, &buf->data[RES_NPROC], precharge);

	if (os_io_get_usage)
		buf->data[RES_IO].data = os_io_get_usage(private->lve_ub) >> 10;

	if (os_iops_get_usage)
		buf->data[RES_IOPS].data = os_iops_get_usage(private->lve_ub);
}

void os_resource_usage_clear(struct c_private *private)
{
	cgrp_param_set_u64(private->cpu_filps[PARAM_CPU_STAT], 0);
}

#ifndef UBC_CL_API
long __do_setublimit(struct user_beancounter *ub, unsigned long resource,
		unsigned long *new_limits)
{
	unsigned long ub_uid;

	/* OVZ native api */
#if RHEL_MAJOR < 7
	ub_uid = ub->ub_uid;
#else
	int ret = kstrtoul(ub->ub_name, 10, &ub_uid);
	if (ret < 0)
		return -EINVAL;
#endif
	return lve_setublimit(ub_uid, resource, new_limits);
}
#else
#define __do_setublimit lve_setublimit
#endif

#ifndef LVE_PER_VE
static void init_beancounter_nolimits(struct user_beancounter *ub)
{
	int k, rc;

	for (k = 0; k < UB_RESOURCES; k++) {
		ub->ub_parms[k].limit = UB_MAXVALUE;
		/* FIXME: whether this is right for physpages and guarantees? */
		ub->ub_parms[k].barrier = UB_MAXVALUE;
	}
	/* No guaranteed pages, vm_enough_memory() should perform checks */
	ub->ub_parms[UB_VMGUARPAGES].limit = 0;
	ub->ub_parms[UB_VMGUARPAGES].barrier = 0;

	rc = __do_setublimit(ub, UB_SWAPPAGES,
			     (unsigned long[2]){lve_swappages, lve_swappages});
	if (rc != 0)
		LVE_WARN("failed to update swappages limit, rc=%d\n", rc);

#ifdef HAVE_UB_RL_STEP
	/* Do not sleep in gang_rate_limit() */
	ub->rl_step = 0;
#endif
}

#ifdef HAVE_UB_SHORTAGE_CB
static void ubc_shortage(struct user_beancounter * ubc, int resource)
{
	int fail = 0;

	switch (resource) {
		case LVE_MEM_LIMIT_RES:
			fail = LVE_RESOURCE_FAIL_MEM;
			break;
		case LVE_MEM_PHY_LIMIT_RES:
			fail = LVE_RESOURCE_FAIL_MEM_PHY;
			break;
		case LVE_NPROC_LIMIT_RES:
			fail = LVE_RESOURCE_FAIL_NPROC;
			break;
		default:
			/* No need to handle unknown resources */
			return;
	}

	lve_resource_fail(current, fail);
}
#endif
#endif

#ifndef LVE_PER_VE
static int os_resource_extra_init(struct c_private *lcontext, char *name)
{
	struct cgroup *_lve_ub_cgroup_root = lve_get_ub_cgroup_root();
	struct cgroup *_lve_mem_cgroup_root = lve_get_mem_cgroup_root();

	if (_lve_mem_cgroup_root) {
#ifdef HAVE_IN_UB_MEMCG_ATTACH
		struct user_beancounter *old_ub = set_exec_ub(lcontext->lve_ub);
		current->in_ub_memcg_attach = 1;
#endif
		lcontext->cgrp[CG_MEM_GRP] = cgroup_kernel_open(_lve_mem_cgroup_root,
					CGRP_CREAT, name);
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
		lcontext->cgrp[CG_UB_GRP] = cgroup_kernel_open(_lve_ub_cgroup_root,
						CGRP_CREAT, name);
		if (IS_ERR(lcontext->cgrp[CG_UB_GRP])) {
			LVE_ERR("can't create ub_cgroup\n");
			lcontext->cgrp[CG_UB_GRP] = NULL;
		}
		LVE_DBG("ub_cgroup=%p\n", lcontext->cgrp[CG_UB_GRP]);
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

	snprintf(name, sizeof(name), "%u", id);
	cgrp = lve_call(cgroup_kernel_open(lvpp->lve_cpu_root, CGRP_CREAT |
				CGRP_EXCL, name), LVE_FAIL_CGRP_OPEN,
				ERR_PTR(-EEXIST));
	if (IS_ERR(cgrp)) {
		LVE_ERR("lve_cpu_root %s err %ld\n",
			name, PTR_ERR(cgrp));
		return PTR_ERR(cgrp);
	}
	lcontext->cgrp[CG_CPU_GRP] = cgrp;
	LVE_DBG("cpu group %p\n", cgrp);

#if RHEL_MAJOR > 6
	cgrp = lve_call(cgroup_kernel_open(lvpp->lve_cpuset_root,
				CGRP_CREAT | CGRP_EXCL, name),
				LVE_FAIL_CGRP_OPEN, ERR_PTR(-EEXIST));
	if (IS_ERR(cgrp)) {
		LVE_ERR("lve_cpuset_root %s err %ld\n",
			name, PTR_ERR(cgrp));
		return PTR_ERR(cgrp);
	}
	lcontext->cgrp[CG_CPUSET_GRP] = cgrp;
	LVE_DBG("cpuset group %p\n", cgrp);
#endif

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

#ifdef HAVE_UB_SHORTAGE_CB
	ub_set_shortage_cb(lcontext->lve_ub, ubc_shortage);
#endif
#endif

	return 0;
}

int os_resource_unlink(uint32_t id, struct c_private *lcontext)
{
	LVE_ENTER("(id=%u, lcontext=%p)\n", id, lcontext);

	if (lcontext->cgrp[CG_CPU_GRP] != NULL)
		cgrp_obfuscate(lcontext->cgrp[CG_CPU_GRP]);

#if RHEL_MAJOR > 6
	if (lcontext->cgrp[CG_CPUSET_GRP] != NULL)
		cgrp_obfuscate(lcontext->cgrp[CG_CPUSET_GRP]);
#endif

#ifdef HAVE_UB_CGROUP
	if (lcontext->lve_ub != NULL && blkio_grp(lcontext->lve_ub) != NULL)
		cgrp_obfuscate(blkio_grp(lcontext->lve_ub));
#endif

	return 0;
}

static void lve_cgroup_release(uint32_t id, char *name, struct cgroup *cgrp)
{
	cgroup_kernel_close(cgrp);
	if (id != ROOT_LVE)
		cgroup_kernel_remove(cgrp->parent, name);
}

int os_resource_fini(uint32_t id, struct c_private *lcontext)
{
	int rc = 0;
	int i;
	char name[20] = {0};

	LVE_ENTER("(id=%u, lcontext=%p)\n", id, lcontext);

	snprintf(name, sizeof(name)-1, "%u\n", id);

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
#ifdef HAVE_UB_SHORTAGE_CB
		ub_set_shortage_cb(lcontext->lve_ub, NULL);
#endif
		put_beancounter(lcontext->lve_ub);
		lcontext->lve_ub = LVE_POISON_PTR;
	}
#endif

	return rc;
}

static int ubc_set_res(struct c_private *lcontext, int res, uint32_t new)
{
	unsigned long limits[2];

	/* temporary disable a ubc limits for LVE in ve case */
	if (lcontext->lve_ub == NULL)
		return 0;

	if (new == 0) {
		limits[0] = limits[1] = UB_MAXVALUE;
	} else {
		limits[0] = UB_MAXVALUE;
		limits[1] = new;
	}
	return lve_call(__do_setublimit(lcontext->lve_ub, res, limits),
					LVE_FAIL_SETUBLIMIT, -EINVAL);
}

int os_resource_setup(struct c_private *lcontext, lve_limits_t new, uint32_t custom)
{
	int rc = 0;
#ifndef LVE_PER_VE
	int lim;

	if (custom & CUST_CPUS) {
		LVE_DBG("set cpu affinity to %d\n", new[LIM_CPUS]);
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPUS_LIMIT],
				new[LIM_CPUS]),	LVE_FAIL_WRT_CPUS_LIM, -EINVAL);
		if (rc)
			return rc;
	}

	if (custom & CUST_CPU) {
		/*
		 * DIV_ROUND_UP needs for case when new[LIM_CPU] is
		 * lesser than 10, in such case divide without round up
		 * produce zero limit.
		 */
		lim = DIV_ROUND_UP(new[LIM_CPU], 10) * 1024 / 1000;
		LVE_DBG("set fairshed rate to %u\n", lim);
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPU_LIMIT], lim),
				LVE_FAIL_WRT_CPU_LIM, -EINVAL);
		if (rc)
			return rc;
	}

	if (custom & CUST_CPU_WEIGHT) {
		rc = lve_call(cgrp_param_set_u64(lcontext->cpu_filps[PARAM_CPU_CHWT],
				new[LIM_CPU_WEIGHT]*1024/100),
				LVE_FAIL_WRT_CPU_CHWT, -EINVAL);
		if (rc)
			return rc;
	}
#endif

	if ((custom & CUST_IO) && (os_io_set_limit != NULL)) {
		rc = lve_call(os_io_set_limit(lcontext->lve_ub,
				new[LIM_IO] << 10, 0),
				LVE_FAIL_IO_SET_LIM, -ENOMEM);
		if (rc)
			return rc;
	}

	if ((custom & CUST_IOPS) && (os_iops_set_limit != NULL)) {
		rc = lve_call(os_iops_set_limit(lcontext->lve_ub,
				new[LIM_IOPS], 0),
				LVE_FAIL_IO_SET_LIM, -ENOMEM);
		if (rc)
			return rc;
	}

	if (custom & CUST_MEM) {
		rc = ubc_set_res(lcontext, LVE_MEM_LIMIT_RES, new[LIM_MEMORY]);
		if (rc) {
			LVE_ERR("ubc set virtual memory limit %d\n", rc);
			return rc;
		}
	}

	if (custom & CUST_MEM_PHY) {
		rc = ubc_set_res(lcontext, LVE_MEM_PHY_LIMIT_RES, new[LIM_MEMORY_PHY]);
		if (rc) {
			LVE_ERR("ubc set phys memory limit %d\n", rc);
			return rc;
		}
	}

	if (custom & CUST_NPROC) {
		rc = ubc_set_res(lcontext, LVE_NPROC_LIMIT_RES, new[LIM_NPROC]);
		if (rc) {
			LVE_ERR("ubc set nproc limit %d\n", rc);
			return rc;
		}
	}

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
//	BUG_ON(task->task_bc.exec_ub != get_ub0());

	/** XXX need change in case non standart io prio */
//	rc = push_task_ub(current, lcontext->lve_ub,
//			  &lenter->old_exec, &lenter->cg_old_io);
	/* XXX don't work with custom IO group */
#ifdef HAVE_BC_FORK_SUB
	BUG_ON(task->task_bc.fork_sub != NULL);
	if (lve_bc_after_enter) {
		task->task_bc.fork_sub =
				get_beancounter_longterm(lcontext->lve_ub);
	} else {
#endif
		rc2 = os_set_dac_override();

		rc = lve_call(lve_ub_attach_task(lcontext->lve_ub, task),
				LVE_FAIL_UB_ATTACH_TASK, -ENOMEM);

		if (rc2 == 0)
			os_clear_dac_override();

		if (rc != 0) {
			LVE_ERR("push ub failed\n");
		}
#ifdef HAVE_BC_FORK_SUB
	}
#endif

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
#if RHEL_MAJOR > 6
	rc = lve_call(lve_cgroup_kernel_attach(lcontext->cgrp[CG_CPUSET_GRP], task),
			LVE_FAIL_CGRP_ATTACH_TSK, -ENOMEM);
	if (rc != 0)
		LVE_ERR("cpuset attach task failed with %d\n", rc);
#endif

out:
#endif /* LVE_PER_VE */

	return rc;
}

static int os_lvp_cpu_init(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);
	char name[16];

	/** XXX hack until we will have a 2 level cpu scheduler */
	if (lvp->lvp_id == 0) {
		lvpp->lve_cpu_root = cmnt[CPU_SUBSYS].cgrp_root;
#if RHEL_MAJOR > 6
		lvpp->lve_cpuset_root = cmnt[CPUSET_SUBSYS].cgrp_root;

		c->cgrp[CG_CPU_GRP] = lvpp->lve_cpu_root;
		atomic_inc(&c->cgrp[CG_CPU_GRP]->count);

		c->cgrp[CG_CPUSET_GRP] = lvpp->lve_cpuset_root;
		atomic_inc(&c->cgrp[CG_CPUSET_GRP]->count);

		goto out_lvpp_ref;
#endif
	}

	snprintf(name, sizeof(name), "%d", lvp->lvp_id);
	/* We hold a reference to the parent CPU cgroup so it exists */
	c->cgrp[CG_CPU_GRP] = cgroup_kernel_open(cmnt[CPU_SUBSYS].cgrp_root, 0,
						name);
	if (IS_ERR(c->cgrp[CG_CPU_GRP])) {
		LVE_ERR("Can't open cgroup %s, err %lu \n", name,
			PTR_ERR(c->cgrp[CG_CPU_GRP]));
		return PTR_ERR(c->cgrp[CG_CPU_GRP]);
	}

#if RHEL_MAJOR > 6
	c->cgrp[CG_CPUSET_GRP] = cgroup_kernel_open(cmnt[CPUSET_SUBSYS].cgrp_root, 0,
						name);
	if (IS_ERR(c->cgrp[CG_CPUSET_GRP])) {
		LVE_ERR("Can't open cgroup %s, err %lu\n", name,
			PTR_ERR(c->cgrp[CG_CPUSET_GRP]));
		cgroup_kernel_close(c->cgrp[CG_CPU_GRP]);
		return PTR_ERR(c->cgrp[CG_CPUSET_GRP]);
	}
#endif

	c->lve_ub = lve_get_beancounter_byuid(lvp->lvp_id, 1);
	if (c->lve_ub == NULL) {
		cgroup_kernel_close(c->cgrp[CG_CPU_GRP]);
#if RHEL_MAJOR > 6
		cgroup_kernel_close(c->cgrp[CG_CPUSET_GRP]);
#endif
		LVE_ERR("Can't allocate UBC for LVP %s\n", name);
		return -ENOMEM;
	}

	if (lvp->lvp_id != 0) {
		lvpp->lve_cpu_root = c->cgrp[CG_CPU_GRP];
#if RHEL_MAJOR > 6
		lvpp->lve_cpuset_root = c->cgrp[CG_CPUSET_GRP];
#endif
	}
#if RHEL_MAJOR > 6
out_lvpp_ref:
#endif
	atomic_inc(&lvpp->lve_cpu_root->count);
#if RHEL_MAJOR > 6
	atomic_inc(&lvpp->lve_cpuset_root->count);
#endif

	LVE_DBG("cpu root %p host %p\n", lvpp->lve_cpu_root,
			cmnt[CPU_SUBSYS].cgrp_root);
#if RHEL_MAJOR > 6
	LVE_DBG("cpuset root %p host %p\n", lvpp->lve_cpuset_root,
			cmnt[CPU_SUBSYS].cgrp_root);
#endif

	return 0;
}

static void os_lvp_cpu_fini(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);

	/** XXX hack until we will have a 2 level cpu scheduler */
	if (lvp->lvp_id == 0) {
		lvpp->lve_cpu_root = c->cgrp[CG_CPU_GRP];
#if RHEL_MAJOR > 6
		lvpp->lve_cpuset_root = c->cgrp[CG_CPUSET_GRP];
#endif
	}

	if (lvpp->lve_cpu_root)
		cgroup_kernel_close(lvpp->lve_cpu_root);
#if RHEL_MAJOR > 6
	if (lvpp->lve_cpuset_root)
		cgroup_kernel_close(lvpp->lve_cpuset_root);
#endif
	put_beancounter(c->lve_ub);
}

static int os_global_cpu_init(void)
{
	/* We don't take a reference here, so won't need to drop it */
	cmnt[CPU_SUBSYS].cgrp_root = cgroup_get_root(cmnt[CPU_SUBSYS].mnt_root);
	BUG_ON(cmnt[CPU_SUBSYS].cgrp_root == NULL);
#if RHEL_MAJOR > 6
	cmnt[CPUSET_SUBSYS].cgrp_root = cgroup_get_root(cmnt[CPUSET_SUBSYS].mnt_root);
	BUG_ON(cmnt[CPUSET_SUBSYS].cgrp_root == NULL);
#endif
	return 0;
}

static void os_global_cpu_fini(void)
{
}

static int os_lvp_io_init(struct lvp_ve_private *lvp)
{
	return 0;
}

static void os_lvp_io_fini(struct lvp_ve_private *lvp)
{
}

const char os_io_set_limit_fn[]   = "iolimit_set_io_limit";
const char os_iops_set_limit_fn[] = "iolimit_set_iops_limit";
const char os_io_get_usage_fn[]   = "iolimit_get_io_usage";
const char os_iops_get_usage_fn[]   = "iolimit_get_iops_usage";

static int os_global_io_init(void)
{
	os_io_set_limit = (void *)lve_sym_get(os_io_set_limit_fn);
	os_io_get_usage = (void *)lve_sym_get(os_io_get_usage_fn);
	os_iops_set_limit = (void *)lve_sym_get(os_iops_set_limit_fn);
	os_iops_get_usage = (void *)lve_sym_get(os_iops_get_usage_fn);

	printk("io_set_limit = %p\n", os_io_set_limit);
	printk("io_get_usage = %p\n", os_io_get_usage);
	printk("iops_set_limit = %p\n", os_iops_set_limit);
	printk("iops_get_usage = %p\n", os_iops_get_usage);

	return 0;
}

static void os_global_io_fini(void)
{
	if (os_iops_set_limit)
		__symbol_put(os_iops_set_limit_fn);

	if (os_iops_get_usage)
		__symbol_put(os_iops_get_usage_fn);

	if (os_io_set_limit)
		__symbol_put(os_io_set_limit_fn);

	if (os_io_get_usage)
		__symbol_put(os_io_get_usage_fn);
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
	os_lvp_io_fini(lvp);
	os_lvp_cpu_fini(lvp);
}

#ifdef LVE_PER_VE
static int lve_ve_init(void *data)
{
	struct ve_struct *env;
	struct lvp_ve_private *lvp;
	int ret = 0;

	LVE_DBG("lve_ve_init\n");

	if (!try_module_get(THIS_MODULE)) {
		LVE_ERR("Can't get module !\n");
		return -EBUSY;
	}

	env = (struct ve_struct *)data;
	lvp = lvp_alloc(VEID(env), env);
	if (!lvp) {
		LVE_ERR("Can't allocate lvp\n");
		ret = -ENOMEM;
		goto err_alloc;
	}

	return ret;

err_alloc:
	module_put(THIS_MODULE);
	return ret;
}

static void lve_ve_fini(void *data)
{
	struct ve_struct *env;
	struct lvp_ve_private *lvp;

	LVE_DBG("lve_ve_fini\n");
	env = (struct ve_struct *)data;

	lvp = (struct lvp_ve_private *)env->lve;
	if (lvp) {
		lvp_fini(lvp);
#ifndef HAVE_VE_CLEANUP_CHAIN
		smp_mb();
		lvp_free(lvp);
		env->lve = NULL;
		module_put(THIS_MODULE);
#endif
	} else {
		LVE_ERR("Can't find lvp id=%d\n", VEID(env));
	}
	return;
}

#ifdef HAVE_VE_CLEANUP_CHAIN
static void lve_ve_free(void *data)
{
	struct ve_struct *env;

	LVE_DBG("lve_ve_free\n");
	env = (struct ve_struct *)data;
	lvp_free(env->lve);
	env->lve = NULL;

	module_put(THIS_MODULE);
	return;
}

/* lve_ve_fini is called whein ve is destroyed */
static struct ve_hook ve_exit_chain = {
	.fini 	=	lve_ve_free,
	.owner	=	THIS_MODULE,
};
#endif

/* lve_ve_init is called when ve is created */
static struct ve_hook ve_init_chain = {
	.init	=	lve_ve_init,
	.fini	= 	lve_ve_fini,
	.owner	=	THIS_MODULE,
};

static void init_ve_init_exit_chain(void)
{
#ifdef HAVE_VE_CLEANUP_CHAIN
	/* fini chain */
	ve_hook_register(VE_CLEANUP_CHAIN, &ve_exit_chain);
#endif
	/* init chain */
	ve_hook_register(VE_SS_CHAIN, &ve_init_chain);
}

static void cleanup_ve_init_exit_chain(void)
{
	ve_hook_unregister(&ve_init_chain);
#ifdef HAVE_VE_CLEANUP_CHAIN
	ve_hook_unregister(&ve_exit_chain);
#endif
}
#endif

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
	if (nr_ve > 1) {
		mutex_unlock(&ve_list_lock);
		umount_cgroup_root_fs(cmnt);
		LVE_ERR("modlve need load before container start\n");
		return -ENOSYS;
	}
#endif

	os_global_cpu_init();
	os_global_io_init();

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
	os_global_io_fini();
	os_global_cpu_fini();

	umount_cgroup_root_fs(cmnt);
}

module_param(lve_swappages, ulong, 0644);
