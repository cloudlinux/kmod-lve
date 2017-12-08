#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/sched.h>

#include <linux/cgroup.h>

#include <linux/cpuset.h>

/* TODO: rework all "#if 0" stubs */

#if RHEL_MAJOR < 7
#error "RHEL 7 and up supported"
#endif

#if 0
#include <block/blk-cgroup.h>
#endif

#include "lve-api.h"
#include "cgroup_lib.h"
#include "resource.h"
#include "lve_debug.h"
#include "lve_internal.h"

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
	__s64 data;

	data = cgrp_param_get(private->cpu_filps[PARAM_CPU_STAT]);
	if(data > 0) {
		LVE_DBG("cpu usage "LPU64"\n", data);
		buf->data[RES_CPU].data = data;
	}

}

void os_resource_usage_clear(struct c_private *private)
{
	cgrp_param_set_u64(private->cpu_filps[PARAM_CPU_STAT], 0);
}

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


int os_resource_init(struct light_ve *ve __attribute__((unused)))
{
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

	cgrp = lve_call(lve_cgroup_kernel_open(lvpp->lve_cpuset_root,
				LVE_CGRP_CREAT | LVE_CGRP_EXCL, name),
				LVE_FAIL_CGRP_OPEN, ERR_PTR(-EEXIST));
	if (IS_ERR(cgrp)) {
		LVE_ERR("lve_cpuset_root %s err %ld\n",
			name, PTR_ERR(cgrp));
		return PTR_ERR(cgrp);
	}
	lcontext->cgrp[CG_CPUSET_GRP] = cgrp;
	LVE_DBG("cpuset group %p\n", cgrp);

	os_cpuset_init(cmnt[CPUSET_SUBSYS].mnt_root, cgrp);


	return 0;
}

/* XXX TODO move to generic */
int os_resource_unlink(uint32_t id, struct c_private *lcontext)
{
	int rc = 0;
	int i;
	char name[MAX_GRP_NAMESZ] = {0};

	LVE_ENTER("(id=%u, lcontext=%p)\n", id, lcontext);

	lcontext->unlink_id = get_unlink_id();
	snprintf(name, sizeof(name)-1, UNLINK_FORMAT, lcontext->unlink_id);

	for (i = 0; i < CG_MAX_GRP; i++) {
		if (lcontext->cgrp[i] != NULL)
			cgrp_obfuscate(lcontext->cgrp[i], name);
	}

	return rc;
}

static void lve_cgroup_release(uint32_t id, char *name, struct cgroup *cgrp)
{
	lve_cgroup_kernel_close(cgrp);
	if (id != ROOT_LVE)
		lve_cgroup_kernel_remove(cgrp->parent, name);
}

int os_resource_fini(uint32_t id, struct c_private *lcontext)
{
	int rc = 0;
	int i;
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

	return rc;
}

int os_resource_setup(struct c_private *lcontext, int32_t new,
		      enum lve_limits custom)
{
	int rc = 0;
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
				new*1024/100),
				LVE_FAIL_WRT_CPU_CHWT, -EINVAL);
		break;
	default:
		BUG();
	}

	return rc;
}

/* enter to memory / io control usage */
int os_resource_push(struct task_struct *task, struct c_private *lcontext)
{
	return 0;
}

void os_resource_pop(struct task_struct *task, struct c_private *lcontext)
{
}

int os_cpu_enter(struct task_struct *task, struct c_private *lcontext)
{
	int rc;

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
	return rc;
}


static int os_lvp_cpu_init(struct lvp_ve_private *lvp)
{
	struct lvp_private *lvpp = os_lvp_private(lvp);
	struct c_private *c = lve_private(lvp->lvp_default);

	/** XXX hack until we will have a 2 level cpu scheduler */
	if (lvp->lvp_id == 0) {
		lvpp->lve_cpu_root = cmnt[CPU_SUBSYS].cgrp_root;
		lvpp->lve_cpuset_root = cmnt[CPUSET_SUBSYS].cgrp_root;

		c->cgrp[CG_CPU_GRP] = lvpp->lve_cpu_root;
		atomic_inc(&c->cgrp[CG_CPU_GRP]->count);

		c->cgrp[CG_CPUSET_GRP] = lvpp->lve_cpuset_root;
		atomic_inc(&c->cgrp[CG_CPUSET_GRP]->count);

		goto out_lvpp_ref;
	}

out_lvpp_ref:

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
	if (lvp->lvp_id == 0) {
		lvpp->lve_cpu_root = c->cgrp[CG_CPU_GRP];
		lvpp->lve_cpuset_root = c->cgrp[CG_CPUSET_GRP];
	}

	if (lvpp->lve_cpu_root)
		lve_cgroup_kernel_close(lvpp->lve_cpu_root);
	if (lvpp->lve_cpuset_root)
		lve_cgroup_kernel_close(lvpp->lve_cpuset_root);
}

void os_lvp_fini(struct lvp_ve_private *lvp)
{
	os_lvp_cpu_fini(lvp);
}

int os_lvp_init(struct lvp_ve_private *lvp, void *data)
{
	int rc;

	rc = os_lvp_cpu_init(lvp);
	if (rc < 0)
		return rc;

	return 0;
}

int os_freezer_enter(struct task_struct *task, struct c_private *lcontext)
{
        return 0;
}

int os_freezer_freeze(struct light_ve *ve)
{
        return -ENOSYS;
}

int os_freezer_thaw(struct light_ve *ve)
{
        return -ENOSYS;
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

int os_global_init(void)
{
	int rc;
	LVE_ENTER("os_global_init");

	memset(cmnt, 0, sizeof(*cmnt) * NR_SUBSYS);

	rc = mount_cgroup_root_fs(cmnt);
	if (rc)
		return rc;

	os_global_cpu_init();

	return 0;
}

void os_global_fini(void)
{
	os_global_cpu_fini();

	umount_cgroup_root_fs(cmnt);
}
