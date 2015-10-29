#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/sched.h>

#include <linux/cgroup.h>

#include <linux/cpuset.h>
#include <block/blk-cgroup.h>

#define UB_IOPRIO_MAX 8

#include "lve-api.h"
#include "../resource.h"
#include "../lve_debug.h"
#include "../lve_internal.h"

static struct cgroup *lve_cpu_root;
static u64 ioprio_weight[UB_IOPRIO_MAX] = {320, 365, 410, 460, 500, 550, 600, 640};
static struct cgroup *lve_io_root;
static struct cgroup *lve_mem_root;

#define MAX_GRP_NAMESZ 20

struct c_private {
	struct cgroup *cg_cpu_grp;
	struct cgroup *cg_mem_grp;
	struct cgroup *cg_io_grp;
};

struct e_private {
	struct cgroup *cg_old_cpu;
	struct cgroup *cg_old_mem;
	struct cgroup *cg_old_io;
};

unsigned int os_context_private_sz(void)
{
	return sizeof(struct c_private);
}

unsigned int os_enter_private_sz(void)
{
	return sizeof(struct e_private);
}

void os_resource_usage(struct c_private *private, struct lve_usage *buf)
{
#ifdef CONFIG_CGROUP_CPUACCT
	if (private->cg_cpu_stat) {
		u64 data;

		data = private->cg_cpu_stat->read_u64(private->cg_cpu_grp,
						      private->cg_cpu_stat);
		LVE_DBG("cpu usage "LPU64"\n", data);
		buf->data[RES_CPU].data = data;
		
	}
#endif

}

void os_resource_usage_clear(struct c_private *private)
{
#ifdef CONFIG_CGROUP_CPUACCT
	if (private->cg_cpu_stat) {
		unsigned long data;

		data = private->cg_cpu_stat->write_u64(private->cg_cpu_grp,
						       private->cg_cpu_stat, 0);
	}
#endif

}

int os_resource_init(struct light_ve *ve)
{
	char name[MAX_GRP_NAMESZ];
	struct cgroup *cgrp;
	struct c_private *lcontext = lve_private(ve);
	int id = ve->lve_id;

	snprintf(name, sizeof(name), "%u", id);
	cgrp = cgroup_kernel_open(lve_cpu_root, CGRP_CREAT | CGRP_EXCL | CGRP_WEAK, name);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);
	lcontext->cg_cpu_grp = cgrp;
#ifdef CONFIG_CGROUP_CPUACCT
	lcontext->cg_cpu_stat = cgrp_param_get(cgrp, "cpuacct.usage");
	if (IS_ERR(lcontext->cg_cpu_stat)) {
		/* acct disabled ? */
		LVE_DBG("can't find param %ld\n", PTR_ERR(lcontext->cg_cpu_stat));
		lcontext->cg_cpu_stat = NULL;
	}
#endif

	LVE_DBG("cpu group %p\n", cgrp);
	return 0;
}

int os_resource_unlink(uint32_t id, struct c_private *private)
{
	int rc = 0;

#ifdef CONFIG_CGROUP_CPUACCT
	if (lcontext->cg_cpu_stat) {
		/** we a create a cpu context with WEAK flag so it will destroyed 
		    after close */
		cgrp_param_release(lcontext->cg_cpu_stat);
		lcontext->cg_cpu_stat = NULL;
	}
#endif

	return rc;
}

int os_resource_fini(struct c_private *lcontext)
{
	if (lcontext->cg_cpu_grp)
		cgroup_kernel_close(lcontext->cg_cpu_grp);
	if (lcontext->cg_mem_grp)
		cgroup_kernel_close(lcontext->cg_mem_grp);
	if (lcontext->cg_io_grp)
		cgroup_kernel_close(lcontext->cg_io_grp);

	return 0;
}

int os_resource_setup(struct c_private *lcontext, lve_limits_t new, uint32_t custom)
{
	int rc;

	lve_cgroup_lock();
	if (custom & CUST_CPUS) {
		LVE_DBG("set cpu affinity to \n");
		rc = cgroup_set_cpumask(lcontext->cg_cpu_grp, cpu_active_mask);
		if (rc)
			goto out;
	}

	if (custom & CUST_CPU) {
		LVE_DBG("set fairshed rate to %u\n",
			new[LIM_CPU]*1024*num_online_cpus()/100);
#ifdef FSCHED_CPULIMIT
#else
		LVE_WARN("CPU limiting don't supported\n");
#endif
	}

	if (custom & CUST_MEM) {
		LVE_DBG("set memory usage to \n");
	}

	if (custom & CUST_IO) {
		rc = blkio_cgroup_set_weight(lcontext->cg_io_grp, ioprio_weight[new[LIM_CPU]]);
	}

	rc = 0;
out:
	lve_cgroup_unlock();

	return rc;

}

/* enter to memory / io control usage */
void os_resource_push(struct c_private *lcontext, struct e_private *lenter)
{
	lve_cgroup_lock();
	lenter->cg_old_io = task_cgroup(current, blkio_subsys_id);
	lve_cgroup_attach_task(lcontext->cg_io_grp, current);

	lve_cgroup_unlock();
}

void os_resource_pop(struct c_private *lcontext, struct e_private *lenter)
{
	lve_cgroup_lock();
	lve_cgroup_attach_task(lenter->cg_old_io, current);
	lve_cgroup_unlock();
}

int os_cpu_enter(struct c_private *lcontext, struct e_private *lenter)
{
	lve_cgroup_lock();
	lenter->cg_old_cpu = task_cgroup(current, cpu_cgroup_subsys_id);
	lve_cgroup_attach_task(lcontext->cg_cpu_grp, current);
	lve_cgroup_unlock();

	return 0;
}

/* May be removed in the future as part of tags cleanup */
int os_cpu_leave(struct e_private *lenter)
{
	return 0;
}

int os_cpu_pop(struct e_private *lenter)
{
	lve_cgroup_lock();
	lve_cgroup_attach_task(lenter->cg_old_cpu, current);
	lve_cgroup_unlock();

	return 0;
}

static int os_cpu_init(void)
{
	struct vfsmount *c_mnt;
	struct cgroup *cgrp;
	int ret;
	struct cgroup_sb_opts lve_cpu_opt = {
		.subsys_bits	= (1ul << cpu_cgroup_subsys_id) |
				(1ul << cpuacct_subsys_id);
	};

	c_mnt = cgroup_kernel_mount(&lve_cpu_opt);
	if (IS_ERR(c_mnt))
		return PTR_ERR(c_mnt);
	lve_cpu_root = cgroup_get_root(c_mnt);

	LVE_DBG("cpu root %p\n", lve_cpu_root);
	return 0;
}

static void os_cpu_fini(void)
{
}
#if 0
static int os_mem_init(void)
{
	return 0;
}

static void os_mem_fini(void)
{
}


static int os_io_init(void)
{
	struct vfsmount *c_mnt;
	struct cgroup *cgrp;
	int ret;
	struct cgroup_sb_opts lve_cpu_opt = {
		.subsys_bits	= 1ul << blkio_subsys_id,
	};

	c_mnt = cgroup_kernel_mount(&lve_cpu_opt);
	if (IS_ERR(c_mnt))
		return PTR_ERR(c_mnt);
	lve_io_root = cgroup_get_root(c_mnt);

	LVE_DBG("lve_io_root %p\n", lve_io_root);
	return 0;
}

static void os_io_fini(void)
{
}
#endif

int os_init(void)
{
	os_cpu_init();
	//os_mem_init();
	//os_io_init();

	return 0;
}

int os_fini(void)
{
	os_cpu_fini();
	return 0;
}
