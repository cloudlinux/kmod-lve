#ifndef _OPENVZ_CGROUPS_H_
#define _OPENVZ_CGROUPS_H_

#include <linux/version.h>

#include "cgroup_lib.h"

extern struct cgrp_mount cmnt[NR_SUBSYS];

struct cgroup;
struct vfsmount;
struct user_beancounter;

struct lvp_private {
	struct cgroup *lve_cpu_root;
#if RHEL_MAJOR > 6
	struct cgroup *lve_cpuset_root;
	struct cgroup *lve_memory_root;
#endif
	struct cgroup *lve_cpu_acct;
	struct cgroup *lve_io_root;
};

enum param_id {
	PARAM_CPU_STAT = 0,
	PARAM_CPU_LIMIT,
	PARAM_CPU_CHWT,
	PARAM_CPUS_LIMIT,
	PARAM_CPU_MAX
};

enum cgrp_id {
	CG_CPU_GRP = 0,
	CG_CPUSET_GRP,
	CG_UB_GRP,
	CG_MEM_GRP,
	CG_MAX_GRP
};

struct c_private {
	struct user_beancounter *lve_ub;
	struct cgroup *cgrp[CG_MAX_GRP];
	struct file *cpu_filps[PARAM_CPU_MAX];
};

#endif
