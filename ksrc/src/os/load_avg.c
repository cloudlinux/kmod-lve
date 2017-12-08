#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>

#include <linux/cgroup.h>

#include "lve_kmod_c.h"
#include "light_ve.h"
#include "lve_internal.h"
#include "resource.h"
#include "cgroup_lib.h"

#if defined(HAVE_LOADAVG_PTR)
static int os_loadavg_cgroup(struct cgroup *cgrp)
{
	int load = 0;
	struct cgroup_iter it;
	struct task_struct *tsk;

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

int os_loadavg_global(struct lvp_ve_private *host)
{
	struct c_private *c = lve_private(host->lvp_default);
	struct cgroup *cgrp = c->cgrp[CG_CPU_GRP];
	int load;

	load = os_loadavg_cgroup(cgrp);
#if RHEL_MAJOR < 7
	/* Sigh, RHEL6 has some tasks in / and some in /0 */
	load += os_loadavg_cgroup(os_lvp_private(host)->lve_cpu_root);
#endif

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
