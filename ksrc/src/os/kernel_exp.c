#include "lve_kmod_c.h"
#include "kernel_exp.h"
#include <linux/nsproxy.h>

#include "cgroup_lib.h"

void _lve_set_fs_pwd(struct fs_struct *, struct path *);
void _lve_set_fs_root(struct fs_struct *, struct path *);

void lve_set_fs_root_pwd(struct fs_struct *f, struct path *p)
{
	_lve_set_fs_root(f, p);
	_lve_set_fs_pwd(f, p);
}

#ifdef HAVE_2ARGS_CGROUP_ATTACH_TASK
int _lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk);

int lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk)
{
	if (cgrp == NULL)
		return 0;
	return _lve_cgroup_kernel_attach(cgrp, tsk);
}
#else

extern struct mutex lve_cgroup_mutex;
int lve_cgroup_attach_task(struct cgroup *, struct task_struct *, bool);

int lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk)
{
	int ret;

	if (cgrp == NULL)
		return 0;

	mutex_lock(&lve_cgroup_mutex);
	ret = lve_cgroup_attach_task(cgrp, tsk, false);
	mutex_unlock(&lve_cgroup_mutex);

	return ret;
}
#endif

#if OPENVZ_VERSION > 0
#include <bc/beancounter.h>

#ifndef HAVE_UB_ATTACH_TASK

#ifdef HAVE_UB_ATTACH
int _lve_ub_attach(struct user_beancounter *bc);
#endif

int lve_ub_attach_task(struct user_beancounter *bc, struct task_struct *task)
{
#ifndef HAVE_UB_ATTACH
	return set_task_exec_ub(task, bc);
#else
	return (task == current) ? _lve_ub_attach(bc) : -EINVAL;
#endif
}
#else
int _lve_ub_attach_task(struct user_beancounter *bc, struct task_struct *task);

int lve_ub_attach_task(struct user_beancounter *bc, struct task_struct *task)
{
	return _lve_ub_attach_task(bc, task);
}
#endif /* HAVE_UB_ATTACH_TASK */

#include <linux/cgroup.h>
#include <linux/mount.h>
extern struct cgroup *lve_ub_cgroup_root;
extern struct vfsmount *lve_ub_cgroup_mnt;

struct cgroup *lve_get_ub_cgroup_root(void)
{
	struct cgroup *_lve_ub_cgroup_root = NULL;

#ifdef HAVE_UB_CGROUP_ROOT
	_lve_ub_cgroup_root = lve_ub_cgroup_root;
#else
#ifdef  HAVE_UB_CGROUP_MNT
	_lve_ub_cgroup_root = lve_cgroup_get_root(lve_ub_cgroup_mnt);
#endif
#endif /* HAVE_UB_CGROUP_ROOT */

	return _lve_ub_cgroup_root;
}

#endif /* OpenVZ */

int lve_copy_namespaces(unsigned long flags, struct task_struct *tsk)
{
#if defined(HAVE_COPY_NS_WITH_2ARGS)
	return copy_namespaces(CLONE_NEWNS, tsk);
#elif defined(HAVE_COPY_NS_WITH_3ARGS)
	return copy_namespaces(CLONE_NEWNS, tsk, 0);
#else
#error "Unsupported copy_namespaces() prototype"
#endif
}
