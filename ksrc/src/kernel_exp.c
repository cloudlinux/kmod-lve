#include "lve_kmod_c.h"
#include "kernel_exp.h"
void _lve_set_fs_pwd(struct fs_struct *, struct path *);
void _lve_set_fs_root(struct fs_struct *, struct path *);

void lve_set_fs_root_pwd(struct fs_struct *f, struct path *p)
{
	_lve_set_fs_root(f, p);
	_lve_set_fs_pwd(f, p);
}

#ifdef HAVE_3ARGS_COPY_MNT_NS
struct mnt_namespace *_lve_copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,
		struct fs_struct *new_fs);

struct mnt_namespace *lve_copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,
		struct fs_struct *new_ns)
{
	return _lve_copy_mnt_ns(flags, ns, new_ns);
}
#else
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>

struct mnt_namespace *_lve_copy_mnt_ns(unsigned long flags, struct mnt_namespace *mnt_ns,
		struct user_namespace *user_ns, struct fs_struct *new_fs);

struct mnt_namespace *lve_copy_mnt_ns(unsigned long flags, struct mnt_namespace *mnt_ns,
		struct fs_struct *new_ns)
{
	struct user_namespace *user_ns = task_cred_xxx(current, user_ns);
	return _lve_copy_mnt_ns(flags, mnt_ns, user_ns, new_ns);
}
#endif /* HAVE_3ARGS_COPY_MNT_NS */

#ifndef HAVE_UB_ATTACH_TASK
#include <bc/beancounter.h>

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

#ifndef HAVE_SWITCH_NS
void lve_switch_ns(struct task_struct *tsk, struct nsproxy *new)
{
	struct nsproxy *oldns;

	task_lock(tsk);
	oldns = tsk->nsproxy;
	tsk->nsproxy = new;
	task_unlock(tsk);
	if (oldns)
		put_nsproxy(oldns);
}
#endif

#ifdef HAVE_2ARGS_CGROUP_ATTACH_TASK
int _lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk);

int lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk)
{
	return _lve_cgroup_kernel_attach(cgrp, tsk);
}
#else
int lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk)
{
	int ret;

	mutex_lock(&lve_cgroup_mutex);
	ret = lve_cgroup_attach_task(cgrp, tsk, false);
	mutex_unlock(&lve_cgroup_mutex);

	return ret;
}
#endif

int lve_vprintk(unsigned long ip, const char *fmt, va_list ap);

int lve_printk(unsigned long ip, const char *fmt, ...)
{
	int rc;
	va_list ap;

	va_start(ap, fmt);
	rc = lve_vprintk(ip, fmt, ap);
	va_end(ap);
	return rc;
}

#include <linux/cgroup.h>
#include <linux/mount.h>

struct cgroup *lve_get_ub_cgroup_root(void)
{
	struct cgroup *_lve_ub_cgroup_root = NULL;

#ifdef HAVE_UB_CGROUP_ROOT
	_lve_ub_cgroup_root = lve_ub_cgroup_root;
#else
#ifdef  HAVE_UB_CGROUP_MNT
	_lve_ub_cgroup_root = cgroup_get_root(lve_ub_cgroup_mnt);
#endif
#endif /* HAVE_UB_CGROUP_ROOT */

	return _lve_ub_cgroup_root;
}

struct cgroup *lve_get_mem_cgroup_root(void)
{
	struct cgroup *_lve_mem_cgroup_root = NULL;

#ifdef HAVE_MEM_CGROUP_ROOT
	_lve_mem_cgroup_root = lve_mem_cgroup_root;
#else
#ifdef HAVE_UB_BOUND_CGROUP_MNT
	_lve_mem_cgroup_root =
		cgroup_get_root(&lve_ub_bound_cgroup_mnt[UB_MEM_CGROUP]);
#endif
#endif /* HAVE_MEM_CGROUP_ROOT */

	return _lve_mem_cgroup_root;
}
