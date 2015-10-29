#ifndef _LVE_OS_COMPAT_H_
#define _LVE_OS_COMPAT_H_

#include <linux/slab.h>
#include "lve_kmod_c.h"
#include "kernel_exp.h"

#define lve_task_pid(t)	task_pid_nr((t))

#define lve_kmem_cache_create(a,b,c,d,e) kmem_cache_create(a,b,c,d,e)

static inline int lve_kmem_cache_destroy(void *ptr)
{
	kmem_cache_destroy(ptr);
	return 0;
}

#ifdef CONFIG_VE
#ifdef HAVE_VE_PROC_ROOT
#define lve_procfs_root(lvp)	(current->ve_task_info.owner_env->proc_root)
#else
struct lvp_ve_private;
struct proc_dir_entry;
struct proc_dir_entry *lve_procfs_root(struct lvp_ve_private *lvp);
#endif /* HAVE_VE_PROC_ROOT */
#else
#ifndef HAVE_PROC_ROOT
#define lve_procfs_root(lvp)	(NULL)
#else
#define lve_procfs_root(lvp)	(&glob_proc_root)
#endif
#endif

#ifdef LVE_PER_VE
#ifdef HAVE_VE_TASK_INFO
#define lve_task_veid(t)	((t)->ve_task_info.owner_env->veid)
#else
#define lve_task_veid(t)	((t)->task_ve->veid)
#endif
#define CAP_LVE_ADMIN		(CAP_VE_SYS_ADMIN)
#else
#define lve_task_veid(t)	(0)
#define CAP_LVE_ADMIN		(CAP_SYS_ADMIN)
#endif

#ifdef HAVE_NAMESPACE_H
#include <linux/namespace.h>
#define lve_mnt_namespace namespace
#endif
#ifdef HAVE_MNT_NAMESPACE_H
#include <linux/mnt_namespace.h>
#define lve_mnt_namespace mnt_namespace
#endif

static inline 
struct task_struct *lve_find_task(pid_t pid)
{
	struct task_struct *task;

	read_lock(&tasklist_lock);
#ifdef HAVE_TASK_PID_TYPE_VE
	task = find_task_by_pid_type_ve(PIDTYPE_PID, pid);
#else
	task = lve_find_task_by_vpid(pid);
#endif
	if (task)
		get_task_struct(task);
	read_unlock(&tasklist_lock);

	return task;
}

#ifndef HAVE_PATH_H
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};
#endif

#ifdef HAVE_PATH_LOOKUP
#define lve_path_lookup(name,flags,ndp) path_lookup(name, flags, ndp)
#else
#define lve_path_lookup(name,flags,ndp) kern_path(name, flags, &(ndp)->path)
#endif

#ifdef HAVE_PLAIN_CRED_EUID
#define lve_cred_euid(credp) (credp)->euid
#else
#define lve_cred_euid(credp) (credp)->euid.val
#endif

#ifdef HAVE_DO_EACH_THREAD_ALL
#define lve_do_each_thread do_each_thread_all
#define lve_while_each_thread while_each_thread_all
#else
#define lve_do_each_thread do_each_thread
#define lve_while_each_thread while_each_thread
#endif

#ifdef HAVE_UB_SYNC_MEMCG
#define lve_sync_ub_usage ub_sync_memcg
#else
#define lve_sync_ub_usage ub_update_resources
#endif

#ifdef HAVE_VFS_RENAME_WITH_6ARGS
#define lve_vfs_rename(a,b,c,d) vfs_rename(a,b,c,d,NULL,0)
#else
#ifdef HAVE_VFS_RENAME_WITH_5ARGS
#define lve_vfs_rename(a,b,c,d) vfs_rename(a,b,c,d,NULL)
#else
#define lve_vfs_rename vfs_rename
#endif /* HAVE_VFS_RENAME_WITH_5ARGS */
#endif /* HAVE_VFS_RENAME_WITH_6ARGS */

#endif
