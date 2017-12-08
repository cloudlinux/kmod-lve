#ifndef _LVE_OS_COMPAT_H_
#define _LVE_OS_COMPAT_H_

#include <linux/slab.h>
#include "lve_kmod_c.h"
#include "kernel_exp.h"

struct proc_dir_entry;
struct lvp_ve_private;
#ifdef CONFIG_VE
#ifdef HAVE_VE_PROC_ROOT
#define lve_procfs_root(lvp)	(current->ve_task_info.owner_env->proc_root)
#else
static inline struct proc_dir_entry *lve_procfs_root(struct lvp_ve_private *lvp)
{
	return NULL;
}
#endif /* HAVE_VE_PROC_ROOT */
#else
#ifndef HAVE_PROC_ROOT
static inline struct proc_dir_entry *lve_procfs_root(struct lvp_ve_private *lvp)
{
	return NULL;
}
#else
#define lve_procfs_root(lvp)	(&glob_proc_root)
#endif
#endif

#ifdef LVE_PER_VE
#define CAP_LVE_ADMIN		(CAP_VE_SYS_ADMIN)
#else
#define CAP_LVE_ADMIN		(CAP_SYS_ADMIN)
#endif

#include <linux/mnt_namespace.h>

static inline 
struct task_struct *lve_find_task(pid_t pid)
{
	struct task_struct *task;

	read_lock(&tasklist_lock);
	task = lve_find_task_by_vpid(pid);
	if (task)
		get_task_struct(task);
	read_unlock(&tasklist_lock);

	return task;
}

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

struct lve_namespace {
	struct nsproxy		*lve_nsproxy;
	struct fs_struct	*lve_fs;
};

#endif
