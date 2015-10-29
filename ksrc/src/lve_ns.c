#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/mount.h>

#include <linux/nsproxy.h>

#include "lve_debug.h"
#include "lve_internal.h"
#include "light_ve.h"
#include "lve_os_compat.h"
#include "resource.h"
#include "kernel_exp.h"

#ifdef HAVE_CREATE_NEW_NAMESPACES
#include <linux/init_task.h>
struct nsproxy *create_new_namespaces(unsigned long flags,
	struct task_struct *tsk, struct user_namespace *user_ns,
	struct fs_struct *new_fs);

struct nsproxy *lve_nsproxy_dup(struct nsproxy *ns)
{
	struct task_struct *task;
	struct nsproxy *nsnew;

	task = kmalloc(sizeof(*task), GFP_KERNEL);
	if (task == NULL) {
		LVE_WARN("failed to allocate task_struct\n");
		return NULL;
	}

	task->nsproxy = ns;
	nsnew = create_new_namespaces(0, task, NULL, NULL);
	kfree(task);

	if (IS_ERR(nsnew)) {
		LVE_WARN("failed to create new ns, err %ld\n", PTR_ERR(nsnew));
		nsnew = NULL;
	}

	return nsnew;
}
#endif

#if !defined(HAVE_SWITCH_NS)
static inline void lve_put_ns(struct namespace *namespace)
{
	if (atomic_dec_and_lock(&namespace->count, &vfsmount_lock))
		/* releases vfsmount_lock */
		lve_ns_put_final(namespace);
}

struct nsproxy *lve_dup_proxy(struct nsproxy *ns, struct fs_struct *fs, struct vfsmount *new_root)
{
	struct nsproxy *ns2;
	struct lve_mnt_namespace *lve_namespace;

	if (new_root != NULL)
		return NULL;

	ns2 = dup_namespaces(ns);
	if (ns2 == NULL) {
		LVE_WARN("Can't copy nsproxy\n");
		goto out;
	}
	lve_namespace = dup_namespace(container_of(&ns2, struct task_struct, nsproxy), fs);
	if (!lve_namespace) {
		LVE_WARN("Can't copy namespace\n");
		put_nsproxy(ns2);
		ns2 = NULL;
		goto out;
	}
	/* drop the reference from dup_namespaces */
	lve_put_ns(ns2->namespace);
	ns2->namespace = lve_namespace;
out:
	return ns2;
}
#else
struct nsproxy *lve_dup_proxy(struct nsproxy *ns, struct fs_struct *fs, struct vfsmount *new_root)
{
	struct nsproxy *ns2;
	struct mnt_namespace *old;

#ifndef HAVE_DUP_MNT_NS
	/* NONE CL patches appled */
	if (new_root)
		return NULL;
#endif

	ns2 = lve_nsproxy_dup(ns);
	if (ns2 == NULL) {
		LVE_WARN("Can't dup NS\n");
		goto out;
	}
	old = ns2->mnt_ns;

	LVE_DBG("dup mnt ns %p\n", new_root);
#ifdef HAVE_DUP_MNT_NS
	ns2->mnt_ns = dup_mnt_ns(ns2->mnt_ns, fs, new_root);
#else
	ns2->mnt_ns = lve_copy_mnt_ns(CLONE_NEWNS, ns2->mnt_ns, fs);
#endif
	if (old)
		lve_put_mnt_ns(old);
	LVE_DBG("nsproxy %p mnt_ns %p\n", ns2, ns2->mnt_ns);
	if (IS_ERR(ns2->mnt_ns)) {
		LVE_WARN("can't create mnt ns %ld\n", PTR_ERR(ns2->mnt_ns));
		ns2->mnt_ns = NULL;
		put_nsproxy(ns2);
		ns2 = NULL;
	}
out:
	return ns2;
}
#endif

#ifndef HAVE_KILL_FS
static void lve_fs_get(struct fs_struct *fs)
{
	atomic_inc(&fs->count);
}
#else
/* cl6 */
static void lve_fs_get(struct fs_struct *fs)
{
	spin_lock(&fs->lock);
	fs->users ++;
	spin_unlock(&fs->lock);
}

static void lve_fs_put(struct fs_struct *fs)
{
	int kill;

	spin_lock(&fs->lock);
	kill = !--fs->users;
	spin_unlock(&fs->lock);
	if (kill)
		lve_free_fs_struct(fs);
}
#endif

static void lve_namespace_switch(struct light_ve *ve,
				 struct fs_struct *new_fs,
				 struct nsproxy *new_ns,
				 bool need_lock)
{
	struct fs_struct *old_fs;
	struct nsproxy *old_ns;

	LVE_DBG("switch ns for %u(%p) -> %p %p\n", ve->lve_id, ve,
		new_fs, new_ns);
	if (need_lock)
		write_lock(&ve->lve_ns_lock);
	old_fs = ve->lve_fs;
	old_ns = ve->lve_nsproxy;

	ve->lve_fs = new_fs;
	ve->lve_nsproxy = new_ns;
	if (need_lock)
		write_unlock(&ve->lve_ns_lock);

	if (old_fs)
		lve_fs_put(old_fs);

	if (old_ns)
		put_nsproxy(old_ns);
}

static void lve_namespace_get(struct light_ve *ve,
			      struct fs_struct **fs,
			      struct nsproxy **ns)
{
	read_lock(&ve->lve_ns_lock);
	*fs = ve->lve_fs;
	*ns = ve->lve_nsproxy;

	if (ve->lve_fs)
		lve_fs_get(ve->lve_fs);
	if (ve->lve_nsproxy)
		get_nsproxy(ve->lve_nsproxy);
	read_unlock(&ve->lve_ns_lock);
}

static int lve_namespace_clone(struct light_ve *ve,
			       struct nsproxy *old_ns,
			       struct fs_struct *old_fs,
			       struct path *new_root
			      )
{
	struct fs_struct *new_fs;
	struct nsproxy *new_ns;
	struct vfsmount *mnt_root = NULL;

	new_fs = lve_copy_fs_struct(old_fs);
	if (new_fs == NULL)
		return -ENOMEM;

	if (new_root) {
		LVE_DBG("try to use root %s mnt %p\n",
			new_root->dentry->d_name.name, new_root->mnt);
		lve_set_fs_root_pwd(new_fs, new_root);
		mnt_root = new_root->mnt;
	}

	new_ns = lve_dup_proxy(old_ns, new_fs, mnt_root);
	if (new_ns == NULL) {
		lve_fs_put(new_fs);
		return -ENOMEM;
	}

	lve_namespace_switch(ve, new_fs, new_ns, true);

	return 0;
}

int lve_namespace_fini(struct light_ve *ve)
{
	/* no op */
	if (lve_no_namespaces)
		return 0;

	lve_namespace_switch(ve, NULL, NULL, false);
	return 0;
}

void lve_namespace_unset_default(void)
{
	struct lvp_ve_private *lvp;

	/* no op */
	if (lve_no_namespaces)
		return;

	lvp = TASK_VE_PRIVATE(current);
	lve_namespace_fini(lvp->lvp_default);
}

int lve_namespace_set_default(void)
{
	struct lvp_ve_private *lvp;

	/* no op */
	if (lve_no_namespaces)
		return 0;

	lvp = TASK_VE_PRIVATE(current);

	/* fs / ns protected by task reference */
	return lve_namespace_clone(lvp->lvp_default, current->nsproxy,
				    current->fs, NULL);
}

#ifdef HAVE_DUP_MNT_NS
int lve_namespace_set_root(struct light_ve *ve, const char __user *root)
{
	struct path path;
	int rc;

	if (lve_no_namespaces)
		return -ENOSYS;

	rc = user_path(root, &path);
	if (rc)
		return rc;

	if (path.mnt->mnt_root != path.dentry) {
		LVE_WARN("please set to mount root\n");
		path_put(&path);
		return -EMEDIUMTYPE;
	}

	rc = lve_namespace_clone(ve, current->nsproxy, current->fs, &path);
	path_put(&path);

	return rc;
}
#else
int lve_namespace_set_root(struct light_ve *ve, const char __user *root)
{
	return -ENOSYS;
}
#endif
/* we are single user in that time so direct access to ve is OK */
int lve_namespace_init(struct light_ve *ve)
{
	struct lvp_ve_private *lvp = ve->lve_lvp;
	struct nsproxy *old_ns;
	struct fs_struct *old_fs;
	int rc = 0;

	/* no op */
	if (lve_no_namespaces)
		return 0;

	rwlock_init(&ve->lve_ns_lock);
	lve_namespace_get(lvp->lvp_default, &old_fs, &old_ns);
	if (old_fs == NULL || old_ns == NULL) {
		LVE_ERR("trying to create a namespace before setup\n");
		return -EPROTO;
	}


	rc = lve_namespace_clone(ve, old_ns, old_fs, NULL);
	if (rc == 0) {
		/* new root set - release old one from ns_get */
		lve_fs_put(old_fs);
		put_nsproxy(old_ns);
	}

	return rc;
}

int lve_namespace_enter(struct task_struct *task, struct light_ve *ve)
{
	struct nsproxy *old_nsp;
	struct nsproxy *lve_ns;
	struct fs_struct *lve_fs;
	struct fs_struct *new_fs = NULL; /* to shut gcc up */

	if (lve_no_namespaces)
		return -ENOSYS;

	lve_namespace_get(ve, &lve_fs, &lve_ns);
	if (lve_ns == NULL || lve_fs == NULL) {
		if (lve_ns)
			put_nsproxy(lve_ns);
		if (lve_fs)
			lve_fs_put(lve_fs);
		return -ENODEV;
	}

	new_fs = lve_copy_fs_struct(lve_fs);
	lve_fs_put(lve_fs);
	if (new_fs == NULL) {
		LVE_ERR("copy_fs_struct failed\n");
		/* release from get */
		put_nsproxy(lve_ns);
		return -ENOMEM;
	}

	task_lock(task);
	old_nsp = get_nsproxy(task->nsproxy);
	lve_fs = task->fs;
	task->fs = new_fs;
	task_unlock(task);

	lve_switch_ns(task, lve_ns);

	lve_fs_put(lve_fs); /* replaced with task fs */
	put_nsproxy(old_nsp);

	return 0;
}

int lve_namespace_enter_admin(struct light_ve *ve)
{
	struct nsproxy *old_nsp;
	struct fs_struct *old_fs;
	struct nsproxy *lve_ns;
	struct fs_struct *lve_fs;
	struct task_struct *task = current;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (lve_no_namespaces)
		return -ENOSYS;

	lve_namespace_get(ve, &lve_fs, &lve_ns);
	if (lve_ns == NULL || lve_fs == NULL) {
		if (lve_ns)
			put_nsproxy(lve_ns);
		if (lve_fs)
			lve_fs_put(lve_fs);
		return -ENODEV;
	}

	task_lock(task);
	old_nsp = get_nsproxy(task->nsproxy);
	old_fs = task->fs;
	task->fs = lve_fs;
	task_unlock(task);

	lve_switch_ns(task, lve_ns);

	lve_fs_put(old_fs);
	put_nsproxy(old_nsp);

	return 0;
}

int lve_namespace_assign(struct light_ve *ve)
{
	struct fs_struct *new_fs;
	struct nsproxy *new_ns;
	struct task_struct *task = current;

	task_lock(task);
	new_ns = get_nsproxy(task->nsproxy);
	new_fs = task->fs;
	lve_fs_get(new_fs);
	task_unlock(task);

	lve_namespace_switch(ve, new_fs, new_ns, true);

	return 0;
}
