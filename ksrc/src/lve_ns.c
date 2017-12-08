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
#include <linux/user_namespace.h>

#ifdef LVE_PER_VE
#include <linux/ve.h>
#include <net/net_namespace.h>
#endif

#include "lve_debug.h"
#include "lve_internal.h"
#include "light_ve.h"
#include "lve_os_compat.h"
#include "resource.h"
#include "kernel_exp.h"

static inline void lve_put_nsproxy(struct nsproxy *ns)
{
        if (atomic_dec_and_test(&ns->count)) {
#ifdef LVE_PER_VE
		ns->net_ns = get_net(ve0.ve_netns);
#endif
                free_nsproxy(ns);
        }
}


static struct nsproxy *lve_copy_ns(struct nsproxy *old_ns,
				struct fs_struct *new_fs)
{
	int rc;
	struct cred *new_cred;
	struct task_struct *tsk;

	tsk = kzalloc(sizeof(*tsk), GFP_KERNEL);
	if (tsk == NULL) {
		LVE_ERR("Cannot allocate fake task\n");
		return NULL;
	}

	tsk->nsproxy = old_ns;
	tsk->fs = new_fs;

	/*
 	 * We need to provide valid creds for copy_namespaces()
 	 * Just copy current creds and keep refcounters correct
 	 */
	new_cred = prepare_creds();
	if (new_cred == NULL) {
		LVE_ERR("cannot copy current task creds\n");
		kfree(tsk);
		return NULL;
	}

	atomic_inc(&new_cred->user->processes);
        tsk->cred = tsk->real_cred = new_cred;

	rc = lve_copy_namespaces(CLONE_NEWNS, tsk);
	old_ns = tsk->nsproxy;
	put_cred(new_cred);

	kfree(tsk);

	if (rc < 0) {
		LVE_ERR("can't copy namespaces");
		return ERR_PTR(rc);
	}

#ifdef LVE_PER_VE
	put_net(old_ns->net_ns);
#endif

	return old_ns;
}

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
	old_fs = ve->lve_namespace.lve_fs;
	old_ns = ve->lve_namespace.lve_nsproxy;

	ve->lve_namespace.lve_fs = new_fs;
	ve->lve_namespace.lve_nsproxy = new_ns;
	if (need_lock)
		write_unlock(&ve->lve_ns_lock);

	if (old_fs)
		lve_fs_put(old_fs);

	if (old_ns)
		lve_put_nsproxy(old_ns);
}

static void lve_namespace_get(struct light_ve *ve,
			      struct fs_struct **fs,
			      struct nsproxy **ns)
{
	read_lock(&ve->lve_ns_lock);
	*fs = ve->lve_namespace.lve_fs;
	*ns = ve->lve_namespace.lve_nsproxy;

	if (ve->lve_namespace.lve_fs)
		lve_fs_get(ve->lve_namespace.lve_fs);
	if (ve->lve_namespace.lve_nsproxy)
		get_nsproxy(ve->lve_namespace.lve_nsproxy);
	read_unlock(&ve->lve_ns_lock);
}

int lve_namespace_clone(struct light_ve *ve,
			       struct nsproxy *old_ns,
			       struct fs_struct *old_fs,
			       struct path *new_root
			      )
{
	int rc;
	struct fs_struct *new_fs;
	struct nsproxy *new_ns;

	new_fs = lve_copy_fs_struct(old_fs);
	if (new_fs == NULL)
		return -ENOMEM;

	if (new_root) {
		LVE_DBG("try to use root %s mnt %p\n",
			new_root->dentry->d_name.name, new_root->mnt);
		lve_set_fs_root_pwd(new_fs, new_root);
	}

	new_ns = lve_copy_ns(old_ns, new_fs);

	if (IS_ERR(new_ns)) {
		rc = PTR_ERR(new_ns);
		goto ns_copy_fail;
	}

	if (new_ns == NULL) {
		rc = -ENOMEM;
		goto ns_copy_fail;
	}

	lve_namespace_switch(ve, new_fs, new_ns, true);
	return 0;

ns_copy_fail:
	lve_fs_put(new_fs);
	return rc;
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

	if (test_and_set_bit(LVE_BIT_NS, &ve->lve_bit_flag))
		return -EBUSY;

	rc = lve_namespace_clone(ve, current->nsproxy, current->fs, &path);
	path_put(&path);

	if (rc != 0)
		clear_bit(LVE_BIT_NS, &ve->lve_bit_flag);

	return rc;
}

int lve_namespace_init(struct light_ve *ve)
{
	/* zero done via ve zalloc */
	rwlock_init(&ve->lve_ns_lock);

	return 0;
}

/* we are single user in that time so direct access to ve is OK */
int lve_namespace_setup(struct lvp_ve_private *lvp, struct light_ve *ve)
{
	struct nsproxy *old_ns;
	struct fs_struct *old_fs;
	int rc = 0;

	/* no op */
	if (lve_no_namespaces)
		return 0;

	lve_namespace_get(lvp->lvp_default, &old_fs, &old_ns);
	if (old_fs == NULL || old_ns == NULL) {
		LVE_ERR("trying to create a namespace before setup\n");
		return -EPROTO;
	}

	LVE_DBG("ns setup %p - %p/%p\n", ve, old_ns, old_fs);
	rc = lve_namespace_clone(ve, old_ns, old_fs, NULL);

	/* release references from lve_namespace_get() */
	lve_fs_put(old_fs);
	lve_put_nsproxy(old_ns);

	return rc;
}

int lve_namespace_enter(struct task_struct *task, struct light_ve *ve,
			struct lve_namespace *saved_ns)
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
			lve_put_nsproxy(lve_ns);
		if (lve_fs)
			lve_fs_put(lve_fs);
		return -ENODEV;
	}

	new_fs = lve_copy_fs_struct(lve_fs);
	lve_fs_put(lve_fs);
	if (new_fs == NULL) {
		LVE_ERR("copy_fs_struct failed\n");
		/* release from get */
		lve_put_nsproxy(lve_ns);
		return -ENOMEM;
	}

	task_lock(task);
	old_nsp = task->nsproxy;
	get_nsproxy(task->nsproxy);
	lve_fs = task->fs;
	task->fs = new_fs;
	task_unlock(task);

	switch_task_namespaces(task, lve_ns);

	if (saved_ns != NULL) {
		if (saved_ns->lve_fs != NULL)
			lve_fs_put(saved_ns->lve_fs);

		saved_ns->lve_fs = lve_fs;
	} else {
		lve_fs_put(lve_fs); /* replaced with task fs */
	}

	if (saved_ns != NULL) {
		if (saved_ns->lve_nsproxy != NULL)
			lve_put_nsproxy(saved_ns->lve_nsproxy);

		saved_ns->lve_nsproxy = old_nsp;
	} else {
		lve_put_nsproxy(old_nsp);
	}

	return 0;
}

int lve_namespace_leave(struct task_struct *task,
			struct lve_namespace *saved_ns)
{
	struct nsproxy *old_nsp;
	struct fs_struct *lve_fs;

	if (lve_no_namespaces)
		return -ENOSYS;

	task_lock(task);
	old_nsp = task->nsproxy;
	get_nsproxy(task->nsproxy);
	lve_fs = task->fs;
	task->fs = saved_ns->lve_fs;
	task_unlock(task);

	switch_task_namespaces(task, saved_ns->lve_nsproxy);

	lve_fs_put(lve_fs); /* replaced with task fs */
	lve_put_nsproxy(old_nsp);

	saved_ns->lve_nsproxy = NULL;
	saved_ns->lve_fs = NULL;

	return 0;
}

int lve_namespace_enter_admin(struct light_ve *ve,
			      struct lve_namespace *saved_ns)
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
			lve_put_nsproxy(lve_ns);
		if (lve_fs)
			lve_fs_put(lve_fs);
		return -ENODEV;
	}

	task_lock(task);
	old_nsp = task->nsproxy;
	get_nsproxy(task->nsproxy);
	old_fs = task->fs;
	task->fs = lve_fs;
	task_unlock(task);

	switch_task_namespaces(task, lve_ns);

	if (saved_ns != NULL) {
		if (saved_ns->lve_fs != NULL)
			lve_fs_put(saved_ns->lve_fs);

		saved_ns->lve_fs = old_fs;
	} else {
		lve_fs_put(old_fs);
	}

	if (saved_ns != NULL) {
		if (saved_ns->lve_nsproxy != NULL)
			lve_put_nsproxy(saved_ns->lve_nsproxy);

		saved_ns->lve_nsproxy = old_nsp;
	} else {
		lve_put_nsproxy(old_nsp);
	}

	return 0;
}

int lve_namespace_assign(struct light_ve *ve)
{
	struct fs_struct *new_fs;
	struct nsproxy *new_ns;
	struct task_struct *task = current;

	if (test_and_set_bit(LVE_BIT_NS, &ve->lve_bit_flag))
		return -EBUSY;

	task_lock(task);
	new_ns = task->nsproxy;
	get_nsproxy(task->nsproxy);
	new_fs = task->fs;
	lve_fs_get(new_fs);
	task_unlock(task);

	lve_namespace_switch(ve, new_fs, new_ns, true);

	return 0;
}

void lve_namespace_free(struct lve_namespace *saved_ns)
{
	if (saved_ns->lve_fs != NULL)
		lve_fs_put(saved_ns->lve_fs);

	if (saved_ns->lve_nsproxy != NULL)
		lve_put_nsproxy(saved_ns->lve_nsproxy);
}
