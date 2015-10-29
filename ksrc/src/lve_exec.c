#include "lve_kmod_c.h"

#ifdef HAVE_EXEC_NOTIFIER

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/virtinfo.h>
#include <linux/binfmts.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include "lve_internal.h"
#include "resource.h"

struct lve_exec_entry *
lve_exec_find_entry(struct lvp_ve_private *lvp, struct dentry *dentry)
{
	struct lve_exec_entry *e;

	list_for_each_entry(e, &lvp->lvp_exec_entries, list) {
		if (e->path.dentry == dentry)
			return e;
	}

	return NULL;
}

int lve_exec_add_file(struct lvp_ve_private *lvp, char *name)
{
	struct lve_exec_entry *e;
	struct nameidata nd;
	int rc;

	rc = lve_path_lookup(name, LOOKUP_FOLLOW, &nd);
	if (rc)
		goto out;

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e) {
		path_put(&nd.path);
		rc = -ENOMEM;
		goto out;
	}

	e->path = nd.path;
	write_lock(&lvp->lvp_exec_lock);
	if (lve_exec_find_entry(lvp, e->path.dentry) != NULL) {
		write_unlock(&lvp->lvp_exec_lock);
		path_put(&e->path);
		kfree(e);
		goto out;
	}
	list_add_tail(&e->list, &lvp->lvp_exec_entries);
	write_unlock(&lvp->lvp_exec_lock);
out:
	return rc;
}

int lve_exec_del_file(struct lvp_ve_private *lvp, char *name)
{
	struct lve_exec_entry *e, *e_next;
	LIST_HEAD(list);
	struct nameidata nd;
	int rc;

	if (name) {
		rc = lve_path_lookup(name, LOOKUP_FOLLOW, &nd);
		if (rc)
			goto out;
	}

	rc = -ESRCH;
	write_lock(&lvp->lvp_exec_lock);
	list_for_each_entry_safe(e, e_next, &lvp->lvp_exec_entries, list) {
		if (!name || e->path.dentry == nd.path.dentry) {
			path_put(&e->path);
			list_move(&e->list, &list);
			rc = 0;
			if (name)
				break;
		}
	}
	write_unlock(&lvp->lvp_exec_lock);

	if (name)
		path_put(&nd.path);

	list_for_each_entry_safe(e, e_next, &list, list) {
		kfree(e);
	}
out:
	return rc;
}

static int lve_exec_need_enter(struct lvp_ve_private *lvp,
			       struct dentry *dentry)
{
	int rc = 0;

	read_lock(&lvp->lvp_exec_lock);
	if (lve_exec_find_entry(lvp, dentry) != NULL)
		rc = 1;
	read_unlock(&lvp->lvp_exec_lock);

	return rc;
}

static int lve_exec_notify(struct vnotifier_block *self,
			   unsigned long event, void *arg, int old_ret)
{
	struct linux_binprm *bprm;
	uid_t euid;
	int rc;

	if (event != VIRTINFO_EXEC)
		return old_ret;

	bprm = arg;
	euid = lve_cred_euid(bprm->cred);

	/* Should be ignored for UID=0 (CKSIX-40) */
	if (euid == 0)
		return NOTIFY_OK;

	/* Should be ignored if already in LVE */
	if (NODEID_LVEID(lve_node_id(current)) != ROOT_LVE)
		return NOTIFY_OK;

	rc = lve_exec_need_enter(TASK_VE_PRIVATE(current),
				 bprm->file->f_dentry);
	if (!rc)
		return NOTIFY_OK;

	rc = _lve_enter(current, euid,
			&(struct ve_enter){ NULL, LVE_ENTER_NAMESPACE });
	if (rc)
		return NOTIFY_FAIL;

	return NOTIFY_OK;
}

static struct vnotifier_block lve_exec_nb = {
	.notifier_call = lve_exec_notify,
};


int lvp_exec_init(struct lvp_ve_private *lvp)
{
	INIT_LIST_HEAD(&lvp->lvp_exec_entries);
	rwlock_init(&lvp->lvp_exec_lock);

	return 0;
}

void lvp_exec_fini(struct lvp_ve_private *lvp)
{
	int rc;

	rc = lve_exec_del_file(lvp, NULL);
	BUG_ON(rc != 0 && rc != -ESRCH);
}

int lve_exec_init(void)
{
	virtinfo_notifier_register(VITYPE_GENERAL, &lve_exec_nb);

	return 0;
}

void lve_exec_fini(void)
{
	virtinfo_notifier_unregister(VITYPE_GENERAL, &lve_exec_nb);
}

#endif
