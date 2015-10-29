#include <linux/kernel.h>
#include <linux/cgroup.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/version.h>

#include "../lve_debug.h"
#include "../kernel_exp.h"
#include "cgroup_lib.h"

u64 ioprio_weight[] = {320, 365, 410, 460, 500, 550, 600, 640};

#ifdef HAVE_DENTRY_OPEN_PATH
struct file *cgrp_dentry_open(struct dentry *d, struct vfsmount *m)
{
	struct path path;

	path.mnt = m;
	path.dentry = d;

	return dentry_open(&path, O_RDWR, current_cred());
}
#else
struct file *cgrp_dentry_open(struct dentry *d, struct vfsmount *m)
{
	return dentry_open(d, m, O_RDWR, current_cred());
}
#endif

struct file *cgrp_param_open(struct vfsmount *v, struct cgroup *cgrp,
		const char *param)
{
	struct file *filp;
	struct dentry *grp = cgrp->dentry;
	struct dentry *p;

	LVE_ENTER("open %s - %p %p\n", param, v, cgrp);

	mutex_lock(&grp->d_inode->i_mutex);
	p = lve_call(lookup_one_len(param, grp, strlen(param)),
			LVE_FAIL_CGRP_PARAM_GET, ERR_PTR(-ENOMEM));
	mutex_unlock(&grp->d_inode->i_mutex);
	if (IS_ERR(p)) {
		LVE_ERR("cgrp_param_lookup %s failed with %ld\n", param, PTR_ERR(p));
		filp = (void *)p;
		goto out;
	}

	mntget(v);
	filp = cgrp_dentry_open(p, v);
	if (IS_ERR(filp))
		LVE_ERR("cgrp_param_open failed %ld\n", PTR_ERR(filp));
out:
	LVE_DBG("return %p\n", filp);
	return filp;
}

void cgrp_param_release(struct file *filp)
{
	LVE_ENTER("close %p\n", filp);
	filp_close(filp, NULL);
}

int cgrp_param_set_string(struct file *filp, const char *buf, size_t nbytes)
{
	int rc = -EBADFD;
	loff_t off = 0;

	if (filp == NULL)
		return 0;

	LVE_ENTER("write %p %s\n", filp, filp->f_dentry->d_name.name);
	if (filp->f_op && filp->f_op->write) {
		mm_segment_t oldfs;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		rc = (filp->f_op->write)(filp, buf, nbytes, &off);
		set_fs(oldfs);
	}
	if (rc > 0)
		rc = 0;
	LVE_DBG("write return %d\n", rc);
	return rc;
}

int cgrp_param_set_u64(struct file *filp, __u64 data)
{
	char sval[22] = {0};

	snprintf(sval, sizeof(sval), "%llu", data);

	return cgrp_param_set_string(filp, sval, sizeof(sval));
}

/* return <0 if error */
__s64 cgrp_param_get(struct file *filp)
{
	__s64 rc = -EBADFD;
	loff_t off = 0;

	if (filp == NULL)
		return 0;

	LVE_ENTER("read %s\n", filp->f_dentry->d_name.name);
	if (filp->f_op && filp->f_op->read) {
		mm_segment_t oldfs;
		char sval[30];

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		rc = (filp->f_op->read)(filp, sval, sizeof(sval), &off);
		set_fs(oldfs);
		if (rc > 0) {
			/* XXX */
			rc = simple_strtol(sval, NULL, 0);
		}
	}

	LVE_DBG("read return %lld\n", rc);
	return rc;
}

int cgrp_populate_dir(struct cgroup *cgrp, struct file **filp,
		struct params *p, int nr_params)
{
	int i, rc = 0;
	const char *p_name;
	struct vfsmount *p_mnt;

	for (i = 0; i < nr_params; i++) {
		p_name = p[i].p_name;
		p_mnt = *p[i].p_mnt;

		filp[i] = cgrp_param_open(p_mnt, cgrp, p_name);
		if (IS_ERR(filp[i])) {
			LVE_ERR("can't setup param %s <> %ld\n", p_name,
				PTR_ERR(filp[i]));
			rc = PTR_ERR(filp[i]);
			filp[i] = NULL;
			break;
		}
	}

	return rc;
}

int cgrp_obfuscate(struct cgroup *cgrp)
{
	static atomic_t counter = ATOMIC_INIT(0);
	char newname[20] = "";
	struct inode *pinode;
	struct dentry *de, *new;
	int rc, i;

	de = cgrp->dentry;
	BUG_ON(de == NULL);
	pinode = cgrp->parent->dentry->d_inode;
	BUG_ON(pinode == NULL);

	LVE_DBG("obfuscating %.*s\n", de->d_name.len, de->d_name.name);

	do {
		mutex_lock(&pinode->i_mutex);

		/* Obfuscated already? */
		for (i = 0; i < (int)de->d_name.len - 5; i++) {
			/* Not zero-terminated for strstr :( */
			if (!memcmp(de->d_name.name + i, "-rmv-", 5)) {
				mutex_unlock(&pinode->i_mutex);
				rc = 0;
				goto out;
			}
		}

		snprintf(newname, sizeof(newname), "%.*s-rmv-%d",
			 de->d_name.len, de->d_name.name,
			 atomic_inc_return(&counter));

		new = lookup_one_len(newname, cgrp->parent->dentry,
				     strlen(newname));
		if (IS_ERR(new)) {
			mutex_unlock(&pinode->i_mutex);
			rc = PTR_ERR(new);
			goto out;
		}

		rc = lve_vfs_rename(pinode, de, pinode, new);

		dput(new);
		mutex_unlock(&pinode->i_mutex);
	} while (unlikely(rc == -EEXIST));

out:
	LVE_DBG("cgrp_obfuscate newname=%s rc=%d\n", newname, rc);

	return rc;
}

int mount_cgroup_root_fs(struct cgrp_mount *cmnt)
{
	int i, n, rc;
	struct file_system_type *cgroup_fs_type;
	char *mnt_opts[NR_SUBSYS];
#if RHEL_MAJOR < 7
	char opts_cpu[] = "name=fairsched,cpu,cpuacct,cpuset";
#else
	char opts_cpu[] = "cpu,cpuacct";
	char opts_cpuset[] = "cpuset";
	char opts_memory[] = "memory";

	mnt_opts[CPUSET_SUBSYS] = opts_cpuset;
	mnt_opts[MEM_SUBSYS] = opts_memory;
#endif
	mnt_opts[CPU_SUBSYS] = opts_cpu;

	cgroup_fs_type = lve_get_fs_type("cgroup");
	if (IS_ERR(cgroup_fs_type)) {
		LVE_ERR("cgroup filesystem type %ld", PTR_ERR(cgroup_fs_type));
		return PTR_ERR(cgroup_fs_type);
	}

	for (i = 0; i < NR_SUBSYS; i++) {
		cmnt[i].mnt_root = lve_vfs_kern_mount(cgroup_fs_type, 0,
		cgroup_fs_type->name, mnt_opts[i]);
		if (IS_ERR(cmnt[i].mnt_root)) {
			rc = PTR_ERR(cmnt[i].mnt_root);
			goto err;
		}
	}

	return 0;

err:
	for (n = 0; n < i; n++) {
		mntput(cmnt[i].mnt_root);
		cmnt[i].mnt_root = NULL;
	}

	return rc;
}

void umount_cgroup_root_fs(struct cgrp_mount *cmnt)
{
	int i;

	for (i = 0; i < NR_SUBSYS; i++) {
		if (cmnt[i].mnt_root != NULL)
			mntput(cmnt[i].mnt_root);
	}
}
