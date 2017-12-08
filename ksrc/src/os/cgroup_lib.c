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

#include "lve_debug.h"
#include "kernel_exp.h"
#include "cgroup_lib.h"

struct cgrp_mount cmnt[NR_SUBSYS];
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
	dget(d);
	mntget(m);
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
	if (!p->d_inode) {
		filp = ERR_PTR(-ENOENT);
		goto out_neg;
	}

	filp = cgrp_dentry_open(p, v);
	if (IS_ERR(filp))
		LVE_ERR("cgrp_param_open failed %ld\n", PTR_ERR(filp));

	/*
	 * cgrp_dentry_open() has taken the required references to
	 * mnt and dentry, so now drop the dentry reference from
	 * lookup_one_len().
	 */
out_neg:
	dput(p);
out:
	LVE_DBG("return %p\n", filp);
	return filp;
}

#ifdef HAVE___FPUT
void __fput(struct file *file);
#endif

void cgrp_param_release(struct file *filp)
{
	LVE_ENTER("close %p\n", filp);
#ifdef HAVE___FPUT
	/* avoid async release when possible */
	if (atomic_long_dec_and_test(&filp->f_count))
		__fput(filp);
#else
	filp_close(filp, NULL);
#endif
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

int cgrp_param_get_string(struct file *filp, char *buf, size_t nbytes)
{
	int rc = -EBADFD;
	loff_t off = 0;

	if (filp == NULL)
		return 0;

	LVE_ENTER("read %p %s\n", filp, filp->f_dentry->d_name.name);
	if (filp->f_op && filp->f_op->read) {
		mm_segment_t oldfs;

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		rc = (filp->f_op->read)(filp, buf, nbytes, &off);
		set_fs(oldfs);
	}
	if (rc > 0)
		rc = 0;
	LVE_DBG("read return %d\n", rc);
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
	int rc;
	/*
	 * NULL-terminated string with possible newline at the end
	 */
	char sval[23] = {0};
	s64 sval_res;

	rc = cgrp_param_get_string(filp, sval, sizeof(sval));

	if (rc < 0)
		goto out;

	rc = kstrtos64(sval, 0, &sval_res);
	if (rc == 0)
		return sval_res;
out:
	return (__s64)rc;
}

int cgrp_param_open_write_string(struct vfsmount *mnt, struct cgroup *cgrp,
				 const char *param, const char *buf,
				 unsigned count)
{
	struct file *filp;
	int rc;

	filp = cgrp_param_open(mnt, cgrp, param);
	if (IS_ERR(filp)) {
		LVE_ERR("can't open %s, rc=%ld\n", param, PTR_ERR(filp));
		return PTR_ERR(filp);
	}

	rc = cgrp_param_set_string(filp, buf, count);
	if (rc != 0)
		LVE_ERR("failed to write %.*s to %s, rc=%d\n",
			count, buf, param, rc);

	cgrp_param_release(filp);

	return rc;
}

int cgrp_param_open_read_string(struct vfsmount *mnt, struct cgroup *cgrp,
				 const char *param, char *buf,
				 unsigned count)
{
	struct file *filp;
	int rc;

	filp = cgrp_param_open(mnt, cgrp, param);
	if (IS_ERR(filp)) {
		LVE_ERR("can't open %s, rc=%ld\n", param, PTR_ERR(filp));
		return PTR_ERR(filp);
	}

	rc = cgrp_param_get_string(filp, buf, count);
	if (rc != 0)
		LVE_ERR("failed to read %.*s from %s, rc=%d\n",
			count, buf, param, rc);

	cgrp_param_release(filp);

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

unsigned long get_unlink_id(void) {
	static atomic_t counter = ATOMIC_INIT(0);

	return atomic_inc_return(&counter);
}

int cgrp_obfuscate(struct cgroup *cgrp, char *newname)
{
	struct inode *pinode;
	struct dentry *de, *new;
	int rc;

	de = cgrp->dentry;
	BUG_ON(de == NULL);
	pinode = cgrp->parent->dentry->d_inode;
	BUG_ON(pinode == NULL);

	LVE_DBG("obfuscating %.*s\n", de->d_name.len, de->d_name.name);
	LVE_DBG("cgrp = %p\n", cgrp);

	mutex_lock(&pinode->i_mutex);
	new = lookup_one_len(newname, cgrp->parent->dentry,
				     strlen(newname));
	if (IS_ERR(new)) {
		mutex_unlock(&pinode->i_mutex);
		rc = PTR_ERR(new);

		goto out;
	}

	rc = lve_vfs_rename(pinode, de, pinode, new);
	mutex_unlock(&pinode->i_mutex);

	dput(new);

out:
	if (rc != 0)
		LVE_ERR("failed to rename cgrp %.*s -> %s, rc %d\n",
			de->d_name.len, de->d_name.name, newname, rc);
	else
		LVE_DBG("cgrp_obfuscate newname=%s rc=%d\n", newname, rc);

	return rc;
}

int mount_cgroup_root_fs(struct cgrp_mount *cmnt)
{
	int i, n, rc;
	struct file_system_type *cgroup_fs_type;
	char *mnt_opts[NR_SUBSYS];
	char opts_memory[] = "memory";
	char opts_blk[] = "blkio";
#ifndef LVE_PER_VE
	char opts_freezer[] = "freezer";
#endif
#if RHEL_MAJOR < 7
	char opts_cpu[] = "name=fairsched,cpu,cpuacct,cpuset";
#else
	char opts_cpu[] = "cpu,cpuacct";
	char opts_cpuset[] = "cpuset";

	mnt_opts[CPUSET_SUBSYS] = opts_cpuset;
#endif
	mnt_opts[MEM_SUBSYS] = opts_memory;
	mnt_opts[BLK_SUBSYS] = opts_blk;
	mnt_opts[CPU_SUBSYS] = opts_cpu;
#ifndef LVE_PER_VE
	mnt_opts[FREEZER_SUBSYS] = opts_freezer;
#endif

	cgroup_fs_type = get_fs_type("cgroup");
	if (IS_ERR(cgroup_fs_type)) {
		LVE_ERR("cgroup filesystem type %ld", PTR_ERR(cgroup_fs_type));
		return PTR_ERR(cgroup_fs_type);
	}

	for (i = 0; i < NR_SUBSYS; i++) {
		cmnt[i].mnt_root = lve_call(vfs_kern_mount(cgroup_fs_type, 0,
			cgroup_fs_type->name, mnt_opts[i]),
			LVE_FAIL_MOUNT_CGROUP_ROOTFS, ERR_PTR(-ENOMEM));
		if (IS_ERR(cmnt[i].mnt_root)) {
			rc = PTR_ERR(cmnt[i].mnt_root);
			LVE_ERR("failed to mount cgroup(%s), rc=%d\n",
				mnt_opts[i], rc);
			goto err;
		}
	}

	return 0;

err:
	for (n = 0; n < i; n++) {
		mntput(cmnt[n].mnt_root);
		cmnt[n].mnt_root = NULL;
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

static inline struct cgroup *__d_cgrp(struct dentry *dentry)
{
	return dentry->d_fsdata;
}

struct cgroup *lve_cgroup_get_root(struct vfsmount *mnt)
{
	return mnt->mnt_root->d_fsdata;
}

struct cgroup *lve_cgroup_kernel_open(struct cgroup *parent,
		enum lve_cgroup_open_flags flags, const char *name)
{
	struct dentry *dentry;
	struct cgroup *cgrp;
	int ret = 0;

	mutex_lock_nested(&parent->dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	dentry = lookup_one_len(name, parent->dentry, strlen(name));
	cgrp = ERR_CAST(dentry);
	if (IS_ERR(dentry))
		goto out;

	if (flags & LVE_CGRP_CREAT) {
		if ((flags & LVE_CGRP_EXCL) && dentry->d_inode)
			ret = -EEXIST;
		else if (!dentry->d_inode)
			ret = vfs_mkdir(parent->dentry->d_inode, dentry, 0755);
	}
	if (!ret && dentry->d_inode) {
		cgrp = __d_cgrp(dentry);
		atomic_inc(&cgrp->count);
	} else {
		cgrp = ret ? ERR_PTR(ret) : NULL;
	}
	dput(dentry);
out:
	mutex_unlock(&parent->dentry->d_inode->i_mutex);
	return cgrp;
}

int lve_cgroup_kernel_remove(struct cgroup *parent, char *name)
{
	struct dentry *dentry;
	int ret;

	mutex_lock_nested(&parent->dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	dentry = lookup_one_len(name, parent->dentry, strlen(name));
	ret = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		LVE_ERR("failed to look up %s for rmdir, rc %d\n", name, ret);
		goto out;
	}
	ret = -ENOENT;
	if (dentry->d_inode)
		ret = vfs_rmdir(parent->dentry->d_inode, dentry);
	if (ret < 0)
		LVE_ERR("failed to rmdir %s, rc %d", name, ret);
	dput(dentry);
out:
	mutex_unlock(&parent->dentry->d_inode->i_mutex);
	return ret;
}

void lve_cgroup_kernel_close(struct cgroup *cgrp)
{
	atomic_dec(&cgrp->count);
}
