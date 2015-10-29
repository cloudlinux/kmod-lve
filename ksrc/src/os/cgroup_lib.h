#ifndef _LVE_CGROUP_LIB_H_
#define _LVE_CGROUP_LIB_H_

#include <linux/version.h>

struct cgroup;
struct vfsmount;

enum subsys_id {
	CPU_SUBSYS = 0,
#if RHEL_MAJOR > 6
	CPUSET_SUBSYS,
	MEM_SUBSYS,
#endif
	NR_SUBSYS,
};

struct cgrp_mount {
	struct vfsmount *mnt_root;
	struct cgroup *cgrp_root;
};

struct params {
	const char *p_name;
	struct vfsmount **p_mnt;
};

#define MAX_GRP_NAMESZ 20

int cgrp_obfuscate(struct cgroup *cgrp);

int mount_cgroup_root_fs(struct cgrp_mount *cmnt);
void umount_cgroup_root_fs(struct cgrp_mount *cmnt);

extern u64 ioprio_weight[];

struct file *cgrp_param_open(struct vfsmount *vfsmnt,
				   struct cgroup *cgrp, const char *param);
void cgrp_param_release(struct file *filp);
int cgrp_param_set_u64(struct file *filp, __u64 data);
int cgrp_param_set_string(struct file *filp, const char *buf, size_t nbytes);
int cgrp_populate_dir(struct cgroup *cgrp, struct file **filp,
		struct params *p, int nr_params);
/* return <0 if error */
__s64 cgrp_param_get(struct file *filp);
#endif
