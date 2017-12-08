#ifndef _LVE_CGROUP_LIB_H_
#define _LVE_CGROUP_LIB_H_

#include <linux/version.h>
#include "lve_kmod_c.h"

struct cgroup;
struct vfsmount;


enum subsys_id {
	CPU_SUBSYS = 0,
#if RHEL_MAJOR > 6
	CPUSET_SUBSYS,
#endif
	MEM_SUBSYS,
	BLK_SUBSYS,
#ifndef LVE_PER_VE
	FREEZER_SUBSYS,
#endif
	NR_SUBSYS,
};

enum lve_cgroup_open_flags {
	LVE_CGRP_CREAT      = 0x0001,	/* create if not found */
	LVE_CGRP_EXCL       = 0x0002,	/* fail if already exist */
};

static inline int get_flags(void)
{
#ifndef LVE_PER_VE
	return LVE_CGRP_CREAT;
#else
	return 0;
#endif
}

struct cgrp_mount {
	struct vfsmount *mnt_root;
	struct cgroup *cgrp_root;
};

extern struct cgrp_mount cmnt[NR_SUBSYS];

struct params {
	const char *p_name;
	struct vfsmount **p_mnt;
};

struct lvp_private {
	struct cgroup *lve_cpu_root;
#if RHEL_MAJOR > 6
	struct cgroup *lve_cpuset_root;
	struct cgroup *lve_memory_root;
#endif
	struct cgroup *lve_cpu_acct;
	struct cgroup *lve_io_root;
	struct cgroup *lve_freezer_root;
};

enum param_id {
	PARAM_CPU_STAT = 0,
	PARAM_CPU_LIMIT,
	PARAM_CPU_CHWT,
	PARAM_CPUS_LIMIT,
	PARAM_CPU_MAX
};

enum cgrp_id {
	CG_CPU_GRP = 0,
	CG_CPUSET_GRP,
	CG_UB_GRP,
	CG_MEM_GRP,
	CG_BLK_GRP,
	CG_FREEZER_GRP,
	CG_MAX_GRP
};

/* connected to each creates context / LVE */
struct c_private {
#if OPENVZ_VERSION > 0
	struct user_beancounter *lve_ub;
#endif
	struct cgroup *cgrp[CG_MAX_GRP];
	struct file *cpu_filps[PARAM_CPU_MAX];
	unsigned long unlink_id;
	int flags;
};

/* we can't use an container_of macro due type check error */
#define os_lve(cp) ((struct light_ve *)( (char *)(cp) - \
		    offsetof(struct light_ve ,lve_private) ))

extern struct cgrp_mount cmnt[NR_SUBSYS];

#define MAX_GRP_NAMESZ 25
#define UNLINK_FORMAT "rmv-%lu"

#ifdef LVE_PER_VE
#define LVP_FMT "%lu"
#else
#define LVP_FMT "lvp%u"
#endif

#define LVE_FMT "lve%u"

unsigned long get_unlink_id(void);
int cgrp_obfuscate(struct cgroup *cgrp, char *unlink_name);


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

int cgrp_param_open_write_string(struct vfsmount *mnt, struct cgroup *cgrp,
				 const char *param, const char *buf,
				 unsigned count);

int cgrp_param_open_read_string(struct vfsmount *mnt, struct cgroup *cgrp,
				 const char *param, char *buf,
				 unsigned count);
struct cgroup *lve_cgroup_get_root(struct vfsmount *mnt);
struct cgroup *lve_cgroup_kernel_open(struct cgroup *parent,
		enum lve_cgroup_open_flags flags, const char *name);
int lve_cgroup_kernel_remove(struct cgroup *parent, char *name);
void lve_cgroup_kernel_close(struct cgroup *cgrp);
#endif
