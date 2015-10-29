#ifndef _LVE_KERNEL_EXP_
#define _LVE_KERNEL_EXP_

#include <linux/profile.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <bc/beancounter.h>

struct fs_struct;
struct namespace;
struct path;
struct vfsmount;
struct file_system_type;
struct cgroup;
struct task_struct;
struct mnt_namespace;
struct user_beancounter;

struct fs_struct * lve_copy_fs_struct(struct fs_struct *);
void lve_free_fs_struct(struct fs_struct *fs_struct);
int lve_put_mnt_ns(struct mnt_namespace *mnt);
#ifndef HAVE_KILL_FS
void lve_fs_put(struct fs_struct *fs);
#endif

void lve_jprobe_ret(void);
int lve_jprobes_reg(struct jprobe **p, int num);
void lve_jprobes_unreg(struct jprobe **p, int num);
void lve_ns_put_final(struct namespace *namespace);

void lve_task_put_final(struct task_struct *arg);
static inline void lve_task_put(struct task_struct *t)
{
	if (atomic_dec_and_test(&t->usage))
		lve_task_put_final(t);
}

void lve_set_fs_root_pwd(struct fs_struct *f, struct path *p);
void * lve_sym_get(const char *name);
#define lve_symbol_get(x) ((typeof(&x))(lve_sym_get(MODULE_SYMBOL_PREFIX #x)))

struct nsproxy *lve_nsproxy_dup(struct nsproxy *arg);
void lve_switch_ns(struct task_struct *tsk, struct nsproxy *new);
void lve_free_nsproxy(struct nsproxy *ns);
struct mnt_namespace *lve_copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,
		struct fs_struct *new_fs);

int lve_printk(unsigned long ip, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

extern rwlock_t lve_tasklist_lock;
struct file_system_type *lve_get_fs_type(const char *);
struct vfsmount *lve_vfs_kern_mount(struct file_system_type *type, int flags, const char *name, void *p);

void lve_check_for_release(struct cgroup *cgrp);
int lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk);

void lve_ub_prechange_snapshot(struct user_beancounter *ub, int *precharge);

extern spinlock_t lve_vfsmount_lock;
void lve_umount_tree(struct vfsmount *mnt, int propagate, struct list_head *kill);
void lve_release_mounts(struct list_head *head);

struct task_struct *lve_find_task_by_vpid(pid_t nr);
int lve_ub_attach_task(struct user_beancounter *bc, struct task_struct *task);

extern struct cgroup *lve_mem_cgroup_root;
extern struct cgroup *lve_ub_cgroup_root;

extern struct vfsmount *lve_ub_cgroup_mnt;
extern struct vfsmount *lve_ub_bound_cgroup_mnt;

struct user_beancounter *lve_get_beancounter_byuid(uid_t uid, int status);

void lve_ub_get_mem_cgroup_parms(struct user_beancounter *ub, struct ubparm *p,
		struct ubparm *s, struct ubparm *k);

void __user *lve_compat_alloc_user_space(unsigned long len);

#ifndef HAVE_2ARGS_CGROUP_ATTACH_TASK
extern struct mutex lve_cgroup_mutex;
int lve_cgroup_attach_task(struct cgroup *, struct task_struct *, bool);
#endif

struct cgroup *lve_get_ub_cgroup_root(void);
struct cgroup *lve_get_mem_cgroup_root(void);

#endif
