#ifndef _LVE_KERNEL_EXP_
#define _LVE_KERNEL_EXP_

#include <linux/profile.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/spinlock.h>

struct fs_struct;
struct namespace;
struct path;
struct vfsmount;
struct file_system_type;
struct cgroup;
struct task_struct;
struct mnt_namespace;
struct cgroup_subsys_state;
struct gang_set;
enum freezer_state;
struct mem_cgroup;

struct task_struct *lve_find_task_by_vpid(pid_t nr);

struct fs_struct * lve_copy_fs_struct(struct fs_struct *);
void lve_free_fs_struct(struct fs_struct *fs_struct);

void lve_ns_put_final(struct namespace *namespace);

void lve_set_fs_root_pwd(struct fs_struct *f, struct path *p);

int lve_cgroup_kernel_attach(struct cgroup *cgrp, struct task_struct *tsk);

int lve_copy_namespaces(unsigned long flags, struct task_struct *tsk);

struct user_beancounter;
struct ubparm;

void lve_ub_prechange_snapshot(struct user_beancounter *ub, int *precharge);
int lve_ub_attach_task(struct user_beancounter *bc, struct task_struct *task);

#ifdef HAVE_GET_BEANCOUNTER_BYUID
struct user_beancounter *lve_get_beancounter_byuid(uid_t uid, int create);
#endif
#ifdef HAVE_GET_BEANCOUNTER_BYNAME
struct user_beancounter *lve_get_beancounter_by_name(const char *name, int create);
#endif

struct cgroup *lve_get_ub_cgroup_root(void);

struct cgroup_subsys_state *lve_ub_get_css(struct user_beancounter *ub, int idx);

int lve_freezer_change_state(struct cgroup *c, enum freezer_state s);
int lve_try_to_free_gang_pages(struct gang_set *gs, gfp_t gfp);

extern rwlock_t lve_css_set_lock;
unsigned long lve_try_to_free_mem_cgroup_pages(struct mem_cgroup *mem,
						unsigned long nr_pages,
						gfp_t gfp_mask, bool noswap);

struct mem_cgroup *lve_mem_cgroup_from_cont(struct cgroup *cont);
extern void ub_fini_cgroup(void);


#ifndef HAVE_BSEARCH
void *bsearch(const void *key, const void *base, size_t num, size_t size,
	      int (*cmp)(const void *key, const void *elt));
#else
#include <linux/bsearch.h>
#endif


#endif
