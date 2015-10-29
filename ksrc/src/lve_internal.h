#ifndef _LVE_INTERNAL_
#define _LVE_INTERNAL_

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/radix-tree.h>

#include "lve-api.h"
#include "kernel_exp.h"
#include "lve_os_compat.h"
#include "tags.h"

#define RESERVED_UID	100
#define RESERVED_GID	100
#define ROOT_LVE	(0)


struct lve_stats {
	spinlock_t enter_lock;
	long	st_enters;	/* counted enters */
	long	st_err_enters;	/* fail on lve_enter */
};


struct light_ve {
	struct list_head	lve_link;
	struct list_head	lve_init_link;
	struct proc_dir_entry	*lve_proc_dir;
	atomic_t		lve_refcnt;
	uint32_t                lve_id;
	lve_limits_t		lve_limits;
	rwlock_t		lve_ns_lock;
	struct fs_struct        *lve_fs;
	struct nsproxy		*lve_nsproxy;
	struct lve_stats	lve_stats;
	unsigned long		lve_custom:1,
				lve_disable:1;
	unsigned long		lve_unlinked:1;
	unsigned long		lve_bit_flag;
	struct lvp_ve_private	*lve_lvp;
	char			lve_private[0]; // private data
};

enum lve_bits {
	LVE_BIT_INIT,
	LVE_BIT_ERROR,
};

enum lve_unlink_target {
	LVE_UNLINK_VE,
	LVE_UNLINK_ALL,
	LVE_UNLINK_DEFAULT
};

struct c_private;

static inline struct c_private *lve_private(struct light_ve *lve)
{
	return ((struct c_private *)(&lve->lve_private[0]));
}

struct light_ve *lve_find(uint32_t ve_id);
struct light_ve *lve_alloc(struct lvp_ve_private *lvp, uint32_t ve_id);
struct light_ve * lve_find_or_alloc(uint32_t ve_id);
void lve_last_put(struct light_ve *ptr);
void lve_unlink(struct lvp_ve_private *lvp, enum lve_unlink_target target, struct light_ve *ve);
void lve_exit_task(struct task_struct *task, struct switch_data *sw_data);

static inline long
light_ve_get(struct light_ve *ptr)
{
	/* Atomically adds @i to @v and returns @i + @v */
	return atomic_inc_return(&ptr->lve_refcnt);
}
#if 1
static inline void
light_ve_put(struct light_ve *ptr)
{
	int refcnt;

	refcnt = atomic_dec_return(&ptr->lve_refcnt);
	BUG_ON(refcnt < 0);
	if (refcnt == 0)
		lve_last_put(ptr);
}
#endif
#if 0
#define light_ve_put(ptr) 	{ \
	printk("%s:%d - lve put %p %d\n", \
	    __FILE__, __LINE__, ptr, atomic_read(&ptr->lve_refcnt)); \
	if (atomic_dec_and_test(&ptr->lve_refcnt)) \
		lve_free(ptr);					\
	}
#endif

int lve_list_init(void);
void lve_list_fini(void);

/** lve_resource.c */
struct lve_usage;
int lve_resources_init(struct light_ve *ve);
int lve_resources_free(struct light_ve *ve);

int lve_resources_setup(struct light_ve *lve, lve_limits_t limits);
int lve_resources_unlink(struct light_ve *lve);
int lve_resource_push(struct task_struct *task, struct light_ve *ve, uint32_t flags);

void lve_resource_usage(struct light_ve *ve, struct lve_usage *buf);
void lve_resource_usage_clear(struct light_ve *ve);

void lve_resource_fail(struct task_struct * task, int resource);

int lve_namespace_init(struct light_ve *ve);
int lve_namespace_fini(struct light_ve *ve);
int lve_namespace_enter(struct task_struct *task, struct light_ve *ve);
int lve_namespace_enter_admin(struct light_ve *ve);
int lve_namespace_set_default(void);
void lve_namespace_unset_default(void);
int lve_namespace_set_root(struct light_ve *ve, const char __user *root);
int lve_namespace_assign(struct light_ve *ve);

int lve_start(void);
int is_in_lve(struct task_struct *task);

extern unsigned long la_history[15*60*HZ/LOAD_FREQ + 1];
extern signed la_ptr;

extern unsigned lve_stats;
extern unsigned lve_ubc;

#ifdef HAVE_EXEC_NOTIFIER
struct lve_exec_entry {
	struct list_head	list;
	struct path		path;
};

int lve_exec_add_file(struct lvp_ve_private *lvp, char *name);
int lve_exec_del_file(struct lvp_ve_private *lvp, char *name);
#endif

int _lve_enter(struct task_struct *enter_task, uint32_t ve_id,
		struct ve_enter *ve_data);

/* procfs */
extern int lve_stats_dir_init(struct light_ve *lve);
extern void lve_stats_dir_fini(struct light_ve *lve);

#endif
