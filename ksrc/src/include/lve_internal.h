#ifndef _LVE_INTERNAL_
#define _LVE_INTERNAL_

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/radix-tree.h>

#include "lve-api.h"
#include "kernel_exp.h"
#include "lve_os_compat.h"
#include "lve_net.h"
#include "tags.h"

#define RESERVED_UID	100
#define RESERVED_GID	100

static inline bool lve_id_disabled(uint32_t lve_id) {
	if ((lve_id == ROOT_LVE) || (lve_id == SELF_LVE))
		return true;
	return false;
}

struct lve_stats {
	spinlock_t enter_lock;
	long	st_enters;	/* counted enters */
	long	st_err_enters;	/* fail on lve_enter */
};

static inline 
void lve_stat_init(struct lve_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	spin_lock_init(&stats->enter_lock);
}

struct light_ve {
	struct list_head	lve_link;
	struct list_head	lve_init_link;
	struct proc_dir_entry	*lve_proc_dir;
	atomic_t		lve_refcnt;
	atomic_t		lve_tags;
	wait_queue_head_t	lve_tags_wq;
	uint32_t                lve_id;
	lve_limits_t		lve_limits;
	rwlock_t		lve_ns_lock;
	struct lve_namespace	lve_namespace;
	struct lve_net		lve_net;
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
	LVE_BIT_NS,
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

struct light_ve *_lve_find(struct lvp_ve_private *lvp, uint32_t lve_id);
struct light_ve *lve_find(uint32_t lvp_id, uint32_t ve_id);

struct light_ve *lve_alloc(struct lvp_ve_private *lvp, uint32_t ve_id);
struct light_ve * lve_find_or_alloc(uint32_t lvp_id, uint32_t ve_id);
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

int lve_resources_setup(struct light_ve *lve, lve_limits_t limits, bool first);
int lve_resources_unlink(struct light_ve *lve);
int lve_resource_push(struct task_struct *task, struct light_ve *ve,
		      struct switch_data *sw_data);
int lve_resource_pop(struct task_struct *task, struct light_ve *ve,
		     struct switch_data *sw_data);

void lve_resource_usage(struct light_ve *ve, struct lve_usage *buf);
void lve_resource_usage_clear(struct light_ve *ve);

void lve_resource_fail(struct task_struct * task, int resource);

int lve_namespace_init(struct light_ve *ve);
int lve_namespace_setup(struct lvp_ve_private *parent, struct light_ve *ve);
int lve_namespace_fini(struct light_ve *ve);
int lve_namespace_enter(struct task_struct *task, struct light_ve *ve,
			struct lve_namespace *saved_ns);
int lve_namespace_enter_admin(struct light_ve *ve,
			      struct lve_namespace *saved_ns);
int lve_namespace_leave(struct task_struct *task,
			struct lve_namespace *saved_ns);
int lve_namespace_set_default(void);
void lve_namespace_unset_default(void);
int lve_namespace_set_root(struct light_ve *ve, const char __user *root);
int lve_namespace_assign(struct light_ve *ve);
void lve_namespace_free(struct lve_namespace *ns);
int lve_namespace_clone(struct light_ve *ve, struct nsproxy *old_ns, struct fs_struct *old_fs,
	struct path *new_root);

int is_in_lve(struct task_struct *task);

extern unsigned long la_history[15*60*HZ/LOAD_FREQ + 1];
extern signed la_ptr;

extern unsigned lve_stats;
extern unsigned lve_ubc;

struct lve_exec_entry {
	struct list_head	list;
	struct path		path;
};

int lve_exec_add_file(struct lvp_ve_private *lvp, char *name);
int lve_exec_del_file(struct lvp_ve_private *lvp, char *name);

int _lve_enter(struct task_struct *enter_task, uint32_t lvp, uint32_t ve_id,
		struct ve_enter *ve_data);

/* procfs */
extern int lve_stats_dir_init(struct light_ve *lve);
extern void lve_stats_dir_fini(struct light_ve *lve);

void light_ve_free(struct light_ve *ptr);

/* mapping */
extern const struct seq_operations lve_map_op;
/**
 * allocate a mapping for a LVE to corresponded LVP
 */
int lve_lvp_map_add(uint32_t lve_id, uint32_t lvp_id);
/**
 * remove mapping as part of lve remove process
 */
void lve_lvp_map_del(uint32_t lve_id);

/**
 * move LVE betwen LVP - not implemented now
 */
int lve_lvp_map_move(uint32_t lve_id, uint32_t lvp_id);
/** 
 * take a LVP (reseller id) for corresponded LVE
 */
uint32_t lve_lvp_map_get(uint32_t lve_id);

void lve_kill_all_threads(uint32_t ve_id, uint32_t lve_id);
#endif
