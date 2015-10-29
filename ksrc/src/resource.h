#ifndef __LVE_OS_RESOURCE_H_
#define __LVE_OS_RESOURCE_H_

#include <linux/sched.h>
#ifdef LVE_PER_VE
#include <linux/ve.h>
#endif
#include <linux/version.h>

struct ve_struct;
struct lvp_private;

struct lvp_ve_private {
	uint32_t		lvp_id; /* mostly for init */
	rwlock_t		lvp_lock;
	struct list_head	lvp_list;
	struct radix_tree_root	lvp_list_tree;
	struct proc_dir_entry	*lvp_proc_root;
	struct proc_dir_entry	*lvp_stats_root;
#ifdef LVE_PER_VE
	struct ve_struct	*lvp_ve;
#endif
	unsigned long 		lvp_last_reset;
	uint64_t		lvp_grace_period;
	struct light_ve		*lvp_default;
#ifdef HAVE_EXEC_NOTIFIER
	struct list_head	lvp_exec_entries;
	rwlock_t		lvp_exec_lock;
#endif
	char			lvp_private[0];
};

#define os_lvp_private(lvp) ((struct lvp_private *)(lvp->lvp_private))

enum {
    CUST_CPU 	= 1 << 1,
    CUST_CPUS 	= 1 << 2,
    CUST_MEM	= 1 << 3,
    CUST_IO	= 1 << 4,
    CUST_ENTER	= 1 << 5,
    CUST_MEM_PHY = 1 << 6,
    CUST_CPU_WEIGHT = 1 << 7,
    CUST_NPROC	= 1 << 8,
    CUST_IOPS	= 1 << 9,
};

enum resources {
    RES_CPU,
    RES_MEM,
    RES_IO,
    RES_ENTER,
    RES_MEM_PHY,
    RES_CPU_WEIGHT,
    RES_NPROC,
    RES_IOPS,
    MAX_RESOURCES
};

struct one_resource {
	u64 data;
	u64 fail;
};

struct lve_usage {
	struct one_resource data[MAX_RESOURCES];
};

extern bool lve_unint_hack;
extern bool lve_user_setup;
struct task_struct;

/** context private info - one per lve */
struct c_private;

int os_global_init(void);
void os_global_fini(void);

int os_lvp_init(struct lvp_ve_private *lvp, void *data);
void os_lvp_fini(struct lvp_ve_private *lvp);

int lvp_proc_init(struct lvp_ve_private *lvp);
int lvp_proc_fini(struct lvp_ve_private *lvp);

unsigned int os_context_private_sz(void);
unsigned int os_lvp_private_sz(void);

int os_loadavg_global(struct light_ve *host);
int os_loadavg_count(struct light_ve *lve);

/* return node is in format LVE_ID << 32 | VE_ID to be compatible with VZ */
#ifdef LVE_PER_VE
#define NODEID_ENCODE(ve_id, lve_id) 	(((uint64_t)lve_id)<<32 | (ve_id))
#define NODEID_VEID(node)		((node)&0xFFFFFFFF)
#define NODEID_LVEID(node)		((node)>>32)
#else
#define NODEID_ENCODE(ve_id, lve_id) 	(lve_id)
#define NODEID_VEID(node)		(0)
#define NODEID_LVEID(node)		(node)
#endif

uint64_t lve_node_id(struct task_struct *task);

/* XXX need hide from all except resource.c */
void os_resource_usage(struct c_private *private, struct lve_usage *buf);
void os_resource_usage_clear(struct c_private *private); 

struct light_ve;
int os_resource_init(struct light_ve *ve);
int os_resource_fini(uint32_t id, struct c_private *private);

int os_resource_setup(struct c_private *private, lve_limits_t new, uint32_t custom);
int os_resource_unlink(uint32_t id, struct c_private *private);

extern bool lve_bc_after_enter;
extern bool lve_no_namespaces;
int os_resource_push(struct task_struct *task, struct c_private *lcontext);

int os_cpu_enter(struct task_struct *task, struct c_private *lcontext);

struct lvp_ve_private;

#ifdef LVE_PER_VE
#ifdef HAVE_VE_TASK_INFO
#define TASK_VE_PRIVATE(tsk) ((struct lvp_ve_private *)(tsk)->ve_task_info.owner_env->lve)
#else
#define TASK_VE_PRIVATE(tsk) ((struct lvp_ve_private *)(tsk)->task_ve->lve)
#endif
#else
#define TASK_VE_PRIVATE(tsk) (root_lvp)
#endif
extern struct lvp_ve_private *root_lvp;

struct lvp_ve_private *lvp_alloc(uint32_t id, void *data);
void lvp_fini(struct lvp_ve_private *lvp);
void lvp_free(struct lvp_ve_private *lvp);

#endif
