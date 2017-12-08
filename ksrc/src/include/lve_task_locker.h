#ifndef _LVE_TASK_LOCKER_H_
#define _LVE_TASK_LOCKER_H_

#include <linux/spinlock.h>

struct task_struct;

int lve_task_lock_init(void);
void lve_task_lock_fini(void);
void lve_task_lock(struct task_struct *);
void lve_task_unlock(struct task_struct *);

#endif
