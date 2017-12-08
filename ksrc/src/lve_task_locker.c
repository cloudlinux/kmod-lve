#include <linux/module.h>
#include <linux/sched.h>
#include <linux/hash.h>

#include "lve_debug.h"
#include "lve_task_locker.h"

#define TLOCKER_ARRAY_BITS	10
#define TLOCKER_ARRAY_SZ	(1 << TLOCKER_ARRAY_BITS)

static struct mutex tlocker_array[TLOCKER_ARRAY_SZ];

void lve_task_lock(struct task_struct *tsk)
{
	mutex_lock(&tlocker_array[hash_32(tsk->pid, TLOCKER_ARRAY_BITS)]);
}

void lve_task_unlock(struct task_struct *tsk)
{
	mutex_unlock(&tlocker_array[hash_32(tsk->pid, TLOCKER_ARRAY_BITS)]);
}

int lve_task_lock_init(void)
{
	int i;

	for (i = 0; i < TLOCKER_ARRAY_SZ; i++)
		mutex_init(&tlocker_array[i]);

	return 0;
}

void lve_task_lock_fini(void)
{
}
