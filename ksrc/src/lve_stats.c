#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include "lve_internal.h"
#include "resource.h"
#include "lve_debug.h"

#if defined(HAVE_LOADAVG_PTR)
extern void  (*loadavg_ptr)(void);

static void update_loadavg(void)
{
#ifndef LVE_PER_VE
	long count;
	struct light_ve *ve;
	struct lvp_ve_private *lvp = root_lvp;

	/* Reduce by 1 so as not to account our loadavg thread */
	count = os_loadavg_global(lvp->lvp_default) - 1;
	LVE_DBG("global count %ld\n", count);

	read_lock(&lvp->lvp_lock);
	list_for_each_entry(ve, &lvp->lvp_list, lve_link) {
		count += os_loadavg_count(ve);
		LVE_DBG("lve %d count %ld\n", ve->lve_id, count);
	}
	read_unlock(&lvp->lvp_lock);

	LVE_DBG("total count %ld\n", count);

	count *= FIXED_1;

	CALC_LOAD(avenrun[0], EXP_1, count);
	CALC_LOAD(avenrun[1], EXP_5, count);
	CALC_LOAD(avenrun[2], EXP_15, count);
#else
	os_loadavg_ve();
#endif
}

int loadavg_thread(void *unused) {
	while (!kthread_should_stop()) {
		update_loadavg();
		/*
		 * Though we count load average ourselves, the
		 * thread should not appear on the thread list
		 * as non-interruptible, since other ways to
		 * calculate LA will always show at least 1.0
		 * We are still safe from signals, since this thread
		 * was forked from kthreadd, which called
		 * ignore_signals() and we copied SIG_IGN handlers in
		 * copy_sighand().
		 */
		schedule_timeout_interruptible(LOAD_FREQ);
	}
	return 0;
}

static void lve_nop(void)
{
}

static struct task_struct *la_thread;

int lve_stats_init(void)
{
        /* XXX: Here we would like to calculate some approximate history */

	la_thread = lve_call(kthread_create(loadavg_thread, NULL, "lve_loadavg"),
					LVE_FAIL_STATS_CRT_THREAD, ERR_PTR(-ENOMEM));
	if (IS_ERR(la_thread))
		return -ENOMEM;
	loadavg_ptr_init(lve_nop);
	wake_up_process(la_thread);

	return 0;
}

void lve_stats_fini(void)
{
	kthread_stop(la_thread);
	loadavg_ptr_fini();
}

#else
int lve_stats_init(void)
{
	return 0;
}

void lve_stats_fini(void)
{
}
#endif
