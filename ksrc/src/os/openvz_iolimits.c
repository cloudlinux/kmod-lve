/*
 *  kernel/ve/vziolimit.c
 *
 *  Copyright (C) 2014, Parallels inc.
 *  All rights reserved.
 *
 *  Rework of the original module for Cloud Linux
 *  Copyright (C) 2014, Cloud Linux
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/virtinfo.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/freezer.h>
#include <linux/vzctl.h>
#include <linux/vziolimit.h>
#include <bc/beancounter.h>

#include "lve_debug.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#define private_data2 iolimit
#define current_is_flusher()	(current->flags & PF_SWAPWRITE)

uid_t ub_id(struct user_beancounter *ub)
{
	uid_t id;

	if (kstrtouint(ub->ub_name, 10, &id) != 0)
		id = -1;
	return id;
}

#else
#define current_is_flusher()	(current->flags & PF_FLUSHER)
#define ub_id(ub) (ub->ub_uid)
#endif

unsigned int iolimits_latency = 0xffffff;


struct throttle {
       unsigned speed;		/* maximum speed, units per second */
       unsigned burst;		/* maximum bust, units */
//       unsigned latency;	/* maximum wait delay, jiffies */
       unsigned remain;		/* units/HZ */
       unsigned long time;	/* wall time in jiffies */
       long long state;		/* current state in units */
       unsigned long long io;	/* total io in bytes or operations */
};

/**
 * set throttler initial state, externally serialized
 * @speed	maximum speed (1/sec)
 * @burst	maximum burst chunk
 * @latency	maximum timeout (ms)
 */
static void throttle_setup(struct throttle *th, unsigned speed,
		unsigned burst/*, unsigned latency*/)
{
	th->time = jiffies;
	th->burst = burst;
//	th->latency = msecs_to_jiffies(latency);
	th->state = 0;
	wmb();
	th->speed = speed;
}

/* externally serialized */
static int throttle_charge(struct throttle *th, unsigned charge)
{
	unsigned long time, now = jiffies;
	long long step, ceiling = charge + th->burst;

	if (!th->speed)
		return -ERANGE;

	/* Step 1: convert idle seconds into bytes */
	if (time_before(th->time, now)) {
		step = (u64)th->speed * (now - th->time);
		do_div(step, HZ);
		step += th->state;
		/* feed throttler as much as we can */
		if (step <= ceiling)
			th->state = step;
		else if (th->state < ceiling)
			th->state = ceiling;
		th->time = now;
	}

	if (charge > th->state) {
		charge -= th->state;
		step = charge * HZ;
		if (do_div(step, th->speed))
			step++;
		time = th->time + step;
		/* limit maximum latency */
		if (time_after(time, now + msecs_to_jiffies(iolimits_latency)))
			time = now + msecs_to_jiffies(iolimits_latency);
		th->time = time;
		step *= th->speed;
		step += th->remain;
		th->remain = do_div(step, HZ);
		th->state += step;
	}

	return 0;
}

/* lockless */
static unsigned long throttle_timeout(struct throttle *th, unsigned long now)
{
	unsigned long time;

	if (!th->speed)
		return 0;
	rmb();
	time = th->time;
	if (time_before(time, now))
		return 0;
	return min(time - now, (unsigned long)msecs_to_jiffies(iolimits_latency));
}

struct iolimit {
	struct throttle throttle;
	struct throttle iops;
	wait_queue_head_t wq;
	long ub_id;

	long dirty_pages;
	long async_write_canceled;
};

static void sync_stats(struct user_beancounter *ub)
{
	struct iolimit *iolimit = ub->private_data2;
	unsigned long flags;
	long diff_dp, diff_awc;

	if (iolimit == NULL)
		return;

	spin_lock_irqsave(&ub->ub_lock, flags);
	diff_dp = ub_stat_get_exact(ub, dirty_pages) - iolimit->dirty_pages;
	diff_awc = __ub_percpu_sum(ub, async_write_canceled) - iolimit->async_write_canceled;
	do {
		iolimit->dirty_pages += diff_dp;
		iolimit->async_write_canceled += diff_awc;
		spin_unlock_irqrestore(&ub->ub_lock, flags);
#ifdef HAVE_SUB_UBC
		ub = ub->ub_parent;
		if (ub == NULL || ub == get_ub0() ||
		    (iolimit = ub->private_data2) == NULL)
#endif
			break;

		spin_lock_irqsave(&ub->ub_lock, flags);
	} while (1);
}

#include <linux/signal.h>

static sigset_t block_sigsinv(unsigned long sigs)
{
	unsigned long flags;
	sigset_t old;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	old = current->blocked;
	sigaddsetmask(&current->blocked, ~sigs);
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);

	return old;
}

static void restore_sigs(sigset_t old)
{
	unsigned long flags;

	spin_lock_irqsave(&current->sighand->siglock, flags);
	current->blocked = old;
	recalc_sigpending();
	spin_unlock_irqrestore(&current->sighand->siglock, flags);
}

static void iolimit_wait(struct iolimit *iolimit, unsigned long timeout)
{
	DEFINE_WAIT(wait);
	sigset_t old;

	/* BSD process accounting can write inside do_exit() */
	if (current->flags & PF_EXITING)
		return;

	trace_iolimit_wait(iolimit->ub_id, timeout * 1000 / HZ);

	old = block_sigsinv(sigmask(SIGKILL));

	do {
#ifdef TASK_IOTHROTTLED
		prepare_to_wait(&iolimit->wq, &wait,
				TASK_INTERRUPTIBLE | TASK_IOTHROTTLED);
#else
		prepare_to_wait(&iolimit->wq, &wait, TASK_INTERRUPTIBLE);
#endif
		timeout = schedule_timeout(timeout);
		if (fatal_signal_pending(current))
			break;
		if (unlikely(freezing(current)))
			break;
		if (unlikely(timeout))
			timeout = min(throttle_timeout(&iolimit->throttle,
						jiffies), timeout);
	} while (timeout);
	finish_wait(&iolimit->wq, &wait);

	restore_sigs(old);
}

static unsigned long iolimit_timeout(struct iolimit *iolimit)
{
	unsigned long now = jiffies;

	return max(throttle_timeout(&iolimit->throttle, now),
			throttle_timeout(&iolimit->iops, now));
}

static void iolimit_balance_dirty(struct iolimit *iolimit,
				  struct user_beancounter *ub,
				  unsigned long write_chunk)
{
	struct throttle *th = &iolimit->throttle;
	unsigned long flags, dirty, state;

	if (!th->speed)
		return;

	trace_iolimit_dirty(iolimit->ub_id, write_chunk << PAGE_SHIFT);

	state = th->state >> PAGE_SHIFT;
	dirty = iolimit->dirty_pages + write_chunk;
	if (dirty < state)
		return;

	spin_lock_irqsave(&ub->ub_lock, flags);
	/* precharge dirty pages */
	throttle_charge(th, (long long)dirty << PAGE_SHIFT);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

static int current_swap_in(void)
{
	if (current->delays)
		return !!(current->delays->flags & DELAYACCT_PF_SWAPIN);

	return 0;
}


static int iolimit_virtinfo_ub(struct user_beancounter *ub,
			       unsigned long cmd, void *arg)
{
	struct iolimit *iolimit = ub->private_data2;
	unsigned long flags, timeout;
	int rc;

	if (!iolimit)
		return NOTIFY_OK;

	switch (cmd) {
		case VIRTINFO_IO_ACCOUNT:
			spin_lock_irqsave(&ub->ub_lock, flags);
			rc = throttle_charge(&iolimit->throttle, *(size_t*)arg);
			if (!rc)
				iolimit->throttle.state -= *(size_t*)arg;
			iolimit->throttle.io += *(size_t*)arg;
			spin_unlock_irqrestore(&ub->ub_lock, flags);

			trace_iolimit_io_account(iolimit->ub_id, *(size_t*)arg);

			break;
#ifdef VIRTINFO_IO_FUSE_REQ
		case VIRTINFO_IO_FUSE_REQ:
#endif
		case VIRTINFO_IO_OP_ACCOUNT:
			spin_lock_irqsave(&ub->ub_lock, flags);
			rc = throttle_charge(&iolimit->iops, 1);
			if (!rc)
				if (iolimit->iops.state > 1 ||
				    !current_is_flusher())
					iolimit->iops.state--;
			iolimit->iops.io += 1;
			spin_unlock_irqrestore(&ub->ub_lock, flags);
			break;
		case VIRTINFO_IO_PREPARE:
#if 0
		/* We don't want to sleep in journal */
		case VIRTINFO_IO_JOURNAL:
#endif
			if (current_is_flusher())
				break;
			timeout = iolimit_timeout(iolimit);
			if (timeout && !fatal_signal_pending(current))
				iolimit_wait(iolimit, timeout);
			break;
		case VIRTINFO_IO_READAHEAD:
		case VIRTINFO_IO_CONGESTION:
			timeout = iolimit_timeout(iolimit);
			if (timeout)
				return NOTIFY_FAIL;
			break;
#ifdef VIRTINFO_IO_BALANCE_DIRTY
		case VIRTINFO_IO_BALANCE_DIRTY:
			iolimit_balance_dirty(iolimit, ub, (unsigned long)arg);
			break;
#endif
	}

	return NOTIFY_OK;
}

static int iolimit_virtinfo(struct vnotifier_block *nb,
			    unsigned long cmd, void *arg,
			    int old_ret)
{
	struct user_beancounter *ub = get_exec_ub();
	int rc = NOTIFY_OK;

	/* Skip if swap-in is in progress */
	if (current_swap_in())
		return rc;

	if (cmd == VIRTINFO_IO_BALANCE_DIRTY)
		sync_stats(ub);

#ifdef HAVE_SUB_UBC
	while (ub != NULL && rc != NOTIFY_FAIL) {
		rc = iolimit_virtinfo_ub(ub, cmd, arg);
		ub = ub->ub_parent;
	}
#else
	rc = iolimit_virtinfo_ub(ub, cmd, arg);
#endif

	return rc;
}

static struct vnotifier_block iolimit_virtinfo_nb = {
	.notifier_call = iolimit_virtinfo,
};

static struct iolimit *iolimit_get(struct user_beancounter *ub)
{
	struct iolimit *iolimit = ub->private_data2;

	if (iolimit)
		return iolimit;

	iolimit = kzalloc(sizeof(struct iolimit), GFP_KERNEL);
	if (!iolimit)
		return NULL;
	init_waitqueue_head(&iolimit->wq);

	spin_lock_irq(&ub->ub_lock);
	if (ub->private_data2) {
		kfree(iolimit);
		iolimit = ub->private_data2;
	} else
		ub->private_data2 = iolimit;
	spin_unlock_irq(&ub->ub_lock);

	iolimit->ub_id = ub_id(ub);

	return iolimit;
}

int ovz_set_io_limit(struct user_beancounter *ub,
		     unsigned speed, unsigned burst)
{
	struct iolimit *iolimit;

	iolimit = iolimit_get(ub);
	if (!iolimit)
		return -ENOMEM;

	spin_lock_irq(&ub->ub_lock);
	throttle_setup(&iolimit->throttle, speed, burst);
	spin_unlock_irq(&ub->ub_lock);
	wake_up_all(&iolimit->wq);

	return 0;
}

unsigned long long ovz_get_io_usage(struct user_beancounter *ub)
{
	struct iolimit *iolimit = ub->private_data2;

	if (iolimit)
		return iolimit->throttle.io +
		  ((long long)(iolimit->dirty_pages +
			       iolimit->async_write_canceled) <<
			       PAGE_SHIFT);

	return 0;
}

unsigned long long ovz_get_iops_usage(struct user_beancounter *ub)
{
	struct iolimit *iolimit = ub->private_data2;

	if (iolimit)
		return iolimit->iops.io;

	return 0;
}

int ovz_set_iops_limit(struct user_beancounter *ub,
		       unsigned speed, unsigned burst)
{
	struct iolimit *iolimit;

	iolimit = iolimit_get(ub);
	if (!iolimit)
		return -ENOMEM;

	spin_lock_irq(&ub->ub_lock);
	throttle_setup(&iolimit->iops, speed, burst);
	spin_unlock_irq(&ub->ub_lock);
	wake_up_all(&iolimit->wq);

	return 0;
}

int ovz_io_limits_init(struct user_beancounter *ub)
{
	if (!iolimit_get(ub))
		return -ENOMEM;

	return 0;
}

static void throttle_state(struct user_beancounter *ub,
		struct throttle *throttle, struct iolimit_state *state)
{
	spin_lock_irq(&ub->ub_lock);
	state->speed = throttle->speed;
	state->burst = throttle->burst;
	state->latency = 0;
	spin_unlock_irq(&ub->ub_lock);
}

static int ovz_iolimit_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct user_beancounter *ub;
	struct iolimit *iolimit;
	struct iolimit_state state;
	int err;

	if (cmd != VZCTL_SET_IOLIMIT && cmd != VZCTL_GET_IOLIMIT &&
	    cmd != VZCTL_SET_IOPSLIMIT && cmd != VZCTL_GET_IOPSLIMIT)
		return -ENOTTY;

	if (copy_from_user(&state, (void __user *)arg, sizeof(state)))
		return -EFAULT;

	ub = get_beancounter_byuid(state.id, 0);
	if (!ub)
		return -ENOENT;

	iolimit = ub->private_data2;

	switch (cmd) {
		case VZCTL_SET_IOLIMIT:
			err = ovz_set_io_limit(ub, state.speed, state.burst);
			break;
		case VZCTL_SET_IOPSLIMIT:
			err = ovz_set_iops_limit(ub, state.speed, state.burst);
			break;
		case VZCTL_GET_IOLIMIT:
			err = -ENXIO;
			if (!iolimit)
				break;
			throttle_state(ub, &iolimit->throttle, &state);
			err = -EFAULT;
			if (copy_to_user((void __user *)arg, &state, sizeof(state)))
				break;
			err = 0;
			break;
		case VZCTL_GET_IOPSLIMIT:
			err = -ENXIO;
			if (!iolimit)
				break;
			throttle_state(ub, &iolimit->iops, &state);
			err = -EFAULT;
			if (copy_to_user((void __user *)arg, &state, sizeof(state)))
				break;
			err = 0;
			break;
		default:
			err = -ENOTTY;
	}

	put_beancounter(ub);
	return err;
}

static struct vzioctlinfo iolimit_vzioctl = {
	.type		= VZIOLIMITTYPE,
	.ioctl		= ovz_iolimit_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ovz_iolimit_ioctl,
#endif
	.owner		= THIS_MODULE,
};

int ovz_iolimits_init(void)
{
	virtinfo_notifier_register(VITYPE_IO, &iolimit_virtinfo_nb);
	vzioctl_register(&iolimit_vzioctl);

	return 0;
}

void ovz_iolimits_exit(void)
{
	vzioctl_unregister(&iolimit_vzioctl);
	virtinfo_notifier_unregister(VITYPE_IO, &iolimit_virtinfo_nb);
}

module_param_named(latency, iolimits_latency, uint, 0644);
