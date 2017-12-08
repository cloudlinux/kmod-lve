#ifndef _LVE_DEBUG_
#define _LVE_DEBUG_

#include <linux/kernel.h>
#include <linux/hardirq.h>
#include "lve_os_compat.h"
#include "kernel_exp.h"
#include <linux/ftrace.h>
#include "lve_debug_events.h"

#define safe_pid() (in_interrupt() ? -1 : current->pid)

#define LVE_DEBUG_FAC_DBG	0
#define LVE_DEBUG_FAC_WARN	1
#define LVE_DEBUG_FAC_ERR	2

extern atomic_t lve_debug_mask;
extern unsigned long fail_value;

#define LVE_ERR(a, ...)								\
	do {									\
		if (atomic_read(&lve_debug_mask) & (1 << LVE_DEBUG_FAC_WARN)) {	\
			trace_printk("lve-err "a, ##__VA_ARGS__);			\
			printk(KERN_ERR"LVE: [%d] %s: "a, safe_pid(),		\
				__FUNCTION__, ##__VA_ARGS__);			\
		}								\
	} while (0)

#define LVE_WARN(a, ...)							\
	do {									\
		if (atomic_read(&lve_debug_mask) & (1 << LVE_DEBUG_FAC_ERR)) {	\
			trace_printk("lve-warn "a, ##__VA_ARGS__);			\
			printk(KERN_WARNING"LVE: [%d] %s: "a, safe_pid(),	\
				__FUNCTION__,##__VA_ARGS__);			\
		}								\
	} while (0)

#define LVE_DBG(a, ...)								\
	do {									\
		if (atomic_read(&lve_debug_mask) & (1 << LVE_DEBUG_FAC_DBG)) {	\
			trace_printk("LVE: "a, ##__VA_ARGS__);			\
			printk("LVE: [%d] %s: "a, safe_pid(), __FUNCTION__,	\
				##__VA_ARGS__);					\
		} 								\
	} while (0)

#define LVE_ENTER(a,...) LVE_DBG("enter "a, ##__VA_ARGS__);
#define LVE_LEAVE() LVE_DBG("leave\n");

/* printf specifiers for certain types, only valid for platforms we support */
#define LPU64 "%llu"
#define LPD64 "%lld"
#define LPX64 "%llx"

/* access will result in NULL ptr dereference, but NULL ptr checks will fail */
#define LVE_POISON_PTR ((void *)0xded)

#define LVE_FAIL_VAL(type, loc) (((type) << 8) + (loc))
#define LVE_FAIL_TYPE(val) (((val) >> 8) & 0xff)
#define LVE_FAIL_LOC(val) ((val) & 0xff)

enum {
	LVE_FAIL_ALLOC_VE,
	LVE_FAIL_RDXT_PRELOAD,
	LVE_FAIL_ALLOC_LVP_CACHE,
	LVE_FAIL_ALLOC_LVP,
	LVE_FAIL_DUP_NS,
	LVE_FAIL_CP_FS_STRCT1,
	LVE_FAIL_CP_FS_STRCT2,
	LVE_FAIL_CP_FS_STRCT3,
	LVE_FAIL_ALLOC_LVE_CACHE,
	LVE_FAIL_LVE_LOOKUP,
	LVE_FAIL_LVE_INSRT,
	LVE_FAIL_STATS_CRT_THREAD,
	LVE_FAIL_ALLOC_SWITCH,
	LVE_FAIL_ALLOC_SWITCH_CACHE,
	LVE_FAIL_ALLOC_COOKIE,
	LVE_FAIL_ALLOC_COOKIE_CACHE,
	LVE_FAIL_MISC_REG,
	LVE_FAIL_GET_UB_BYUID, /* cl5, cl6 */
	LVE_FAIL_INIT_THRDS_INIT,

	LVE_FAIL_LVP_MAP_LOOKUP,
	LVE_FAIL_LVP_MAP_INSRT,

	LVE_FAIL_GET_SUB_UB_BYUID, /* cl7 */
	LVE_FAIL_MOUNT_CGROUP_ROOTFS,

	LVE_FAIL_COMMON_NUM,
};
/* openvz_cgroup */
enum {
	LVE_FAIL_CGRP_OPEN = LVE_FAIL_COMMON_NUM,
	LVE_FAIL_SETUBLIMIT,
	LVE_FAIL_WRT_CPUS_LIM,
	LVE_FAIL_WRT_CPU_LIM,
	LVE_FAIL_WRT_CPU_CHWT,
	LVE_FAIL_IO_SET_LIM,
	LVE_FAIL_UB_ATTACH_TASK,
	LVE_FAIL_CGRP_ATTACH_TSK,
	LVE_FAIL_CGRP_PATH,
	LVE_FAIL_CGRP_PARAM_GET,
};
/* openvz */
enum {
	LVE_FAIL_FSCHED_VCPUS = LVE_FAIL_COMMON_NUM,
	LVE_FAIL_FSCHED_RATE,
	LVE_FAIL_FSCHED_CHWT1,
	LVE_FAIL_SETUBLIM_MEM,
	LVE_FAIL_FSCHED_CHWT2,
	LVE_FAIL_SETUBLIM_PMEM,
	LVE_FAIL_SETUBLIM_NPROC,
	LVE_FAIL_MVPR_TSK,
	LVE_FAIL_FSCHED_MKNOD,
};

#define LVE_FAIL_CHECK		0x01
#define LVE_FAIL_RACE		0x02
#define LVE_FAIL_TIMEOUT	0x04
#define LVE_FAIL_ONCE		0x08

#define LVE_FAIL_ONCE_BIT	0x10
#define LVE_FAIL_RACE_BIT	0x11

static inline bool LVE_FAIL_PRECHECK(unsigned int type, unsigned long loc)
{
	if (likely(fail_value == 0))
		return 0;

	if ((LVE_FAIL_LOC(fail_value) == loc) &&
		LVE_FAIL_TYPE(fail_value) & type)
		return 1;
	return 0;
}

static inline bool LVE_CHECK_ONCE(void)
{
	if (LVE_FAIL_TYPE(fail_value) & LVE_FAIL_ONCE)
		return !test_and_set_bit(LVE_FAIL_ONCE_BIT, &fail_value);
	else
		return 1;
}

static inline bool lve_fail_check(unsigned long loc)
{
	if (LVE_FAIL_PRECHECK(LVE_FAIL_CHECK, loc) && LVE_CHECK_ONCE()) {
		LVE_WARN("fail %lx\n", fail_value);
		return 1;
	}

	return 0;
}

#define lve_call(call, val, err) lve_fail_check(val) ? err : call
#define LVE_RACE_STATE() test_bit(LVE_FAIL_RACE_BIT, &fail_value)

#include <linux/wait.h>

static DECLARE_WAIT_QUEUE_HEAD(lve_race_waitq);
static int lve_race_state;

static inline void lve_fail_race(unsigned int id)
{
	if (LVE_FAIL_PRECHECK(LVE_FAIL_RACE, id)) {
		if (LVE_CHECK_ONCE() && !LVE_RACE_STATE()) {
			lve_race_state = 0;
			set_bit(LVE_FAIL_RACE_BIT, &fail_value);
			LVE_WARN("lve_fail_race: id %x sleeping\n", id);
			wait_event_interruptible(
					lve_race_waitq, lve_race_state != 0);
			LVE_WARN("lve_fail_race: id %x awake\n", id);
		} else {
			LVE_WARN("lve_fail_race: id %x waking\n", id);
			lve_race_state = 1;
			wake_up_interruptible(&lve_race_waitq);
			clear_bit(LVE_FAIL_RACE_BIT, &fail_value);
		}
	}
}

static inline void lve_fail_timeout(unsigned int id, int ms)
{
	if (LVE_FAIL_PRECHECK(LVE_FAIL_TIMEOUT, id) && LVE_CHECK_ONCE()) {
		LVE_WARN("lve_fail_timeout id %x sleeping for %dms\n", id, ms);
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(ms));
		LVE_WARN("lve_fail_timeout id %x awake\n", id);
	}
}
#endif

