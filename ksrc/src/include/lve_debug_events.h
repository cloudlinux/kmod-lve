#undef TRACE_SYSTEM
#define TRACE_SYSTEM lve

#if !defined(_LVE_DEBUG_EVENTS_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _LVE_DEBUG_EVENTS_H_

#include <linux/tracepoint.h>
#include "lve-api.h"

#define show_entry_flags(flags)					\
	__print_flags(flags, "|",				\
		{LVE_ENTER_NAMESPACE,	"LVE_ENTER_NAMESPACE"}, \
		{LVE_ENTER_NO_UBC,	"LVE_ENTER_NO_UBC"},	\
		{LVE_ENTER_NO_MAXENTER,	"LVE_ENTER_NO_MAXENTER"},\
		{LVE_ENTER_SILENCE,	"LVE_ENTER_SILENCE"})

TRACE_EVENT(lve_enter,
	TP_PROTO(struct task_struct *t, uint32_t lvp_id, uint32_t lve_id,
		 uint32_t flags, uint32_t cookie, int rc),
	TP_ARGS(t, lvp_id, lve_id, flags, cookie, rc),
	TP_STRUCT__entry(
		__array(char,		comm,	TASK_COMM_LEN)
		__field(pid_t,		pid)
		__field(uint32_t,	lve_id)
		__field(uint32_t,	lvp_id)
		__field(uint32_t,	flags)
		__field(uint32_t,	cookie)
		__field(int,		rc)
	),
	TP_fast_assign(
		memcpy(__entry->comm, t->comm, TASK_COMM_LEN);
		__entry->pid		= t->pid;
		__entry->lve_id		= lve_id;
		__entry->lvp_id		= lvp_id;
		__entry->flags		= flags;
		__entry->cookie		= cookie;
		__entry->rc		= rc;
	),
	TP_printk("comm=%s pid=%d lve=%u lvp=%u flags=%s cookie=%x rc=%d",
		  __entry->comm, __entry->pid, __entry->lve_id, __entry->lvp_id,
		  show_entry_flags(__entry->flags), __entry->cookie,
		  __entry->rc)
);

TRACE_EVENT(lve_leave,
	TP_PROTO(struct task_struct *t, uint32_t cookie, int rc),
	TP_ARGS(t, cookie, rc),
	TP_STRUCT__entry(
		__array(char,		comm,	TASK_COMM_LEN)
		__field(pid_t,		pid)
		__field(uint32_t,	cookie)
		__field(int,		rc)
	),
	TP_fast_assign(
		memcpy(__entry->comm, t->comm, TASK_COMM_LEN);
		__entry->pid		= t->pid;
		__entry->cookie		= cookie;
		__entry->rc		= rc;
	),
	TP_printk("comm=%s pid=%d cookie=%x rc=%d",
		  __entry->comm, __entry->pid,
		  __entry->cookie, __entry->rc)
);

TRACE_EVENT(lve_setup,
	TP_PROTO(uint32_t lvp_id, uint32_t lve_id, lve_limits_t lim, int hires, 
		 int rc),
	TP_ARGS(lvp_id, lve_id, lim, hires, rc),
	TP_STRUCT__entry(
		__field(uint32_t,	lve_id)
		__field(uint32_t,	lvp_id)
		__field(int,		hires)
		__field(int,		rc)
		__field(int32_t,	l_cpu)
		__field(int32_t,	l_io)
		__field(int32_t,	l_enter)
		__field(int32_t,	l_cpus)
		__field(int32_t,	l_mem)
		__field(int32_t,	l_pmem)
		__field(int32_t,	l_cpuw)
		__field(int32_t,	l_nproc)
		__field(int32_t,	l_iops)
	),
	TP_fast_assign(
		__entry->lve_id		= lve_id;
		__entry->lvp_id		= lve_id;
		__entry->hires		= hires;
		__entry->rc		= rc;
		__entry->l_cpu		= lim[LIM_CPU];
		__entry->l_io		= lim[LIM_IO];
		__entry->l_enter	= lim[LIM_ENTER];
		__entry->l_cpus		= lim[LIM_CPUS];
		__entry->l_mem		= lim[LIM_MEMORY];
		__entry->l_pmem		= lim[LIM_MEMORY_PHY];
		__entry->l_cpuw		= lim[LIM_CPU_WEIGHT];
		__entry->l_nproc	= lim[LIM_NPROC];
		__entry->l_iops		= lim[LIM_IOPS];
	),
	TP_printk("lve=%u lvp=%u hires=%d lcpu=%u lio=%u lenter=%u lcpus=%u lmem=%u "
		  "lpmem=%u lcpuw=%u lnproc=%u liops=%u rc=%d",
		  __entry->lve_id, __entry->lvp_id, __entry->hires, __entry->l_cpu,
		  __entry->l_io, __entry->l_enter, __entry->l_cpus,
		  __entry->l_mem, __entry->l_pmem, __entry->l_cpuw,
		  __entry->l_nproc, __entry->l_iops, __entry->rc)
);

TRACE_EVENT(lve_destroy,
	TP_PROTO(uint32_t lvp_id, uint32_t lve_id, int rc),
	TP_ARGS(lvp_id, lve_id, rc),
	TP_STRUCT__entry(
		__field(uint32_t,	lve_id)
		__field(uint32_t,	lvp_id)
		__field(int,		rc)
	),
	TP_fast_assign(
		__entry->lve_id		= lve_id;
		__entry->lvp_id		= lvp_id;
		__entry->rc		= rc;
	),
	TP_printk("lve=%u lvp=%u rc=%d",
		  __entry->lve_id, __entry->lvp_id, __entry->rc)
);

TRACE_EVENT(iolimit_io_account,
	TP_PROTO(long ub_id, long pages),
	TP_ARGS(ub_id, pages),
	TP_STRUCT__entry(
		__field(long,		ub_id)
		__field(long,		pages)
	),
	TP_fast_assign(
		__entry->ub_id		= ub_id;
		__entry->pages		= pages;
	),
	TP_printk("ubid=%ld bytes=%ld", __entry->ub_id, __entry->pages)
);

TRACE_EVENT(iolimit_dirty,
	TP_PROTO(long ub_id, long pages),
	TP_ARGS(ub_id, pages),
	TP_STRUCT__entry(
		__field(long,		ub_id)
		__field(long,		pages)
	),
	TP_fast_assign(
		__entry->ub_id		= ub_id;
		__entry->pages		= pages;
	),
	TP_printk("ubid=%ld bytes=%ld", __entry->ub_id, __entry->pages)
);

TRACE_EVENT(iolimit_wait,
	TP_PROTO(long ub_id, long ms),
	TP_ARGS(ub_id, ms),
	TP_STRUCT__entry(
		__field(long, ub_id)
		__field(long, ms)
	),
	TP_fast_assign(
		__entry->ub_id = ub_id;
		__entry->ms = ms;
	),
	TP_printk("ubid=%ld ms=%ld", __entry->ub_id, __entry->ms)
);

#endif /* _LVE_DEBUG_EVENTS_H_ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE lve_debug_events

/* This part must be outside protection */
#include <trace/define_trace.h>
