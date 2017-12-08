#include <linux/kernel.h>
#include <linux/kprobes.h>

#include "lve_internal.h"
#include "lve_hooks.h"
#include "lve_debug.h"
#include "kernel_exp.h"
#include "tags.h"

#ifdef HAVE_CGROUP_POST_FORK_WITH_1ARG
static notrace void lve_cgroup_post_fork_hook(struct task_struct *new_task)
#elif defined(HAVE_CGROUP_POST_FORK_WITH_2ARGS)
#include <linux/cgroup.h>
static notrace void lve_cgroup_post_fork_hook(struct task_struct *new_task,
					void *old_ss_priv[CGROUP_CANFORK_COUNT])
#else
#error "cgroup_post_fork has unsupported prototype"
#endif
{
	switch_tag_fork(new_task);
	jprobe_return();
}

#ifdef HAVE_PROC_EXIT_CONNECTOR
static notrace void lve_proc_exit_connector_hook(struct task_struct *tsk)
{
	struct switch_data *sw_data;

	sw_data = LVE_TAG_GET(tsk);
	if (sw_data != NULL) {
		LVE_DBG("sw_data=%p comm=%s\n", sw_data, tsk->comm);
		lve_exit_task(tsk, sw_data);
		/* Be careful here since last put can initiate i/o */
		LVE_TAG_PUT_DELAYED(sw_data);
	}
	jprobe_return();
}
#else
#error no proc exit connector
#endif

static struct jprobe lve_fork_jp = {
	.entry		= JPROBE_ENTRY(lve_cgroup_post_fork_hook),
	.kp.symbol_name = "cgroup_post_fork"
};

static struct jprobe lve_free_task_jp = {
	.entry		= JPROBE_ENTRY(lve_proc_exit_connector_hook),
	.kp.symbol_name	= "proc_exit_connector",
};

static struct jprobe *jp[] = {
	&lve_fork_jp,
	&lve_free_task_jp,
};

int lve_hooks_init(void)
{
	return register_jprobes(jp, ARRAY_SIZE(jp));

}

void lve_hooks_fini(void)
{
	unregister_jprobes(jp, ARRAY_SIZE(jp));
}
