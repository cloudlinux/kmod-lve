#include <linux/kernel.h>
#include <linux/kprobes.h>

#include "lve_internal.h"
#include "lve_hooks.h"
#include "lve_debug.h"
#include "kernel_exp.h"
#include "tags.h"

static notrace void lve_fork_hook(struct task_struct *new_task)
{
	switch_tag_fork(new_task);
	lve_jprobe_ret();
}

static notrace void lve_free_task_hook(struct task_struct *tsk)
{
	struct switch_data *sw_data;

	sw_data = LVE_TAG_GET(tsk);
	if (sw_data != NULL) {
		LVE_DBG("sw_data=%p comm=%s\n", sw_data, tsk->comm);
		lve_exit_task(tsk, sw_data);
		LVE_TAG_PUT(sw_data);
	}

	lve_jprobe_ret();
}

static struct jprobe lve_fork_jp = {
	.entry		= JPROBE_ENTRY(lve_fork_hook),
	.kp.symbol_name = "cgroup_post_fork"
};

static struct jprobe lve_free_task_jp = {
	.entry		= JPROBE_ENTRY(lve_free_task_hook),
	.kp.symbol_name	= "free_task",
};

static struct jprobe *jp[] = {
	&lve_fork_jp,
	&lve_free_task_jp,
};

int lve_hooks_init(void)
{
	return lve_jprobes_reg(jp, ARRAY_SIZE(jp));

}

void lve_hooks_fini(void)
{
	lve_jprobes_unreg(jp, ARRAY_SIZE(jp));
}
