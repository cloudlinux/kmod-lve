#include <linux/kernel.h>

#include "lve_kmod_c.h"
#include "lve_debug.h"
#include "lve_internal.h"
#include "light_ve.h"
#include "tags.h"
#include "resource.h"
#include "tags.h"
#include "lve_global_params.h"


int
lve_resources_init(struct light_ve *ve)
{
	int rc = 0;


	lve_namespace_init(ve);

	/* XXX should be we have share NS with top root ? */
	rc = lve_namespace_setup(ve->lve_lvp, ve);
	if (rc)
		goto out;

	rc = os_resource_init(ve);
out:
	return rc;
}

int
lve_resources_free(struct light_ve *ve)
{
	int rc  = 0;

	lve_namespace_fini(ve);
	os_resource_fini(ve);

	return rc;
}

int
lve_resources_unlink(struct light_ve *ve)
{
	lve_net_fini(ve);
	return os_resource_unlink(ve->lve_id, lve_private(ve));
}

int lve_resources_setup(struct light_ve *lve, lve_limits_t limits, bool first)
{
	bool custom = false, force_cpu;
	int lim, rc = 0;

	if (limits[LIM_CPUS] < 1 || limits[LIM_CPUS] > num_online_cpus())
		limits[LIM_CPUS] = num_online_cpus();

	force_cpu = lve->lve_limits[LIM_CPUS] != limits[LIM_CPUS];

	for (lim = LIM_CPU; lim < LVE_LIMITS_MAX; lim++) {
		if (first || lve->lve_limits[lim] != limits[lim] ||
		    (lim == LIM_CPU && force_cpu)) {
			rc = os_resource_setup(lve_private(lve),
					       limits[lim], lim);
			if (rc < 0)
				break;

			lve->lve_limits[lim] = limits[lim];

			if (!first)
				custom = true;
		}
	}

	if (custom)
		lve->lve_custom = 1;

	return rc;
}

int lve_resource_push(struct task_struct *task, struct light_ve *ve,
		      struct switch_data *sw_data)
{
	int rc = 0;

	rc = os_cpu_enter(task, lve_private(ve));
	if (rc)
		goto out;

	if ((sw_data->sw_flags & LVE_ENTER_NO_UBC) == 0) {
		rc = os_resource_push(task, lve_private(ve));
		if (rc) {
			LVE_ERR("os_resource_push failed with %d\n", rc);
			goto out;
		}
	}

	if (sw_data->sw_flags & LVE_ENTER_NAMESPACE) {
		rc = lve_namespace_enter(task, ve, &sw_data->sw_ns);
		if (rc)
			LVE_ERR("lve_namespace_enter failed with %d\n", rc);
	}

	rc = os_freezer_enter(task, lve_private(ve));
	if (rc)
		LVE_ERR("os_freezer_enter failed with %d\n", rc);

out:
	return rc;
}

int lve_resource_pop(struct task_struct *task, struct light_ve *ve,
		     struct switch_data *sw_data)
{
	int rc = 0;

	rc = os_cpu_enter(task, lve_private(ve));
	if (rc)
		goto out;

	if ((sw_data->sw_flags & LVE_ENTER_NO_UBC) == 0) {
		rc = os_resource_push(task, lve_private(ve));
		if (rc) {
			LVE_ERR("os_resource_push failed with %d\n", rc);
			goto out;
		}
	}

	if (sw_data->sw_flags & LVE_ENTER_NAMESPACE) {
		rc = lve_namespace_leave(task, &sw_data->sw_ns);
		if (rc)
			LVE_ERR("lve_namespace_leave failed with %d\n", rc);
	}

	rc = os_freezer_enter(task, lve_private(ve));
	if (rc)
		LVE_ERR("os_freezer_enter failed with %d\n", rc);

out:
	return rc;
}

void lve_resource_usage(struct light_ve *lve, struct lve_usage *buf)
{
	memset(buf, 0, sizeof(*buf));

	if (lve->lve_id == ROOT_LVE)
		return;

	buf->data[RES_ENTER].data = lve->lve_stats.st_enters;
	buf->data[RES_ENTER].fail = lve->lve_stats.st_err_enters;
	return os_resource_usage(lve_private(lve), buf);
}

void lve_resource_usage_clear(struct light_ve *lve)
{
	if (lve->lve_id == ROOT_LVE)
		return;

	return os_resource_usage_clear(lve_private(lve));
}

uint64_t lve_node_id(struct task_struct *task)
{
	struct switch_data *sw_data;
	uint32_t lve_id = 0;

	sw_data = LVE_TAG_GET(task);
	if (sw_data != NULL && sw_data->sw_from != NULL)
		lve_id = sw_data->sw_from->lve_id;

	if (sw_data != NULL)
		LVE_TAG_PUT(sw_data);

	return NODEID_ENCODE(task_veid(task), lve_id);
}

void lve_resource_fail(struct task_struct * task, int resource)
{
	struct switch_data * sw_data;

	sw_data = LVE_TAG_GET(task);
	if (sw_data == NULL) {
		LVE_WARN("task %p without tag\n", task);
		return;
	}

	sw_data->sw_failmask |= resource;
	LVE_TAG_PUT(sw_data);
}

int lve_res_init()
{
	int ret;

	ret = os_global_init();
	if (ret != 0)
		return -ENOMEM;

	lve_set_param_callbacks();

	return 0;
}

void lve_res_fini()
{
	os_global_fini();
}


/* parent->child relation protected by child ref
 */
static bool __ep_charge(struct light_ve *ve) 
{
	bool ret = false;

	spin_lock(&ve->lve_stats.enter_lock);
	++ve->lve_stats.st_enters;
	if ((ve->lve_limits[LIM_ENTER] != 0) &&
	    (ve->lve_limits[LIM_ENTER] < ve->lve_stats.st_enters)) {
		    ve->lve_stats.st_err_enters ++;
		    ret = true;
	}
	spin_unlock(&ve->lve_stats.enter_lock);

	return ret;
}

/* return true if over limit */
bool lve_ep_charge(struct light_ve *child)
{
	bool over_limit;

	over_limit = __ep_charge(child);
	over_limit |= __ep_charge(child->lve_lvp->lvp_default);

	return over_limit;
}

void __ep_uncharge(struct light_ve *lve)
{
	spin_lock(&lve->lve_stats.enter_lock);
	--lve->lve_stats.st_enters;
	spin_unlock(&lve->lve_stats.enter_lock);
}

void lve_ep_uncharge(struct light_ve *child)
{
	__ep_uncharge(child->lve_lvp->lvp_default);
	__ep_uncharge(child);
}