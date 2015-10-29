#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bitops.h>

#include "lve_debug.h"
#include "lve_internal.h"
#include "resource.h"
#include "lve_global_params.h"

struct lve_global_params {
	uint8_t bitmask[BITMASK_SZ];
	uint64_t value[PARAM_SZ];
	rwlock_t lock;
	param_cb cb[PARAM_SZ];
};

static struct lve_global_params glob_params;

int lve_update_grace_period(uint64_t val)
{
	struct lvp_ve_private *lvp;

	lvp = TASK_VE_PRIVATE(current);
	LVE_DBG("update grace period from %llu to %llu\n",
		lvp->lvp_grace_period, val);
	lvp->lvp_grace_period = val;

	return 0;
}

void lve_params_init(void)
{
	memset(glob_params.bitmask, 0, BITMASK_SZ);
	memset(glob_params.value, 0, PARAM_SZ * sizeof(uint64_t));
	memset(glob_params.cb, 0, PARAM_SZ * sizeof(param_cb));
	rwlock_init(&glob_params.lock);
}

int lve_set_param(enum lve_params lve_param, uint64_t val)
{
	if (lve_param < 0 || lve_param >= LVE_PARAM_MAX) {
		LVE_ERR("parameter index out of range: %d\n", lve_param);
		return -EINVAL;
	}

	write_lock(&glob_params.lock);

	set_bit(lve_param, (unsigned long *)&glob_params.bitmask);
	glob_params.value[lve_param] = val;


	if (glob_params.cb[lve_param] != NULL)
		glob_params.cb[lve_param](val);

	write_unlock(&glob_params.lock);

	return 0;
}

int lve_get_param(enum lve_params lve_param, uint64_t *val)
{
	int ret = -ENODATA;

	if (lve_param < 0 || lve_param >= LVE_PARAM_MAX) {
		LVE_ERR("parameter index out of range: %d\n", lve_param);
		return -EINVAL;
	}

	read_lock(&glob_params.lock);

	if (test_bit(lve_param, (unsigned long *)&glob_params.bitmask)) {
		*val = glob_params.value[lve_param];
		ret = 0;
	}

	read_unlock(&glob_params.lock);

	return ret;
}

int lve_set_param_callback(enum lve_params lve_param, param_cb cb)
{
	if (lve_param < 0 || lve_param >= LVE_PARAM_MAX) {
		LVE_ERR("parameter index out of range: %d\n", lve_param);
		return -EINVAL;
	}

	glob_params.cb[lve_param] = cb;
	return 0;
}

void lve_set_param_callbacks(void)
{
	lve_set_param_callback(LVE_GRACE_PERIOD, lve_update_grace_period);
}
