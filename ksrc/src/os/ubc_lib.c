#include <linux/kernel.h>

#include <bc/beancounter.h>

#include "lve-api.h"

#include "lve_kmod_c.h"
#include "lve_internal.h"
#include "resource.h"
#include "lve_debug.h"
#include "kernel_exp.h"
#include "ubc_lib.h"

/* CL API */
#ifdef UBC_CL_API
long lve_setublimit(struct user_beancounter *ub, unsigned long resource,
		unsigned long *new_limits);
#else
long lve_setublimit(uid_t ub, unsigned long resource,
		unsigned long *new_limits);
#endif


static unsigned long ubc_stat(struct user_beancounter *ub, int index, int *precharge)
{
	unsigned long held;

	held = ub->ub_parms[index].held;
	held = (held > precharge[index]) ? (held - precharge[index]) : 0;

	return held;
}

void ubc_mem_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge)
{
	res->data = ubc_stat(ub, LVE_MEM_LIMIT_RES, precharge);
	res->fail = ub->ub_parms[LVE_MEM_LIMIT_RES].failcnt;
}

void ubc_phys_mem_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge)
{
	res->data = ubc_stat(ub, LVE_MEM_PHY_LIMIT_RES, precharge);
	res->fail = ub->ub_parms[LVE_MEM_PHY_LIMIT_RES].failcnt;
}

void ubc_nproc_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge)
{
	res->data = ubc_stat(ub, LVE_NPROC_LIMIT_RES, precharge);
	res->fail = ub->ub_parms[LVE_NPROC_LIMIT_RES].failcnt;
}

#ifndef UBC_CL_API
long __do_setublimit(struct user_beancounter *ub, unsigned long resource,
		unsigned long *new_limits)
{
	unsigned long ub_uid;

	/* OVZ native api */
#if RHEL_MAJOR < 7
	ub_uid = ub->ub_uid;
#else
	int ret = kstrtoul(ub->ub_name, 10, &ub_uid);
	if (ret < 0)
		return -EINVAL;
#endif
	return lve_setublimit(ub_uid, resource, new_limits);
}
#else
#define __do_setublimit lve_setublimit
#endif

int init_beancounter_swap_limits(struct user_beancounter *ub)
{
	return __do_setublimit(ub, UB_SWAPPAGES,
			     (unsigned long[2]){lve_swappages, lve_swappages});
}

void init_beancounter_nolimits(struct user_beancounter *ub)
{
	int k, rc;

	for (k = 0; k < UB_RESOURCES; k++) {
		ub->ub_parms[k].limit = UB_MAXVALUE;
		/* FIXME: whether this is right for physpages and guarantees? */
		ub->ub_parms[k].barrier = UB_MAXVALUE;
	}
	/* No guaranteed pages, vm_enough_memory() should perform checks */
	ub->ub_parms[UB_VMGUARPAGES].limit = 0;
	ub->ub_parms[UB_VMGUARPAGES].barrier = 0;

	rc = init_beancounter_swap_limits(ub);
	if (rc != 0)
		LVE_WARN("failed to update swappages limit, rc=%d\n", rc);
}

int ubc_set_res(struct user_beancounter *lve_ub, int res, uint32_t new)
{
	unsigned long limits[2];

	/* temporary disable a ubc limits for LVE in ve case */
	if (lve_ub == NULL)
		return 0;

	if (new == 0) {
		limits[0] = limits[1] = UB_MAXVALUE;
	} else {
		limits[0] = UB_MAXVALUE;
		limits[1] = new;
	}
	return lve_call(__do_setublimit(lve_ub, res, limits),
					LVE_FAIL_SETUBLIMIT, -EINVAL);
}

#ifdef HAVE_UB_SHORTAGE_CB
void ubc_shortage(struct user_beancounter * ubc, int resource)
{
	int fail = 0;

	switch (resource) {
		case LVE_MEM_LIMIT_RES:
			fail = LVE_RESOURCE_FAIL_MEM;
			break;
		case LVE_MEM_PHY_LIMIT_RES:
			fail = LVE_RESOURCE_FAIL_MEM_PHY;
			break;
		case LVE_NPROC_LIMIT_RES:
			fail = LVE_RESOURCE_FAIL_NPROC;
			break;
		default:
			/* No need to handle unknown resources */
			return;
	}

	lve_resource_fail(current, fail);
}
#endif
