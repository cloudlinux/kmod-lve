#include <linux/linkage.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/random.h>
#include <linux/capability.h>
#include <linux/module.h>
#include <linux/mutex.h>

#include <linux/sched.h>

#include "lve_debug.h"
#include "lve_internal.h"
#include "tags.h"
#include "light_ve.h"
#include "resource.h"
#include "lve_global_params.h"
#include "lve_task_locker.h"
#include "lve_net.h"

#define CPU_LIM_KERNEL_TO_LOWRES(rate) DIV_ROUND_UP(rate, 100 * num_online_cpus())

static int lve_create(uint32_t lvp_id, uint32_t ve_id)
{
	struct light_ve *ve;
	int rc = 0;

	LVE_ENTER("(ve_id=%u)\n", ve_id);

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	ve = lve_find_or_alloc(lvp_id, ve_id);
	if (IS_ERR(ve))
		rc = PTR_ERR(ve);
	else
		light_ve_put(ve);

	return rc;
}

static int
lve_destroy(uint32_t lvp_id, uint32_t ve_id)
{
	int rc = 0;
	struct light_ve *ve;

	LVE_ENTER("(ve_id=%u)\n", ve_id);

	if (!capable(CAP_LVE_ADMIN)) {
		rc = -EPERM;
		goto out;
	}

	ve = lve_find(lvp_id, ve_id);
	if (ve == NULL) {
		rc = -ESRCH;
		lve_lvp_map_del(ve_id);
		goto out;
	}

	lve_unlink(ve->lve_lvp, LVE_UNLINK_VE, ve);

	light_ve_put(ve);
out:
	trace_lve_destroy(lvp_id, ve_id, rc);

	return rc;
}

static int lve_start(void)
{
	return lve_namespace_set_default();
}

static int lve_check_limits(lve_limits_t ulimits, bool hires)
{
	if (hires) {
		if (ulimits[LIM_CPU] < 0) {
			LVE_ERR("invalid cpu limit %d\n", ulimits[LIM_CPU]);
			return -ERANGE;
		}

		if (ulimits[LIM_CPU] > (10000 * num_online_cpus()))
			ulimits[LIM_CPU] = 10000 * num_online_cpus();
	} else {
		if (ulimits[LIM_CPU] < 0 || ulimits[LIM_CPU] > 100) {
			LVE_ERR("invalid old style cpu limit %d\n", ulimits[LIM_CPU]);
			return -ERANGE;
		}
	}

	if (ulimits[LIM_CPU_WEIGHT] < 0 || ulimits[LIM_CPU_WEIGHT] > 100) {
		LVE_ERR("invalid cpu weight %d\n", ulimits[LIM_CPU_WEIGHT]);
		return -ERANGE;
	}
	if (unlikely(ulimits[LIM_CPU_WEIGHT] == 0)) {
		LVE_DBG("weight 0 corrected to 100\n");
		ulimits[LIM_CPU_WEIGHT] = 100;
	}

	if (ulimits[LIM_IO] < 0) {
		LVE_ERR("invalid io limit %d\n", ulimits[LIM_IO]);
		return -ERANGE;
	}

	if (ulimits[LIM_IOPS] < 0) {
		LVE_ERR("invalid iops limit %d\n", ulimits[LIM_IOPS]);
		return -ERANGE;
	}

	if (ulimits[LIM_ENTER] < 0) {
		LVE_ERR("invalid enter limit %d\n", ulimits[LIM_ENTER]);
		return -ERANGE;
	}

	if (ulimits[LIM_NPROC] < 0) {
		LVE_ERR("invalid nproc limit %d\n", ulimits[LIM_NPROC]);
		return -ERANGE;
	}

	if (ulimits[LIM_MEMORY] < 0) {
		LVE_ERR("invalid mem limit %d\n", ulimits[LIM_MEMORY]);
		return -ERANGE;
	}

	if (ulimits[LIM_MEMORY_PHY] < 0) {
		LVE_ERR("invalid memphy limit %d\n", ulimits[LIM_MEMORY_PHY]);
		return -ERANGE;
	}

	return 0;
}

/*
 * Adjust limits from library format to kernel format.
 */
static void _adjust_limits(lve_limits_t ulimits, bool hires)
{
	if (hires) {
		/* if cpu limit == 0 it means unlimited */
		if (ulimits[LIM_CPU] == 0) {
			ulimits[LIM_CPU] = 10000 * ulimits[LIM_CPUS];
		}
	} else {
		/*
		 * Adjust old style limits(MAX == 100%) to
		 * kernel format(MAX == 10000 * CPUS)
		 */
		ulimits[LIM_CPU]  = 100 * ulimits[LIM_CPUS] * ulimits[LIM_CPU];
	}
}

static int _lve_setup(uint32_t lvp_id, uint32_t ve_id, lve_limits_t lim, bool hires)
{
	int rc = 0;
	struct light_ve *ve;
	struct lvp_ve_private *lvp;

	LVE_ENTER("(lvp=%u, ve_id=%u, lim={[CPU]=%u, [IO]=%u, [ENTER]=%u, "
		  "[CPUS]=%u, [MEMORY]=%u, [MEMPHY]=%u, [CPU_WEIGHT]=%u, "
		  "[NPROC]=%u, [IOPS]=%u}, hires=%d)\n", lvp_id, ve_id,
		  lim[LIM_CPU], lim[LIM_IO], lim[LIM_ENTER], lim[LIM_CPUS],
		  lim[LIM_MEMORY],lim[LIM_MEMORY_PHY], lim[LIM_CPU_WEIGHT],
		  lim[LIM_NPROC], lim[LIM_IOPS], hires);

	if (lve_check_limits(lim, hires)) {
		rc = -ERANGE;
		goto out;
	}

	_adjust_limits(lim, hires);

	if (ve_id == ROOT_LVE) {
		lvp = lvp_find(lvp_id);
		if (lvp == NULL)
			return -ESRCH;
		/* XXX */
		memcpy(&lvp->lvp_def_limits, lim, sizeof(lve_limits_t));
		lvp_put(lvp);
	} else {
		ve = lve_find_or_alloc(lvp_id, ve_id);
		if (IS_ERR(ve)) {
			rc = PTR_ERR(ve);
			goto out;
		}

		rc = lve_resources_setup(ve, lim, false);
		light_ve_put(ve);
	}
out:
	trace_lve_setup(lvp_id, ve_id, lim, hires, rc);

	return rc;
}

int
_lve_enter(struct task_struct *enter_task, uint32_t lvp_id, uint32_t ve_id,
	   struct ve_enter *ve_data)
{
	struct switch_data *sw_data = NULL;
	struct light_ve *ve;
	long rc;
	int fatal = 0;
	uint64_t nid;

	nid = lve_node_id(enter_task);
	if (unlikely(nid < 0)) {
		LVE_ERR("unable to determine task (%u:%s) domain\n",
			task_pid_nr(enter_task), enter_task->comm);
		rc = -ESRCH;
		goto out;
	}

	if (NODEID_LVEID(nid) != ROOT_LVE) {
		if ((ve_data->flags & LVE_ENTER_SILENCE) == 0)
			LVE_WARN("Can't enter lve from a slave context, "
				 "pid %u, oldve %llu\n",
				 task_pid_nr(current), NODEID_LVEID(nid));
		rc = -EPERM;
		goto out;
	}

	if (ve_id == ROOT_LVE) {
		if ((ve_data->flags & LVE_ENTER_SILENCE) == 0)
			LVE_WARN("lve id must not be equal ROOT_LVE\n");
		rc = -EINVAL;
		goto out;
	}

	sw_data = switch_tag_attach(enter_task);
	if (sw_data == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	ve = lve_find_or_alloc(lvp_id, ve_id);
	LVE_DBG("lve_find_alloc return %p - %ld\n", ve, PTR_ERR(ve));
	if (IS_ERR(ve)) {
		LVE_ERR("Can't alloc ve #%u lvp #%u, rc %ld\n",
			ve_id, lvp_id, PTR_ERR(ve));
		rc = PTR_ERR(ve);
		ve = NULL;
		goto out_admin;
	}

	if (ve->lve_disable) {
		light_ve_put(ve);
		rc = -EPERM;
		goto out_admin;
	}

	switch_tag_account(sw_data, ve);

	if (ve_data->cookie) {
		get_random_bytes(&sw_data->sw_cookie, sizeof(sw_data->sw_cookie));
		LVE_DBG("generate cookie %x\n", sw_data->sw_cookie);
	}

	if (((ve_data->flags & LVE_ENTER_NO_MAXENTER) == 0) &&
	    lve_ep_charge(ve)) {
		    rc = -E2BIG;
		    goto out_admin;
	}

	if (ve_data->cookie && copy_to_user(ve_data->cookie, &sw_data->sw_cookie,
			 sizeof(sw_data->sw_cookie))) {
		LVE_ERR("can't copy cookie into application\n");
		rc = -EFAULT;
		goto out_admin;
	}

	sw_data->sw_flags = ve_data->flags;
	rc = lve_resource_push(enter_task, ve, sw_data);
	/*
	 * The unlink protocol requires that we check lve_unlinked
	 * strictly after entering the corresponding CPU cgroup.
	 * Doing it in the reverse order might lead to the following
	 * scenario:
	 * 1. [lve_enter]  check lve_unlinked when it's 0
	 * 2. [lve_unlink] set lve_unlinked to 1
	 * 3. [lve_unlink] kill all threads of the CPU cgroup
	 * 4. [lve_enter]  lve_resource_push()
	 */
	if (unlikely(ve->lve_unlinked)) {
		fatal = 1;
		rc = -EPERM;
	} else if (rc == 0) {
		goto out;
	}

out_admin:
	lve_exit_task(enter_task, sw_data);
	/* some fatal error need to kill*/
	if (fatal)
		force_sig(SIGKILL, enter_task);
out:
	trace_lve_enter(enter_task, lvp_id, ve_id, ve_data->flags,
			rc == 0 ? sw_data->sw_cookie : 0,
			rc);

	return rc;
}

static int
__lve_leave(struct task_struct *leave_task, uint32_t ve_cookie)
{
	int rc = 0;
	struct switch_data *sw_data;
	struct lvp_ve_private *lvp;

	lvp = TASK_VE_PRIVATE(leave_task);
	sw_data = LVE_TAG_GET(leave_task);
	if (sw_data == NULL) {
		LVE_ERR("can't find info from enter\n");
		rc = -EINVAL;
		goto kill_no_tag;
	}

	if (sw_data->sw_task != leave_task) {
		/*
		 * We don't want to childs of process which enter to lve
		 * be able to leave it, even if they got cookie. It's a
		 * security measures.
		 */
		LVE_WARN("trying to leave without entering lve %d:%s\n",
			leave_task->pid, leave_task->comm);
		rc = -EINVAL;
		goto kill;
	}

	if (!capable(CAP_LVE_ADMIN)) {
		if (ve_cookie != sw_data->sw_cookie) {
			LVE_DBG("Wrong cookie %x - %x\n", ve_cookie, sw_data->sw_cookie);
			rc = -EINVAL;
			goto kill;
		}
	}

	rc = lve_resource_pop(leave_task, lvp->lvp_default, sw_data);
	if (rc != 0) {
		LVE_ERR("failed to pop cpu context for %d:%s\n",
			leave_task->pid, leave_task->comm);
		goto kill;
	}

kill:
	lve_exit_task(leave_task, sw_data);
	LVE_TAG_PUT(sw_data);
kill_no_tag:
	if (rc != 0)
		force_sig(SIGKILL, current);

	trace_lve_leave(leave_task, ve_cookie, rc);

	return rc;
}

void lve_exit_task(struct task_struct *task, struct switch_data *sw_data)
{
	if (sw_data->sw_task == task)
		sw_data->sw_task = NULL;

	LVE_TAG_CLEAR(task);
	/* drop reference from lve_enter() or fork() */
	LVE_TAG_PUT(sw_data);
}

static int
lve_leave(void __user *data)
{
	uint32_t ve_cookie;
	int rc = 0;
	struct ve_leave ve_data;

	if (copy_from_user(&ve_data, data, sizeof(ve_data))) {
		LVE_ERR("Can't read control data from application\n");
		goto exit;
	}

	if (copy_from_user(&ve_cookie, ve_data.cookie, sizeof(ve_cookie))) {
		LVE_ERR("Can't read cookie from application\n");
		rc = -EFAULT;
		goto exit;
	}

	lve_task_lock(current);
	rc = __lve_leave(current, ve_cookie);
	lve_task_unlock(current);
exit:
	return rc;
}

static int
sys_lve_flush(void __user *data)
{
	struct lve_flush flush;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&flush, data, sizeof(flush))) {
		LVE_ERR("can't read flush params\n");
		return -EFAULT;
	}

	LVE_ENTER("(all=%d)\n", flush.all);

	lve_unlink(TASK_VE_PRIVATE(current),
		   flush.all ? LVE_UNLINK_ALL : LVE_UNLINK_DEFAULT, NULL);

	return 0;
}

/* 0.8 */
static int
lve_enter_06(uint32_t lvp_id, uint32_t ve_id, void __user *data)
{
	int ret;
	struct ve_enter    ve_data;

	if (copy_from_user(&ve_data, data, sizeof(ve_data))) {
		printk(KERN_ERR "Can't read control data from application\n");
		return -EFAULT;
	}

	lve_task_lock(current);
	ret = _lve_enter(current, lvp_id, ve_id, &ve_data);
	lve_task_unlock(current);

	return ret;
}

static int
lve_enter_fs_06(void __user *data)
{
	struct switch_data *sw_data = NULL;
	struct ve_enter_fs_06 ve_efs;
	struct light_ve *ve;
	int rc;
	struct lve_namespace *saved_ns = NULL;

	if (copy_from_user(&ve_efs, data, sizeof(ve_efs))) {
		LVE_DBG("Can't read control data from application\n");
		return -EFAULT;
	}

	LVE_ENTER("(admin=%d)\n", ve_efs.admin);

	sw_data = LVE_TAG_GET(current);
	if (sw_data == NULL) {
		rc = -EPERM;
		goto out;
	}
	ve = sw_data->sw_from;

	if (sw_data->sw_task == current)
		saved_ns = &sw_data->sw_ns;

	if (ve_efs.admin)
		rc = lve_namespace_enter_admin(ve, saved_ns);
	else
		rc = lve_namespace_enter(current, ve, saved_ns);

	if (rc == 0 && sw_data->sw_task == current)
		sw_data->sw_flags |= LVE_ENTER_NAMESPACE;
	LVE_TAG_PUT(sw_data);
out:
	LVE_DBG("entered fs rc=%d\n", rc);

	return rc;

}

int is_in_lve(struct task_struct *task)
{
	return (NODEID_LVEID(lve_node_id(task)) != ROOT_LVE);
}

static int
lve_setup_06(uint32_t ve_id, void __user *data)
{
	struct ve_config_10 _cfg;
	struct ve_config    cfg;

	if (!capable(CAP_LVE_ADMIN) && (is_in_lve(current) || !lve_user_setup))
		return -EPERM;

	if (copy_from_user(&_cfg, data, sizeof(_cfg))) {
		printk(KERN_ERR "can't read config params\n");
		return -EFAULT;
	}

	memset(&cfg, 0, sizeof(cfg));
	/* ve_config head is the same as ve_config_10 */
	memcpy(&cfg, &_cfg, sizeof(_cfg));

	return _lve_setup(ROOT_LVP, ve_id, cfg.ulimits, false);
}

static int
lve_setup_enter_06(uint32_t ve_id, void __user *data)
{
	int rc;
	struct lve_setup_enter_10 l_data;

	if (copy_from_user(&l_data, data, sizeof(l_data))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	rc = lve_setup_06(ve_id, l_data.setup);
	if (rc)
		return rc;

	return lve_enter_06(ROOT_LVP, ve_id, l_data.enter);
}


static int
lve_set_default_06(void __user *data)
{
	struct ve_config vedef;
	lve_limits_11_t limits;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&vedef, data, sizeof(vedef))) {
		printk(KERN_ERR "can't read default params\n");
		return -EFAULT;
	}
	memset(limits, 0, sizeof(limits));
	memcpy(limits, vedef.ulimits, sizeof(vedef.ulimits));

	return _lve_setup(ROOT_LVP, ROOT_LVE, limits, false);
}

static int
lve_get_info_06(uint32_t lvp_id, uint32_t ve_id, void __user *data)
{
	int rc = -ESRCH;
	struct ve_config cfg;
	struct light_ve *ve = NULL;
	lve_limits_t *limits;
	struct lvp_ve_private *lvp;

	/* XXX i don't think this need admin rights */

	if (ve_id == ROOT_LVE) {
		lvp = TASK_VE_PRIVATE(current);
		limits = &lvp->lvp_def_limits;
	} else {
		ve = lve_find(lvp_id, ve_id);
		if (ve == NULL)
			return rc;
		limits = &ve->lve_limits;
	}

	/** XXX limits lock */
	memcpy(cfg.ulimits, limits, sizeof(cfg.ulimits));
	if (ve)
		light_ve_put(ve);

	rc = copy_to_user(data, &cfg, sizeof(cfg));
	if (rc)
		rc = -EFAULT;

	return rc;
}


/* 1.1 */
static int lve_setup_11(uint32_t ve_id, void __user *data)
{
	struct ve_config_11 _cfg;
	struct ve_config    cfg;

	if (!capable(CAP_LVE_ADMIN) && (is_in_lve(current) || !lve_user_setup))
		return -EPERM;

	if (copy_from_user(&_cfg, data, sizeof(_cfg))) {
		printk(KERN_ERR "can't read config params\n");
		return -EFAULT;
	}

	memset(&cfg, 0, sizeof(cfg));
	memcpy(&cfg, &_cfg, sizeof(_cfg));

	return _lve_setup(ROOT_LVP, ve_id, cfg.ulimits, false);
}

static int
lve_setup_enter_11(uint32_t ve_id, void __user *data)
{
	int rc;
	struct lve_setup_enter_10 l_data;

	if (copy_from_user(&l_data, data, sizeof(l_data))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	rc = lve_setup_11(ve_id, l_data.setup);
	if (rc)
		return rc;

	return lve_enter_06(ROOT_LVP, ve_id, l_data.enter);
}

enum lve_kflags lve_to_flags_11(struct light_ve *ve)
{
	enum lve_kflags ret = 0;

	if (ve == NULL)
		return 0;

	if (ve->lve_disable)
		ret |= LVE_KFL_DISABLED;

	return ret;
}

void flags_to_lve_11(struct light_ve *ve, enum lve_kflags fl)
{
	if (ve == NULL)
		return;

	/* XXX enter lock ? */
	ve->lve_disable = 0;
	if (fl & LVE_KFL_DISABLED)
		ve->lve_disable = 1;

	return;
}

static int
lve_get_info_11(uint32_t lvp_id, uint32_t ve_id, void __user *data)
{
	int rc = -ESRCH;
	struct lve_info_11 cfg;
	struct light_ve *ve = NULL;
	lve_limits_t *limits;
	struct lvp_ve_private *lvp;

	/* XXX i don't think this need admin rights */
	if (ve_id == ROOT_LVE) {
		lvp = TASK_VE_PRIVATE(current);
		limits = &lvp->lvp_def_limits;
	} else {
		ve = lve_find(lvp_id, ve_id);
		if (ve == NULL)
			return rc;
		limits = &ve->lve_limits;
	}

	/** XXX limits lock */
	memcpy(cfg.li_limits, limits, sizeof(cfg.li_limits));
	cfg.li_limits[LIM_CPU] = CPU_LIM_KERNEL_TO_LOWRES(cfg.li_limits[LIM_CPU]);
	cfg.li_flags = lve_to_flags_11(ve);

	if (ve)
		light_ve_put(ve);

	rc = copy_to_user(data, &cfg, sizeof(cfg));
	if (rc)
		rc = -EFAULT;

	return rc;
}

static int
lve_setup_flags_11(uint32_t lvp_id, uint32_t ve_id, void __user *data)
{
	struct light_ve *ve;
	enum lve_kflags fl;

	if (copy_from_user(&fl, data, sizeof(fl))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	ve = lve_find(lvp_id, ve_id);
	if (ve == NULL)
		return -ESRCH;

	flags_to_lve_11(ve, fl);

	light_ve_put(ve);
	return 0;
}


static int
lve_enter_pid_11(uint32_t lvp, uint32_t ve_id, void __user *data)
{
	int rc = 0;
	struct ve_enter_pid ve_data;
	struct ve_enter    _ve_data;
	struct task_struct *task;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&ve_data, data, sizeof(ve_data))) {
		printk(KERN_ERR "Can't read control data from application\n");
		return -EFAULT;
	}
	_ve_data.cookie = NULL;
	_ve_data.flags = ve_data.flags;

	task = lve_find_task(ve_data.pid);
	if (task) {
		lve_task_lock(task);
		rc = _lve_enter(task, lvp, ve_id, &_ve_data);
		lve_task_unlock(task);
		put_task_struct(task);
	} else {
		rc = - ESRCH;
	}

	return rc;
}

static int
lve_leave_pid_11(void __user *data)
{
	int rc = 0;
	struct ve_leave_pid ve_data;
	struct task_struct *task;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&ve_data, data, sizeof(ve_data))) {
		LVE_ERR("Can't read control data from application\n");
		goto exit;
	}

	task = lve_find_task(ve_data.pid);
	if (task) {
		lve_task_lock(task);
		rc = __lve_leave(task, 0);
		lve_task_unlock(task);
		put_task_struct(task);
	} else {
		rc = - ESRCH;
	}

exit:
	return rc;
}

static int lve_set_fail_val(void __user *data)
{
	struct lve_fail_val fail_data;
	int rc = 0;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&fail_data, data, sizeof(fail_data))) {
		LVE_ERR("Can't read fail data from application\n");
		rc = -EFAULT;
	}
	fail_value = fail_data.val;

	return rc;
}

long lve_fs_root(uint32_t lvp_id, uint32_t ve_id, const char __user *root)
{
	struct light_ve *ve;
	long rc;

	ve = lve_find(lvp_id, ve_id);
	if (ve == NULL)
		return -ESRCH;

	rc = lve_namespace_set_root(ve, root);
	light_ve_put(ve);

	return rc;
}

static int
lve_get_info_13(uint32_t lvp_id, uint32_t ve_id, void __user *data)
{
	int rc = -ESRCH;
	struct lve_info_13 cfg;
	struct light_ve *ve = NULL;
	lve_limits_13_t *limits;
	struct lvp_ve_private *lvp;

	/* XXX i don't think this need admin rights */
	if (ve_id == ROOT_LVE) {
		lvp = TASK_VE_PRIVATE(current);
		limits = &lvp->lvp_def_limits;
	} else {
		ve = lve_find(lvp_id, ve_id);
		if (ve == NULL)
			return rc;
		limits = &ve->lve_limits;
	}

	/** XXX limits lock */
	memcpy(cfg.li_limits, limits, sizeof(cfg.li_limits));
	cfg.li_flags = lve_to_flags_11(ve);

	if (ve)
		light_ve_put(ve);

	rc = copy_to_user(data, &cfg, sizeof(cfg));
	if (rc)
		rc = -EFAULT;

	return rc;
}

/* 1.3 */
static int
lve_setup_13(uint32_t lvp, uint32_t ve_id, void __user *data)
{
	struct ve_config_13 _cfg;
	struct ve_config    cfg;

	if (!capable(CAP_LVE_ADMIN) && (is_in_lve(current) || !lve_user_setup))
		return -EPERM;

	if (copy_from_user(&_cfg, data, sizeof(_cfg))) {
		printk(KERN_ERR "can't read config params\n");
		return -EFAULT;
	}
	/* */
	cfg = _cfg;

	return _lve_setup(lvp, ve_id, cfg.ulimits, true);
}

static int
lve_setup_enter_13(uint32_t lvp, uint32_t ve_id, void __user *data)
{
	int rc;
	struct lve_setup_enter_13 l_data;

	if (copy_from_user(&l_data, data, sizeof(l_data))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	rc = lve_setup_13(lvp, ve_id, l_data.setup);
	if (rc)
		return rc;

	return lve_enter_06(lvp, ve_id, l_data.enter);
}

static int
lve_setup_flags_13(uint32_t lvp_id, uint32_t ve_id, void __user *data)
{
	struct light_ve *ve;
	enum lve_kflags fl;

	if (copy_from_user(&fl, data, sizeof(fl))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	ve = lve_find(lvp_id, ve_id);
	if (ve == NULL)
		return -ESRCH;
	flags_to_lve_11(ve, fl);

	light_ve_put(ve);
	return 0;
}

static int lve_check_fault_13(void __user *data)
{
	int rc;
	struct switch_data * sw_data;

	sw_data = LVE_TAG_GET(current);
	if (sw_data == NULL)
		return -ESRCH;

	rc = copy_to_user(data, &sw_data->sw_failmask,
			  sizeof(sw_data->sw_failmask));
	if (rc)
		goto out;

	sw_data->sw_failmask = 0;

out:
	LVE_TAG_PUT(sw_data);
	return rc;
}

long lve_ns_assign(uint32_t lvp_id, uint32_t ve_id)
{
	struct light_ve *ve;
	long rc;

	LVE_ENTER("(ve_id=%u)\n", ve_id);

	if (lve_no_namespaces)
		return -ENOSYS;

	ve = lve_find(lvp_id, ve_id);
	if (ve == NULL)
		return -ESRCH;

	rc = lve_namespace_assign(ve);
	light_ve_put(ve);

	return rc;
}

/* 1.4 */
static int
lve_set_global_param_14(void __user *data)
{
	struct lve_global_params_14 param;
	enum lve_params p;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&param, data, sizeof(param))) {
		LVE_ERR("Can't read global parameter\n");
		return -EFAULT;
	}

	p = (enum lve_params)param.index;

	LVE_DBG("parameter index=%d value=%llu\n", p, param.val);

	return lve_set_param(p, param.val);
}

static int
lve_get_global_param_14(void __user *data)
{
	int rc;
	struct lve_global_params_14 param;
	enum lve_params p;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&param, data, sizeof(param))) {
		LVE_ERR("Can't read global parameters");
		return -EFAULT;
	}

	p = (enum lve_params)param.index;

	rc = lve_get_param(p, &param.val);
	if (rc != 0) {
		LVE_WARN("Can't get parameter index=%d\n", p);
		return rc;
	}

	if (copy_to_user(data, &param, sizeof(param))) {
		LVE_ERR("Can't copy global parameters\n");
		rc = -EFAULT;
	}

	LVE_DBG("parameter index=%d value=%llu\n", p, param.val);

	return rc;
}

static int
lve_get_pid_info_14(void __user *data)
{
	int rc = 0;
	struct lve_pid_info_14 info;
	struct task_struct *tsk;
	struct switch_data *sw_data;
	struct light_ve *lve;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&info, data, sizeof(info))) {
		LVE_ERR("Can't read info from application\n");
		return -EFAULT;
	}

	tsk = lve_find_task(info.pid);
	if (tsk == NULL) {
		LVE_ERR("Can't find task pid=%llu\n", info.pid);
		return -EINVAL;
	}

	sw_data = LVE_TAG_GET(tsk);
	if (sw_data == NULL) {
		rc = -ESRCH;
		goto out;
	}

	BUG_ON(sw_data->sw_from == NULL);

	lve = sw_data->sw_from;

	LVE_DBG("task comm=%s pid=%u lve id=%u\n",
		tsk->comm, tsk->pid, lve->lve_id);

	/* XXX */
	info.id = lve->lve_id;
	info.flags = sw_data->sw_flags;
	info.leader = sw_data->sw_task == tsk;

	if (copy_to_user(data, &info, sizeof(info))) {
		LVE_ERR("Can't write info to application\n");
		rc = -EFAULT;
		/* fallthrough */
	}

	LVE_TAG_PUT(sw_data);
out:
	put_task_struct(tsk);
	return rc;
}

static int
lve_set_net_limits_14(uint32_t lvp_id, uint32_t veid, void __user *data)
{
	struct light_ve *lve;
	struct lve_net_limits_14 limit;
	int rc;

	if (copy_from_user(&limit, data, sizeof(limit))) {
		LVE_ERR("Can't read info from application\n");
		return -EFAULT;
	}

	LVE_ENTER("\n");
	lve = lve_find(lvp_id, veid);
	if (lve == NULL)
		return -ESRCH;

	rc = lve_net_bw_limit_set(lve, limit.in_lim, limit.out_lim);

	light_ve_put(lve);

	return rc;
}

static int
lve_net_port_limits_14(uint32_t lvp_id, uint32_t veid, void __user *data)
{
	struct light_ve *lve;
	struct lve_net_port_14 ports;
	int ret;

	LVE_ENTER("\n");
	if (copy_from_user(&ports, data, sizeof(ports))) {
		LVE_ERR("Can't read info from application\n");
		return -EFAULT;
	}

	lve = lve_find(lvp_id, veid);
	if (lve == NULL)
		return -ESRCH;

	LVE_DBG("ports ctl %u : %d %d\n", ports.op, ports.port, ports.policy);
	switch (ports.op) {
		case LVE_NETPORT_ADD: {
			bool policy = ports.policy != 0 ? true : false;

			ret = lve_net_port_add(lve, ports.port, policy);
			break;
		}
		case LVE_NETPORT_DEL: {
			ret = lve_net_port_del(lve, ports.port);
			break;
		}
		case LVE_NETPORT_DEFAULT: {
			bool policy = ports.policy != 0 ? true : false;

			ret = lve_net_port_def(lve, policy);
			break;
		}
		default:
			ret = -EINVAL;
			break;
	}
	light_ve_put(lve);

	return ret;
}

/* Freezer control */
static int
lve_freezer(uint32_t lvp_id, uint32_t ve_id, void __user *data)
{
	int rc;
	struct light_ve *ve;
	struct lve_freezer_control fc;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&fc, data, sizeof(fc))) {
		LVE_ERR("Can't read info from application\n");
		return -EFAULT;
	}

	ve = lve_find(lvp_id, ve_id);
	if (ve == NULL)
		return -ESRCH;

	switch (fc.op) {
	case LVE_FREEZER_FREEZE:
		rc = os_freezer_freeze(ve);
		break;
	case LVE_FREEZER_THAW:
		rc = os_freezer_thaw(ve);
		break;
	default:
		LVE_DBG("Freezer: unknown op\n");
		rc = -EINVAL;
		break;
	}

	light_ve_put(ve);
	return rc;
}

static int lve_lvp_create_15(uint32_t lvp_id, void __user *data)
{
	int ret = -ENOSYS;
#ifndef LVE_IN_VE
	struct lvp_ve_private *lvp;

	ret = 0;
	lvp = lvp_alloc(lvp_id, NULL);
	if (lvp == NULL)
		ret = -ENOMEM;
#endif
	return ret;
}

static int lve_lvp_setup_15(uint32_t lvp_id, void __user *data)
{
	int ret = -ENOSYS;
#ifndef LVE_IN_VE
	struct lvp_limits_data cfg;


	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&cfg, data, sizeof(cfg))) {
		printk(KERN_ERR "can't read config params\n");
		return -EFAULT;
	}

	if (lvp_id == ROOT_LVP && cfg.lld_op == LVP_LIMIT_SELF) {
		ret = -EINVAL;
		LVE_ERR("can't setup limits to root lvp\n");
		goto out;
	}

	switch (cfg.lld_op) {
	case LVP_LIMIT_SELF:
		ret = _lve_setup(lvp_id, SELF_LVE, cfg.lld_ulimits, true);
		break;
	case LVP_LIMIT_DEFAULT:
		ret = _lve_setup(lvp_id, ROOT_LVE, cfg.lld_ulimits, true);
		break;
	default:
		ret = -EINVAL;
		LVE_ERR("wrond lvp setup operation %d\n", cfg.lld_op);
		break;
	}
out:
#endif
	return ret;
}

static int lve_lvp_destroy_15(uint32_t lvp_id, void __user *data)
{
	return lvp_destroy(lvp_id);
}

static int lve_lvp_map_15(uint32_t lve_id, void __user *data)
{
	int ret;
	struct lve_map_data map;

	if (!capable(CAP_LVE_ADMIN)) {
		ret = -EPERM;
		goto out;
	}

	if (copy_from_user(&map, data, sizeof(map))) {
		LVE_ERR("can't read map params\n");
		ret = -EFAULT;
		goto out;
	}

	switch (map.lmd_op) {
	case LVE_MAP_ADD:
		ret = lve_lvp_map_add(lve_id, map.lmd_lvp_id);
		break;
	case LVE_MAP_MOVE:
		ret = lve_lvp_map_move(lve_id, map.lmd_lvp_id);
		break;
	default:
		ret = -ENOSYS;
		break;
	}
out:
	return ret;
}

static int lve_lvp_info_15(uint32_t lvp_id, void __user *data)
{
	int rc = -ESRCH;
	struct lvp_info info;
	lve_limits_13_t *limits = NULL;
	struct lvp_ve_private *lvp;

	if (copy_from_user(&info, data, sizeof(info))) {
		printk(KERN_ERR "%s: can't read params\n", __func__);
		return -EFAULT;
	}

	lvp = lvp_find(lvp_id);
	if (!lvp)
		return rc;

	switch (info.li_op) {
		case LVP_LIMIT_SELF:
			limits = &lvp->lvp_default->lve_limits;
			break;
		case LVP_LIMIT_DEFAULT:
			limits = &lvp->lvp_def_limits;
			break;
		default:
			rc = -EINVAL;
			LVE_ERR("wrong lvp info operation %d\n", info.li_op);
			break;
	}
	if (!limits) {
		lvp_put(lvp);
		return rc;
	}

	memcpy(info.li_info.li_limits, limits, sizeof(info.li_info.li_limits));
	info.li_info.li_flags = 0;
	lvp_put(lvp);

	rc = copy_to_user(data, &info, sizeof(info));

	return rc;
}

/*
 * op is
 *
 */
asmlinkage long sys_light_ve(uint32_t ve, ve_op op, void *data)
{
	long rc = 0;
	uint32_t lvp;

	LVE_DBG("got cmd %u - ID %u - data %p\n", _IOC_NR(op), ve, data);
	if (TASK_VE_PRIVATE(current) == NULL) {
		LVE_WARN("LVE disabled for container\n");
		return -ENOSYS;
	}

	switch (op) {
	case SETUP_VE_COMPAT:
	case SETUP_VE_08:
	case SETUP_VE_11:
	case SETUP_VE_13:
	case INFO_VE_08:
	case INFO_VE_COMPAT:
	case INFO_VE_11:
	case INFO_VE_13:
	/* don't allow to use self_lve id */
	case LVE_LVP_SETUP_15:
		if (ve == SELF_LVE)
			return -EINVAL;
		break;
	case DEFAULT_PARAMS_08:
	case DEFAULT_PARAMS_COMPAT:
	case API_VER:
	case API_VER_COMPAT:
	case LEAVE_VE:
	case LEAVE_VE_COMPAT:
	case FLUSH_VE:
	case FLUSH_VE_COMPAT:
	case ENTER_FS:
	case ENTER_FS_COMPAT:
	case IS_IN_LVE:
	case LEAVE_VE_PID:
	case START_VE:
	case SET_FAIL_VAL:
	case CHECK_FAULT_13:
	case ASSIGN_FS_ROOT_13:
	case SET_GLOBAL_PARAM_VAL_14:
	case GET_GLOBAL_PARAM_VAL_14:
	case LVE_GET_PID_INFO_14:
	case LVE_LVP_INFO_15:
		break;
	default:
		if (lve_id_disabled(ve)) {
			LVE_ERR("try to access to disabled lve id\n");
			return -EINVAL;
		}
	}

	lvp = lve_lvp_map_get(ve);

	switch (op) {
	case DEFAULT_PARAMS_08:
	case DEFAULT_PARAMS_COMPAT:
		rc = lve_set_default_06(data);
		break;
	case ENTER_VE:
	case ENTER_VE_COMPAT:
		rc = lve_enter_06(lvp, ve, data);
		break;
	case LEAVE_VE:
	case LEAVE_VE_COMPAT:
		rc = lve_leave(data);
		break;
	case CREATE_VE:
	case CREATE_VE_COMPAT:
		rc = lve_create(lvp, ve);
		break;
	case DESTROY_VE:
	case DESTROY_VE_COMPAT:
		rc = lve_destroy(lvp, ve);
		break;
	case SETUP_VE_08:
	case SETUP_VE_COMPAT:
		rc = lve_setup_06(ve, data);
		break;
	case FLUSH_VE:
	case FLUSH_VE_COMPAT:
		rc = sys_lve_flush(data);
		break;
	case INFO_VE_08:
	case INFO_VE_COMPAT:
		rc = lve_get_info_06(lvp, ve, data);
		break;
	case API_VER:
	case API_VER_COMPAT:
		rc = LVE_API_VERSION(LVE_KMOD_API_MAJOR, LVE_KMOD_API_MINOR);
		break;
	case SETUP_ENTER_VE_08:
	case SETUP_ENTER_VE_COMPAT:
		rc = lve_setup_enter_06(ve, data);
		break;
	case ENTER_FS:
	case ENTER_FS_COMPAT:
		rc = lve_enter_fs_06(data);
		break;
	/* new in 1.1 */
	case SETUP_VE_11:
		rc = lve_setup_11(ve, data);
		break;
	case SETUP_VE_FLAGS_11:
		rc = lve_setup_flags_11(lvp, ve, data);
		break;
	case SETUP_ENTER_VE_11:
		rc = lve_setup_enter_11(ve, data);
		break;
	case INFO_VE_11:
		rc = lve_get_info_11(lvp, ve, data);
		break;
	case IS_IN_LVE:
		rc = is_in_lve(current);
		break;
	case ENTER_VE_PID:
		rc = lve_enter_pid_11(lvp, ve, data);
		break;
	case LEAVE_VE_PID:
		rc = lve_leave_pid_11(data);
		break;
	case START_VE:
		rc = lve_start();
		break;
	case SET_FAIL_VAL:
		rc = lve_set_fail_val(data);
		break;
	case SETUP_FS_ROOT:
		rc = lve_fs_root(lvp, ve, data);
		break;
	case SETUP_VE_13:
		rc = lve_setup_13(lvp, ve, data);
		break;
	case SETUP_VE_FLAGS_13:
		rc = lve_setup_flags_13(lvp, ve, data);
		break;
	case SETUP_ENTER_VE_13:
		rc = lve_setup_enter_13(lvp, ve, data);
		break;
	case INFO_VE_13:
		rc = lve_get_info_13(lvp, ve, data);
		break;
	case CHECK_FAULT_13:
		rc = lve_check_fault_13(data);
		break;
	case ASSIGN_FS_ROOT_13:
		rc = lve_ns_assign(lvp, ve);
		break;
	case SET_GLOBAL_PARAM_VAL_14:
		rc = lve_set_global_param_14(data);
		break;
	case GET_GLOBAL_PARAM_VAL_14:
		rc = lve_get_global_param_14(data);
		break;
	case LVE_GET_PID_INFO_14:
		rc = lve_get_pid_info_14(data);
		break;
	case LVE_NET_PORT_14:
		rc = lve_net_port_limits_14(lvp, ve, data);
		break;
	case LVE_SET_NET_LIMITS_14:
		rc = lve_set_net_limits_14(lvp, ve, data);
		break;
	case LVE_FREEZER_CONTROL:
	case LVE_FREEZER_CONTROL_COMPAT:
		rc = lve_freezer(lvp, ve, data);
		break;
	/* lvp_id send as ve_id in ioctl api */
	case LVE_LVP_CREATE_15:
		rc = lve_lvp_create_15(ve, data);
		break;
	case LVE_LVP_SETUP_15:
		rc = lve_lvp_setup_15(ve, data);
		break;
	case LVE_LVP_DESTROY_15:
		rc = lve_lvp_destroy_15(ve, data);
		break;
	case LVE_LVP_MAP_15:
		rc = lve_lvp_map_15(ve, data);
		break;
	case LVE_LVP_INFO_15:
		rc = lve_lvp_info_15(ve, data);
		break;
	default:
		LVE_ERR("unknown VE operation %d\n", op);
		rc = -EINVAL;
	};
	LVE_DBG("op %x - return %ld\n", op, rc);
	return rc;
}

int __init lve_init()
{
	int ret = 0;

	ret = switch_init();
	if (ret != 0)
		return ret;

	ret = lve_list_init();
	if (ret != 0)
		goto list_error;

	ret = lve_network_init();
	if (ret != 0)
		goto net_error;

	lve_params_init();

	ret = lve_task_lock_init();
	if (ret != 0)
		goto locker_error;

	ret = lve_res_init();
	if (ret != 0)
		goto res_error;

	ret = lve_lvp_init();
	if (ret != 0)
		goto lvp_error;

	ret = lve_lvp_map_init();
	if (ret == 0)
		return 0;
	lve_lvp_fini();
lvp_error:
	lve_res_fini();
res_error:
	lve_task_lock_fini();
locker_error:
	lve_network_fini();
net_error:
	lve_list_fini();
list_error:
	switch_fini();

	return ret;
}

int lve_fini()
{
	lve_task_lock_fini();
	lve_network_fini();
	lve_list_fini();
	lve_res_fini();
	switch_fini();
	lve_lvp_fini();
	lve_lvp_map_fini();

	return 0;
}
