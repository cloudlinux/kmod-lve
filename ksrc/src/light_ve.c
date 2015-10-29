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

#define CPU_LIM_KERNEL_TO_LOWRES(rate) DIV_ROUND_UP(rate, 100 * num_online_cpus())

static int lve_create(uint32_t ve_id)
{
	struct light_ve *ve;
	int rc = 0;

	LVE_ENTER("(ve_id=%u)\n", ve_id);

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (ve_id == ROOT_LVE)
		return -EINVAL;

	ve = lve_find_or_alloc(ve_id);
	if (IS_ERR(ve))
		rc = PTR_ERR(ve);
	else
		light_ve_put(ve);

	return rc;
}

static int
lve_destroy(uint32_t ve_id)
{
	int rc = -EPERM;
	struct light_ve *ve;

	LVE_ENTER("(ve_id=%u)\n", ve_id);

	if (!capable(CAP_LVE_ADMIN))
		return rc;

	ve = lve_find(ve_id);
	if (ve == NULL)
		return -ESRCH;

	lve_unlink(ve->lve_lvp, LVE_UNLINK_VE, ve);

	light_ve_put(ve);

	return 0;
}

static int lve_check_limits(lve_limits_t ulimits, bool hires)
{
	if (hires) {
		if (ulimits[LIM_CPU] < 0 || ulimits[LIM_CPU] > (10000 * num_online_cpus())) {
			LVE_ERR("invalid cpu limit %d\n", ulimits[LIM_CPU]);
			return -ERANGE;
		}
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

static int _lve_setup(uint32_t ve_id, lve_limits_t lim, bool hires)
{
	int rc = 0;
	struct light_ve *ve;
	struct lvp_ve_private *lvp;

	LVE_ENTER("(ve_id=%u, lim={[CPU]=%u, [IO]=%u, [ENTER]=%u, "
		  "[CPUS]=%u, [MEMORY]=%u, [MEMPHY]=%u, [CPU_WEIGHT]=%u, "
		  "[NPROC]=%u, [IOPS]=%u}, hires=%d)\n", ve_id, lim[LIM_CPU],
		  lim[LIM_IO], lim[LIM_ENTER], lim[LIM_CPUS], lim[LIM_MEMORY],
		  lim[LIM_MEMORY_PHY], lim[LIM_CPU_WEIGHT], lim[LIM_NPROC],
		  lim[LIM_IOPS], hires);

	if (lve_check_limits(lim, hires))
		return -ERANGE;

	_adjust_limits(lim, hires);

	if (ve_id == ROOT_LVE) {
		/* XXX */
		lvp = TASK_VE_PRIVATE(current);
		memcpy(&lvp->lvp_default->lve_limits, lim, sizeof(lve_limits_t));
	} else {
		ve = lve_find_or_alloc(ve_id);
		if (IS_ERR(ve))
			return PTR_ERR(ve);

		rc = lve_resources_setup(ve, lim);
		light_ve_put(ve);
	}

	return rc;
}

int
_lve_enter(struct task_struct *enter_task, uint32_t ve_id, struct ve_enter *ve_data)
{
	struct switch_data *sw_data;
	struct light_ve *ve;
	long rc;
	int fatal = 0;
	uint64_t nid;

	LVE_ENTER("(pid=%u, ve_id=%u, ve_data={flags=%x, cookie=%p})\n",
		  lve_task_pid(enter_task), ve_id, ve_data->flags,
		  ve_data->cookie);

	nid = lve_node_id(enter_task);
	if (unlikely(nid < 0)) {
		LVE_ERR("unable to determine task (%u:%s) domain\n",
			lve_task_pid(enter_task), enter_task->comm);
		return -ESRCH;
	}

	if (NODEID_LVEID(nid) != ROOT_LVE) {
		if ((ve_data->flags & LVE_ENTER_SILENCE) == 0)
			LVE_WARN("Can't enter lve from a slave context, "
				 "pid %u, oldve %llu\n",
				 lve_task_pid(current), NODEID_LVEID(nid));
		return -EPERM;
	}

	if (ve_id == ROOT_LVE) {
		if ((ve_data->flags & LVE_ENTER_SILENCE) == 0)
			LVE_WARN("lve id must not be equal ROOT_LVE\n");
		return -EINVAL;
	}

	sw_data = switch_tag_attach(enter_task);
	if (sw_data == NULL)
		return -ENOMEM;


	ve = lve_find_or_alloc(ve_id);
	LVE_DBG("lve_find_alloc return %p - %ld\n", ve, PTR_ERR(ve));
	if (IS_ERR(ve)) {
		LVE_ERR("Can't alloc ve #%u, rc %ld\n", ve_id, PTR_ERR(ve));
		rc = PTR_ERR(ve);
		ve = NULL;
		goto out_admin;
	}
	sw_data->sw_from = ve;

	if (ve->lve_disable) {
		rc = -EPERM;
		goto out_admin;
	}

	if (ve_data->cookie) {
		get_random_bytes(&sw_data->sw_cookie, sizeof(sw_data->sw_cookie));
		LVE_DBG("generate cookie %x\n", sw_data->sw_cookie);
	}

	spin_lock(&ve->lve_stats.enter_lock);
	if ((ve_data->flags & LVE_ENTER_NO_MAXENTER) == 0) {
		++ve->lve_stats.st_enters;
		if ((ve->lve_limits[LIM_ENTER] != 0) &&
		    (ve->lve_limits[LIM_ENTER] < ve->lve_stats.st_enters)) {
		    ve->lve_stats.st_err_enters ++;
		    spin_unlock(&ve->lve_stats.enter_lock);
		    rc = -E2BIG;
		    goto out_admin;
		}
	}
	spin_unlock(&ve->lve_stats.enter_lock);

	if (ve_data->cookie && copy_to_user(ve_data->cookie, &sw_data->sw_cookie,
			 sizeof(sw_data->sw_cookie))) {
		LVE_ERR("can't copy cookie into application\n");
		rc = -EFAULT;
		goto out_admin;
	}

	sw_data->sw_flags = ve_data->flags;
	rc = lve_resource_push(enter_task, ve, sw_data->sw_flags);
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
		return 0;
	}

out_admin:
	lve_exit_task(enter_task, sw_data);
	/* some fatal error need to kill*/
	if (fatal)
		force_sig(SIGKILL, enter_task);

	return rc;
}

static int
__lve_leave(struct task_struct *leave_task, uint32_t ve_cookie)
{
	int rc = 0;
	struct switch_data *sw_data;
	struct lvp_ve_private *lvp;

	LVE_ENTER("(pid=%u, ve_cookie=%u)\n", lve_task_pid(leave_task),
		  ve_cookie);

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

	rc = lve_resource_push(leave_task, lvp->lvp_default, sw_data->sw_flags);
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

	return __lve_leave(current, ve_cookie);
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
lve_enter_06(uint32_t ve_id, void __user *data)
{
	struct ve_enter    ve_data;

	if (copy_from_user(&ve_data, data, sizeof(ve_data))) {
		printk(KERN_ERR "Can't read control data from application\n");
		return -EFAULT;
	}

	return _lve_enter(current, ve_id, &ve_data);
}

static int
lve_enter_fs_06(void __user *data)
{
	struct switch_data *sw_data = NULL;
	struct ve_enter_fs_06 ve_efs;
	struct light_ve *ve;
	int rc;

	if (copy_from_user(&ve_efs, data, sizeof(ve_efs))) {
		LVE_DBG("Can't read control data from application\n");
		return -EFAULT;
	}

	LVE_ENTER("(admin=%d)\n", ve_efs.admin);

	sw_data = LVE_TAG_GET(current);
	if (sw_data != NULL) {
		ve = sw_data->sw_from;
	} else {
		ve = lve_find(NODEID_LVEID(lve_node_id(current)));
		if (ve == NULL) {
			rc = -EINVAL;
			goto out_no_lve;
		}
	}

	if (ve_efs.admin)
		rc = lve_namespace_enter_admin(ve);
	else
		rc = lve_namespace_enter(current, ve);

	if (sw_data) {
		if (rc == 0)
			sw_data->sw_flags |= LVE_ENTER_NAMESPACE;
	} else {
		light_ve_put(ve);
	}

	if (sw_data != NULL)
		LVE_TAG_PUT(sw_data);
out_no_lve:
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

	return _lve_setup(ve_id, cfg.ulimits, false);
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

	return lve_enter_06(ve_id, l_data.enter);
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

	return _lve_setup(ROOT_LVE, limits, false);
}

static int
lve_get_info_06(uint32_t ve_id, void __user *data)
{
	int rc = -ESRCH;
	struct ve_config cfg;
	struct light_ve *ve = NULL;
	lve_limits_t *limits;
	struct lvp_ve_private *lvp;

	/* XXX i don't think this need admin rights */

	if (ve_id == ROOT_LVE) {
		lvp = TASK_VE_PRIVATE(current);
		limits = &lvp->lvp_default->lve_limits;
	} else {
		ve = lve_find(ve_id);
		if (ve == NULL)
			return rc;
		limits = &ve->lve_limits;
	}

	/** XXX limits lock */
	memcpy(cfg.ulimits, limits, sizeof(cfg.ulimits));

	rc = copy_to_user(data, &cfg, sizeof(cfg));
	if (rc)
		rc = -EFAULT;

	if (ve)
		light_ve_put(ve);

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

	return _lve_setup(ve_id, cfg.ulimits, false);
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

	return lve_enter_06(ve_id, l_data.enter);
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
lve_get_info_11(uint32_t ve_id, void __user *data)
{
	int rc = -ESRCH;
	struct lve_info_11 cfg;
	struct light_ve *ve = NULL;
	lve_limits_t *limits;
	struct lvp_ve_private *lvp;

	/* XXX i don't think this need admin rights */
	if (ve_id == ROOT_LVE) {
		lvp = TASK_VE_PRIVATE(current);
		limits = &lvp->lvp_default->lve_limits;
	} else {
		ve = lve_find(ve_id);
		if (ve == NULL)
			return rc;
		limits = &ve->lve_limits;
	}

	/** XXX limits lock */
	memcpy(cfg.li_limits, limits, sizeof(cfg.li_limits));
	cfg.li_limits[LIM_CPU] = CPU_LIM_KERNEL_TO_LOWRES(cfg.li_limits[LIM_CPU]);
	cfg.li_flags = lve_to_flags_11(ve);

	rc = copy_to_user(data, &cfg, sizeof(cfg));
	if (rc)
		rc = -EFAULT;

	if (ve)
		light_ve_put(ve);

	return rc;
}

static int
lve_setup_flags_11(uint32_t ve_id, void __user *data)
{
	struct light_ve *ve;
	enum lve_kflags fl;

	if (copy_from_user(&fl, data, sizeof(fl))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	ve = lve_find(ve_id);
	if (ve == NULL)
		return -ESRCH;

	flags_to_lve_11(ve, fl);

	light_ve_put(ve);
	return 0;
}


static int 
lve_enter_pid_11(uint32_t ve_id, void __user *data)
{
	int rc = 0;
	struct ve_enter_pid ve_data;
	struct ve_enter    _ve_data;
	struct task_struct *task;

	return -ENOTSUPP;

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
		rc = _lve_enter(task, ve_id, &_ve_data);
		lve_task_put(task);
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

	return -ENOTSUPP;

	if (!capable(CAP_LVE_ADMIN))
		return -EPERM;

	if (copy_from_user(&ve_data, data, sizeof(ve_data))) {
		LVE_ERR("Can't read control data from application\n");
		goto exit;
	}

	task = lve_find_task(ve_data.pid);
	if (task) {
		rc = __lve_leave(task, 0);
		lve_task_put(task);
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

long lve_fs_root(uint32_t ve_id, const char __user *root)
{
	struct light_ve *ve;
	long rc;

	ve = lve_find(ve_id);
	if (ve == NULL)
		return -ESRCH;

	rc = lve_namespace_set_root(ve, root);
	light_ve_put(ve);

	return rc;
}

static int
lve_get_info_13(uint32_t ve_id, void __user *data)
{
	int rc = -ESRCH;
	struct lve_info_13 cfg;
	struct light_ve *ve = NULL;
	lve_limits_13_t *limits;
	struct lvp_ve_private *lvp;

	/* XXX i don't think this need admin rights */
	if (ve_id == ROOT_LVE) {
		lvp = TASK_VE_PRIVATE(current);
		limits = &lvp->lvp_default->lve_limits;
	} else {
		ve = lve_find(ve_id);
		if (ve == NULL)
			return rc;
		limits = &ve->lve_limits;
	}

	/** XXX limits lock */
	memcpy(cfg.li_limits, limits, sizeof(cfg.li_limits));
	cfg.li_flags = lve_to_flags_11(ve);

	rc = copy_to_user(data, &cfg, sizeof(cfg));
	if (rc)
		rc = -EFAULT;

	if (ve)
		light_ve_put(ve);

	return rc;
}

/* 1.3 */
static int
lve_setup_13(uint32_t ve_id, void __user *data)
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

	return _lve_setup(ve_id, cfg.ulimits, true);
}

static int
lve_setup_enter_13(uint32_t ve_id, void __user *data)
{
	int rc;
	struct lve_setup_enter_13 l_data;

	if (copy_from_user(&l_data, data, sizeof(l_data))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	rc = lve_setup_13(ve_id, l_data.setup);
	if (rc)
		return rc;

	return lve_enter_06(ve_id, l_data.enter);
}

static int
lve_setup_flags_13(uint32_t ve_id, void __user *data)
{
	struct light_ve *ve;
	enum lve_kflags fl;

	if (copy_from_user(&fl, data, sizeof(fl))) {
		LVE_ERR("can't read params\n");
		return -EFAULT;
	}

	ve = lve_find(ve_id);
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

	rc = copy_to_user(data, &sw_data->sw_failmask, sizeof(sw_data->sw_failmask));
	if (rc)
		goto out;

	sw_data->sw_failmask = 0;

out:
	LVE_TAG_PUT(sw_data);
	return rc;
}

long lve_ns_assign(uint32_t ve_id)
{
	struct light_ve *ve;
	long rc;

	LVE_ENTER("(ve_id=%u)\n", ve_id);

	if (lve_no_namespaces)
		return -ENOSYS;

	ve = lve_find(ve_id);
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
	lve_task_put(tsk);
	return rc;
}

/*
 * op is
 *
 */
asmlinkage long sys_light_ve(uint32_t ve, ve_op op, void __user *data)
{
	long rc = 0;

	LVE_DBG("got cmd %u - ID %u - data %p\n", _IOC_NR(op), ve, data);
	if (TASK_VE_PRIVATE(current) == NULL) {
		LVE_WARN("LVE disabled for contatainer\n");
		return -ENOSYS;
	}

	switch (op) {
	case DEFAULT_PARAMS_08:
	case DEFAULT_PARAMS_COMPAT:
		/* obsolete */
		rc = lve_set_default_06(data);
		break;
	case ENTER_VE:
	case ENTER_VE_COMPAT:
		rc = lve_enter_06(ve, data);
		break;
	case LEAVE_VE:
	case LEAVE_VE_COMPAT:
		rc = lve_leave(data);
		break;
	case CREATE_VE:
	case CREATE_VE_COMPAT:
		rc = lve_create(ve);
		break;
	case DESTROY_VE:
	case DESTROY_VE_COMPAT:
		rc = lve_destroy(ve);
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
		rc = lve_get_info_06(ve, data);
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
		rc = lve_setup_flags_11(ve, data);
		break;
	case SETUP_ENTER_VE_11:
		rc = lve_setup_enter_11(ve, data);
		break;
	case INFO_VE_11:
		rc = lve_get_info_11(ve, data);
		break;
	case IS_IN_LVE:
		rc = is_in_lve(current);
		break;
	case ENTER_VE_PID:
		rc = lve_enter_pid_11(ve, data);
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
		rc = lve_fs_root(ve, data);
		break;
	case SETUP_VE_13:
		rc = lve_setup_13(ve, data);
		break;
	case SETUP_VE_FLAGS_13:
		rc = lve_setup_flags_13(ve, data);
		break;
	case SETUP_ENTER_VE_13:
		rc = lve_setup_enter_13(ve, data);
		break;
	case INFO_VE_13:
		rc = lve_get_info_13(ve, data);
		break;
	case CHECK_FAULT_13:
		rc = lve_check_fault_13(data);
		break;
	case ASSIGN_FS_ROOT_13:
		rc = lve_ns_assign(ve);
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

	lve_params_init();

	ret = lve_res_init();
	if (ret == 0)
		return 0;

	lve_list_fini();
list_error:
	switch_fini();

	return ret;
}

int lve_fini()
{
	lve_res_fini();
	lve_list_fini();
	switch_fini();

	return 0;
}
