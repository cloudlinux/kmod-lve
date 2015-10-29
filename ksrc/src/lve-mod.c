#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "lve-api.h"
#include "lve_debug.h"
#include "light_ve.h"
#include "lve_os_compat.h"
#include "lve_internal.h"
#include "resource.h"
#include "lve_hooks.h"

#if RHEL_MAJOR > 6
#include <linux/memcontrol.h>

static struct static_key *key = &memcg_kmem_enabled_key;

static inline void lve_static_key_slow_inc(void)
{
	atomic_inc(&key->enabled);
}

static inline void lve_static_key_slow_dec(void)
{
	atomic_dec(&key->enabled);
}
#else
static inline void lve_static_key_slow_inc(void)
{
}

static inline void lve_static_key_slow_dec(void)
{
}
#endif

unsigned long fail_value = 0;
#ifndef LVE_DEBUG
atomic_t lve_debug_mask = ATOMIC_INIT((1 << LVE_DEBUG_FAC_WARN) | \
						(1 << LVE_DEBUG_FAC_ERR));
#else
atomic_t lve_debug_mask = ATOMIC_INIT(-1);
#endif
bool lve_bc_after_enter = false;
bool lve_unint_hack = true;
bool lve_user_setup = false;
bool lve_no_namespaces = false;

static long lve_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ve_ioctl vectl;
	int rc = 0;

	LVE_DBG("ioctl cmd %x - %p\n", cmd, (void *)arg);

	rc = copy_from_user(&vectl, (void *)arg, sizeof(struct ve_ioctl));
	if (rc) {
		LVE_ERR("can't read ioctl data from userland\n");
		return -EFAULT;
	}

	rc = sys_light_ve(vectl.id, cmd, vectl.data);

	return rc;
}

#ifdef CONFIG_COMPAT

#include <linux/compat.h>

void *lve_marshall_ve_enter(unsigned long arg)
{
	struct ve_enter *ve;
	struct ve_enter_compat ve_32;

	if (copy_from_user(&ve_32, (void *)arg, sizeof(ve_32)))
		return ERR_PTR(-EFAULT);

	ve = lve_compat_alloc_user_space(sizeof(*ve));
	if (!ve)
		return ERR_PTR(-ENOMEM);

	if (put_user(compat_ptr(ve_32.cookie_p), &ve->cookie) ||
	    put_user(ve_32.flags, &ve->flags))
		return ERR_PTR(-EFAULT);

	return ve;
}

void *lve_marshall_ve_leave(unsigned long arg)
{
	struct ve_leave *ve;
	struct ve_leave_compat ve_32;

	if (copy_from_user(&ve_32, (void *)arg, sizeof(ve_32)))
		return ERR_PTR(-EFAULT);

	ve = lve_compat_alloc_user_space(sizeof(*ve));
	if (!ve)
		return ERR_PTR(-ENOMEM);

	if (put_user(compat_ptr(ve_32.cookie_p), &ve->cookie))
		return ERR_PTR(-EFAULT);

	return ve;
}

void *lve_marshall_ve_setup_enter(unsigned long arg)
{
	struct lve_setup_enter_10 *ve;
	struct lve_setup_enter_10_compat ve_32;
	void *enter;

	if (copy_from_user(&ve_32, (void *)arg, sizeof(ve_32)))
		return ERR_PTR(-EFAULT);

	ve = lve_compat_alloc_user_space(sizeof(*ve));
	if (!ve)
		return ERR_PTR(-ENOMEM);

	enter = lve_marshall_ve_enter(ve_32.enter);
	if (IS_ERR(enter))
		return enter;

	if (put_user(enter, &ve->enter) ||
	    put_user(compat_ptr(ve_32.setup), &ve->setup))
		return ERR_PTR(-EFAULT);

	return ve;
}

static long lve_compat_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct ve_ioctl_compat vectl;
	unsigned long narg;
	void *data = NULL;

	LVE_DBG("compat ioctl cmd %x - %p\n", cmd, (void *)arg);

	if (copy_from_user(&vectl, (void *)arg, sizeof(vectl))) {
		LVE_ERR("can't read ioctl data from userland\n");
		return -EFAULT;
	}

	switch (cmd) {
	case DEFAULT_PARAMS_08:
	case DEFAULT_PARAMS_COMPAT:
		/* no-op */
	case CREATE_VE:
	case CREATE_VE_COMPAT:
		/* no-op */
	case DESTROY_VE:
	case DESTROY_VE_COMPAT:
		/* no-op */
	case API_VER:
	case API_VER_COMPAT:
		/* no-op */
	case START_VE:
	case SET_FAIL_VAL:
	case IS_IN_LVE:
	case SETUP_VE_08:
	case SETUP_VE_COMPAT:
	case FLUSH_VE:
	case FLUSH_VE_COMPAT:
	case INFO_VE_08:
	case INFO_VE_COMPAT:
	case ENTER_FS:
	case ENTER_FS_COMPAT:
	case SETUP_VE_11:
	case SETUP_VE_13:
	case SETUP_VE_FLAGS_11:
	case SETUP_VE_FLAGS_13:
	case INFO_VE_11:
	case INFO_VE_13:
	case ENTER_VE_PID:
	case LEAVE_VE_PID:
	case ASSIGN_FS_ROOT_13:
	case SET_GLOBAL_PARAM_VAL_14:
	case GET_GLOBAL_PARAM_VAL_14:
	case LVE_GET_PID_INFO_14:
		break;
	case ENTER_VE:
	case ENTER_VE_COMPAT:
		data = lve_marshall_ve_enter(vectl.data);
		break;
	case LEAVE_VE:
	case LEAVE_VE_COMPAT:
		data = lve_marshall_ve_leave(vectl.data);
		break;
	case SETUP_ENTER_VE_08:
	case SETUP_ENTER_VE_COMPAT:
	case SETUP_ENTER_VE_11:
	case SETUP_ENTER_VE_13:
		data = lve_marshall_ve_setup_enter(vectl.data);
		break;
	case CHECK_FAULT_13:
		data = compat_ptr(vectl.data);
		break;
	default:
		LVE_ERR("unknown LVE cmd %u\n", cmd);
		return -ENOSYS;
	}

	if (data != NULL) {
		if (IS_ERR(data)) {
			LVE_ERR("marshalling failure for cmd %x\n", cmd);
			return PTR_ERR(data);
		} else {
			narg = (unsigned long)data;
		}
	} else {
		narg = vectl.data;
	}

	return sys_light_ve(vectl.id, cmd, (void *)narg);
}
#endif

static struct file_operations fops = {
	.owner	= THIS_MODULE,
	.unlocked_ioctl	= lve_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = lve_compat_ioctl
#endif
};

static struct miscdevice lve_dev = {
	MISC_DYNAMIC_MINOR,
	LVE_DEV_NAME,
	&fops
};

int lve_start()
{
	return lve_namespace_set_default();
}

static int __init
lve_mod_init(void)
{
	int ret = 0;

	lve_static_key_slow_inc();

	ret = lve_init();
	if (ret)
		goto out_res;

	ret = lve_stats_init();
	if (ret != 0)
		goto out_namespace;

	ret = lve_hooks_init();
	if (ret != 0)
		goto out_stats;

#ifdef HAVE_EXEC_NOTIFIER
	lve_exec_init();
#endif
	ret = lve_call(misc_register(&lve_dev),	LVE_FAIL_MISC_REG, -ENOMEM);
	printk(KERN_INFO "lve driver register status %d\n", ret);
	if (ret)
		goto out_exec;
	return 0;

out_exec:
#ifdef HAVE_EXEC_NOTIFIER
	lve_exec_fini();
#endif
	lve_hooks_fini();
out_stats:
	lve_stats_fini();
out_namespace:
	lve_fini();
out_res:
	lve_static_key_slow_dec();
	return ret;
}

static void __exit
lve_mod_cleanup(void)
{
	misc_deregister(&lve_dev);
	lve_hooks_fini();
#ifdef HAVE_EXEC_NOTIFIER
	lve_exec_fini();
#endif
	lve_stats_fini();
	lve_fini();
	lve_static_key_slow_dec();
}

module_init(lve_mod_init);
module_exit(lve_mod_cleanup);

module_param(lve_bc_after_enter, bool, 0644);
module_param(lve_unint_hack, bool, 0644);
module_param(lve_user_setup, bool, 0644);
module_param(lve_no_namespaces, bool, 0444);
module_param(fail_value, ulong, 0);

#include "mod_info.h"
