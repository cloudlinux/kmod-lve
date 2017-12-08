#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "lve_kmod_c.h"
#include "lve_callchain.h"

/* move OpenVZ callchain here, to easy replace with kcare helpers */
#include <linux/virtinfo.h>

struct lve_call {
	unsigned long		lc_sys_event;
	struct vnotifier_block	lc_sys_cb;
	lve_callback		lc_lve_cb;
};

static int lve_callchain_cb(struct vnotifier_block *self,
			    unsigned long event, void *arg, int old_ret)
{
	struct lve_call *call;
	int ret;

	call = list_entry(self, struct lve_call, lc_sys_cb);
	if (call->lc_sys_event != event)
		return old_ret;

	ret = call->lc_lve_cb(arg);

	return (ret == 0) ? NOTIFY_OK : NOTIFY_FAIL;
}

static long lve_call_to_sys_event(enum lve_event event)
{
	switch(event) {
#ifdef HAVE_EXEC_NOTIFIER
	case LVE_EXEC:
		return VIRTINFO_EXEC;
#endif
#ifdef HAVE_LVE_PORT_CONTROL
	case LVE_BIND:
		return VIRTINFO_SOCKADDR;
#endif
#ifdef HAVE_LVE_TRAF_CONTROL
	case LVE_TRAF_MARK_OUT:
		return VIRTINFO_TRAF_OUT_MARK;
	case LVE_TRAF_ACCOUNT_IN:
		return VIRTINFO_TRAF_IN_ACCOUNT;
	case LVE_TRAF_ACCOUNT_OUT:
		return VIRTINFO_TRAF_OUT_ACCOUNT;
#endif
	default:
		return -ENOSYS;
	}

	return 0;
}

struct lve_call *lve_callchain_register(enum lve_event event, lve_callback cb)
{
	struct lve_call *ret;
	long sys_event;

	sys_event = lve_call_to_sys_event(event);
	if (sys_event < 0)
		return ERR_PTR(sys_event);

	ret = kmalloc(sizeof(*ret), GFP_KERNEL);
	if (ret == NULL)
		return ERR_PTR(-ENOMEM);

	ret->lc_sys_event = sys_event;
	ret->lc_sys_cb.notifier_call = lve_callchain_cb;
	ret->lc_lve_cb = cb;

	virtinfo_notifier_register(VITYPE_GENERAL, &ret->lc_sys_cb);

	return ret;
}

void lve_callchain_unregister(struct lve_call *call)
{
	if (call == NULL)
		return;

	virtinfo_notifier_unregister(VITYPE_GENERAL, &call->lc_sys_cb);

	kfree(call);
}
