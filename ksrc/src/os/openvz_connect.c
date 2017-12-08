#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ve_proto.h>

#include "lve_kmod_c.h"
#include "light_ve.h"
#include "lve_internal.h"
#include "lve_debug.h"
#include "resource.h"
#include "openvz_cgroups.h"

#ifdef LVE_PER_VE
static int lve_ve_init(void *data)
{
        struct lvp_ve_private *lvp;
	struct ve_struct *env = data;

        lvp = lvp_alloc(VEID(env), env);
        if (!lvp) {
                LVE_ERR("Can't allocate lvp\n");
                return -ENOMEM;
        }

        return 0;
}

static void lve_ve_fini(void *data)
{
	struct lvp_ve_private *lvp;
	struct ve_struct *env = data;

	lvp = (struct lvp_ve_private *)env->lve;
	if (lvp) {
		lvp_fini(lvp);
		smp_mb();
		env->lve = NULL;
	} else {
		LVE_ERR("Can't find lvp id=%d\n", VEID(env));
	}

	return;
}

#ifdef HAVE_VE_CLEANUP_CHAIN
/* lve_ve_fini is called whein ve is destroyed */
static struct ve_hook ve_exit_chain = {
	.fini 	=	lve_ve_fini,
	.owner	=	THIS_MODULE,
};
#endif

/* lve_ve_init is called when ve is created */
static struct ve_hook ve_init_chain = {
	.init	=	lve_ve_init,
#ifndef HAVE_VE_CLEANUP_CHAIN
	.fini	= 	lve_ve_fini,
#endif
	.owner	=	THIS_MODULE,
};

void init_ve_init_exit_chain(void)
{
#ifdef HAVE_VE_CLEANUP_CHAIN
	/* fini chain */
	ve_hook_register(VE_CLEANUP_CHAIN, &ve_exit_chain);
#endif
	/* init chain */
	ve_hook_register(VE_SS_CHAIN, &ve_init_chain);
}

void cleanup_ve_init_exit_chain(void)
{
	ve_hook_unregister(&ve_init_chain);
#ifdef HAVE_VE_CLEANUP_CHAIN
	ve_hook_unregister(&ve_exit_chain);
#endif
}
#endif
