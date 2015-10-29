#ifndef _LVE_COMPAT_H_
#define _LVE_COMPAT_H_

/* up to 1.0 */
typedef int32_t lve_limits_10_t[LIM_MEMORY_PHY];
typedef int32_t lve_limits_11_t[LIM_IOPS];

struct ve_config_10 {
	lve_limits_10_t	ulimits;
};

struct ve_config_11 {
	lve_limits_11_t	ulimits;
};

struct lve_info_11 {
	lve_limits_11_t	li_limits;
	enum lve_kflags	li_flags;
};


#ifdef __KERNEL__

#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/compat.h>

#ifdef CONFIG_COMPAT
struct ve_enter_compat {
	compat_uptr_t	cookie_p; /* pointer to enter cookie, 32 bit */
	uint32_t	flags;
};

struct ve_leave_compat {
	compat_uptr_t	cookie_p; /* a 32-bit pointer to the cookie */
};

struct ve_ioctl_compat {
	uint32_t	id;
	uint32_t	cookie[4];
	compat_uptr_t	data;
};

struct lve_setup_enter_10_compat {
	compat_uptr_t	setup; /* a 32-bit pointer */
	compat_uptr_t	enter; /* a 32-bit pointer */
};
#endif
#endif
#endif
