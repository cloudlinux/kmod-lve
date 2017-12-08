#ifndef _LVE_API_H_
#define _LVE_API_H_

#include "linux/ioctl.h"

#ifndef __user
#define __user
#endif

#define ROOT_LVE	(0)
#define SELF_LVE	((uint32_t)~0)
#define ROOT_LVP	(0)

enum lve_limits {
	LIM_CPU = 0,
	LIM_IO,
	LIM_ENTER,
	LIM_CPUS,
	LIM_MEMORY,
	LIM_MEMORY_PHY,
	LIM_CPU_WEIGHT,
	LIM_NPROC,
	LIM_IOPS,
	LVE_LIMITS_MAX
};

typedef int32_t lve_limits_13_t[LVE_LIMITS_MAX];

enum lve_enter_flags {
	LVE_ENTER_NAMESPACE	= 1 << 0, /* use jail to enter */
	LVE_ENTER_NO_UBC	= 1 << 1, /* don't attach ubc */
	LVE_ENTER_NO_MAXENTER	= 1 << 2, /* don't check enter limit */
	LVE_ENTER_SILENCE	= 1 << 3, /* don't print some messages */
	LVE_ENTER_NO_KILLABLE	= 1 << 4, /* don't kill process while destroying lve */
};

struct ve_enter {
	uint32_t __user	*cookie; /* pointer to enter cookie */
	uint32_t	 flags;
};

struct ve_enter_fs_06 {
	int	admin;
};

struct ve_leave {
	uint32_t __user	*cookie; /* */
};

struct lve_flush {
	uint32_t	all;	/* flush all context's or only default cloned */
};

enum lve_kflags {
	LVE_KFL_DISABLED	= 1 << 0, /* containter disabled, don't allow to enter */
};

struct ve_config_13 {
	lve_limits_13_t	ulimits;
};

struct lve_setup_enter_10 {
	struct ve_config_11 __user	*setup;
	struct ve_enter	__user		*enter;
};

struct lve_setup_enter_13 {
	struct ve_config_13 __user	*setup;
	struct ve_enter	__user		*enter;
};

struct lve_info_13 {
	lve_limits_13_t	li_limits;
	enum lve_kflags	li_flags;
};

struct lve_flags {
	enum lve_kflags	lf_set;
};

#define lve_limits_t lve_limits_13_t
#define ve_config ve_config_13

struct ve_enter_pid {
	uint32_t	 pid;
	uint32_t	 flags;
};

struct ve_leave_pid {
	uint32_t 	 pid;
};

struct lve_fail_val {
	uint32_t	val;
};

struct lve_global_params_14 {
	uint64_t	index;
	uint64_t	val;
};

struct lve_pid_info_14 {
	uint64_t	pid;
	uint32_t	id;
	uint32_t	flags;
	int32_t		leader;
};

enum lve_net_port_op {
	LVE_NETPORT_DEFAULT,
	LVE_NETPORT_ADD,
	LVE_NETPORT_DEL,
	LVE_NETPORT_INFO, /* not implement */
};

struct lve_net_port_14 {
	uint16_t op; /* lve_net_port op enum */
	uint16_t port; /* port to change */
	uint16_t policy; /* == 0 deny, == 1 allow */
};

struct lve_net_limits_14 {
	uint64_t in_lim;
	uint64_t out_lim;
};

enum lve_freezer_op {
	LVE_FREEZER_FREEZE,
	LVE_FREEZER_THAW,
};

struct lve_freezer_control {
	uint16_t op;
};

enum lve_resource_fails {
	LVE_RESOURCE_FAIL_MEM	= 1 << 0,   /**< memory limit reached */
	LVE_RESOURCE_FAIL_MEM_PHY = 1 << 1,  /**< physical memory limit reached */
	LVE_RESOURCE_FAIL_NPROC	= 1 << 2,   /**< number of processes limit reached */
};

enum lve_map_op {
	LVE_MAP_ADD,
	LVE_MAP_MOVE,
};

struct lve_map_data {
	uint32_t	lmd_lvp_id;
	enum lve_map_op	lmd_op;
};

enum lvp_limits_op {
	LVP_LIMIT_SELF,
	LVP_LIMIT_DEFAULT,
};

struct lvp_limits_data {
	enum lvp_limits_op	lld_op;
	lve_limits_13_t		lld_ulimits;
};

struct lvp_info {
	enum lvp_limits_op li_op;
	struct lve_info_13 li_info;
};

/**
 last two digits is API version
 */
typedef enum {
	/* 0.7 API */
	LEAVE_VE_COMPAT = 2,
	CREATE_VE_COMPAT = 3,
	DESTROY_VE_COMPAT = 4,
	FLUSH_VE_COMPAT = 6,
	API_VER_COMPAT = 7, /* return api version to the caller */
	DEFAULT_PARAMS_COMPAT = 13,
	SETUP_VE_COMPAT = 14,
	ENTER_VE_COMPAT = 15,
	SETUP_ENTER_VE_COMPAT = 16,
	INFO_VE_COMPAT = 17,
	ENTER_FS_COMPAT = 18,
	LVE_FREEZER_CONTROL_COMPAT = 19,
	/* NEW 0.8 api numbers */
	DEFAULT_PARAMS_08 = _IOW('L', 0, lve_limits_t),
	ENTER_VE	= _IO('L', 1),
	LEAVE_VE	= _IO('L', 2),
	CREATE_VE	= _IO('L', 3),
	DESTROY_VE	= _IO('L', 4),
	SETUP_VE_08	= _IO('L', 5),
	FLUSH_VE	= _IO('L', 6),
	API_VER		= _IO('L', 7), /* return api version to the caller */
	INFO_VE_08	= _IO('L', 8), /* return info about LVE context */
	SETUP_ENTER_VE_08 = _IO('L', 9),
	ENTER_FS	= _IO('L', 14),
	/* new in 1.1 */
	SETUP_VE_11	= _IO('L', 10), /* will also used to set defaults */
	SETUP_VE_FLAGS_11	= _IO('L', 11), /* set additional flags */
	INFO_VE_11	= _IO('L', 12), /* return info about LVE context */
	SETUP_ENTER_VE_11	= _IO('L', 13),
	ENTER_VE_PID	= _IO('L', 15),
	LEAVE_VE_PID	= _IO('L', 16),
	IS_IN_LVE	= _IO('L', 19),
	START_VE	= _IO('L', 20),
	SET_FAIL_VAL = _IO('L', 21),
	/* new in 1.2 */
	SETUP_FS_ROOT	= _IO('L', 22),
	/* new in 1.3 */
	INFO_VE_13	= _IO('L', 23), /* return info about LVE context */
	SETUP_VE_13	= _IO('L', 24), /* will also used to set defaults */
	SETUP_VE_FLAGS_13 = _IO('L', 25), /* set additional flags */
	SETUP_ENTER_VE_13 = _IO('L', 26),
	CHECK_FAULT_13	= _IO('L', 27),
	ASSIGN_FS_ROOT_13 = _IO('L', 28),
	/* new in 1.4 */
	SET_GLOBAL_PARAM_VAL_14 = _IO('L', 29), /* set module global parameter value */
	GET_GLOBAL_PARAM_VAL_14 = _IO('L', 30), /* get module global parameter value */
	LVE_GET_PID_INFO_14 = _IO('L', 31), /* get lve id/flags of the task */
	LVE_NET_PORT_14	= _IO('L', 32), /* set uid/port value */
	LVE_SET_NET_LIMITS_14 = _IO('L', 33), /* set network limits */
	LVE_FREEZER_CONTROL = _IO('L', 34), /* freezer control for a given LVE */
	/* ===================================== */
	/* reseller API must used after it point */
	/* ===================================== */
	LVE_LVP_API_MARK = _IO('L', 200),
	/* new in 1.5 */	
	LVE_LVP_CREATE_15 = _IO('L', 200), /* create reseller container */
	LVE_LVP_DESTROY_15 = _IO('L', 201), /* destroy reseller container */
	LVE_LVP_SETUP_15 = _IO('L', 202), /* setup reseller container limits */
	LVE_LVP_MAP_15 = _IO('L', 203), /* map an LVE ID into reseller */
	LVE_LVP_INFO_15 = _IO('L', 204), /* lvp info */
} ve_op;

struct ve_ioctl {
	uint32_t	id;
	uint32_t	cookie[4];
	void __user	*data;
};

#define LVE_KMOD_API_MAJOR	1
#define LVE_KMOD_API_MINOR	5

#define LVE_API_VERSION(a, b) (((a) << 16) + (b))

#define LVE_DEV_NAME	"lve"

#include "lve-compat.h"

#endif
