#ifndef _LVE_CGROUP_OPENVZ_IMPORTS_

#define _LVE_CGROUP_OPENVZ_IMPORTS_

/* CL API */
#ifdef UBC_CL_API
long lve_setublimit(struct user_beancounter *ub, unsigned long resource,
		unsigned long *new_limits);
#else
long lve_setublimit(uid_t ub, unsigned long resource,
		unsigned long *new_limits);
#endif

#define LVE_MEM_LIMIT_RES UB_PRIVVMPAGES
#define LVE_MEM_PHY_LIMIT_RES UB_PHYSPAGES
#define LVE_NPROC_LIMIT_RES UB_NUMPROC

#endif
