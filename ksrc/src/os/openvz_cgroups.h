#ifndef _OPENVZ_CGROUPS_H_
#define _OPENVZ_CGROUPS_H_

#ifdef HAVE_UB_CGROUP
#define blkio_grp(ubc)	((ubc)->ub_cgroup)
#endif

extern void init_ve_init_exit_chain(void);
extern void cleanup_ve_init_exit_chain(void);

#endif
