#ifndef _LIGHT_VE_H_
#define _LIGHT_VE_H_

#include "lve-api.h"

asmlinkage long sys_light_ve(uint32_t ve, ve_op op, void *data);

int __init lve_init(void);
int lve_fini(void);

int __init lve_stats_init(void);
void lve_stats_fini(void);

/* lve_resource.c */
int __init lve_res_init(void);
void lve_res_fini(void);

/* lve_lvp.c */
int __init lve_lvp_init(void);
void lve_lvp_fini(void);

/* lve_exec.c */
struct lvp_ve_private;
int __init lvp_exec_init(struct lvp_ve_private *lvp);
void lvp_exec_fini(struct lvp_ve_private *lvp);

int __init lve_exec_init(void);
void lve_exec_fini(void);

/* lve_map.c */
int __init lve_lvp_map_init(void);
void lve_lvp_map_fini(void);

#endif
