#ifndef _OPENVZ_IOLIMITS_H_
#define _OPENVZ_IOLIMITS_H_

int ovz_iolimits_init(void);
int ovz_iolimits_exit(void);

int ovz_io_limits_init(struct user_beancounter *ub);

int ovz_set_io_limit(struct user_beancounter *ub,
		     unsigned speed, unsigned burst);
int ovz_set_iops_limit(struct user_beancounter *ub,
		       unsigned speed, unsigned burst);

unsigned long long ovz_get_io_usage(struct user_beancounter *ub);
unsigned long long ovz_get_iops_usage(struct user_beancounter *ub);

#endif
