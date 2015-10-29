#ifndef _LVE_GLOBAL_PARAMS_H_
#define _LVE_GLOBAL_PARAMS_H_

#define BITMASK_SZ     (sizeof(uint64_t) * 3)
#define PARAM_SZ       (BITMASK_SZ * BITS_PER_BYTE)

enum lve_params {
	LVE_GRACE_PERIOD = 125,
	LVE_PARAM_MAX = PARAM_SZ /*192*/,
};

typedef int (*param_cb)(uint64_t val);

int lve_update_grace_period(uint64_t val);

void lve_params_init(void);
int lve_get_param(enum lve_params lve_param, uint64_t *val);
int lve_set_param(enum lve_params, uint64_t val);
int lve_set_param_callback(enum lve_params, param_cb cb);
void lve_set_param_callbacks(void);

#endif
