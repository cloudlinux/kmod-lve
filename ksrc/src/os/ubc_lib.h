#ifndef _UBC_LIB_H_
#define _UBC_LIB_H_

#define LVE_MEM_LIMIT_RES UB_PRIVVMPAGES
#define LVE_MEM_PHY_LIMIT_RES UB_PHYSPAGES
#define LVE_NPROC_LIMIT_RES UB_NUMPROC

struct user_beancounter;
struct one_resource;

void ubc_mem_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge);

void ubc_phys_mem_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge);

void ubc_nproc_stat(struct user_beancounter *ub, struct one_resource *res,
		int *precharge);

int init_beancounter_swap_limits(struct user_beancounter *ub);

void init_beancounter_nolimits(struct user_beancounter *ub);

int ubc_set_res(struct user_beancounter *ub, int res, uint32_t new);

#ifndef HAVE_UB_SHORTAGE_CB
static inline 
void ub_set_shortage_cb(struct user_beancounter *ub,
			void (*cb)(struct user_beancounter *, int)) {
}
#endif
void ubc_shortage(struct user_beancounter * ubc, int resource);
#endif
