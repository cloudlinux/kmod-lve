#ifndef _LVE_CALLCHAIN_H_
#define _LVE_CALLCHAIN_H_

enum lve_event {
	LVE_EXEC,
	LVE_BIND,
	LVE_TRAF_MARK_OUT,
	LVE_TRAF_ACCOUNT_IN,
	LVE_TRAF_ACCOUNT_OUT,
};

typedef int (*lve_callback)(void *arg);

struct lve_call *lve_callchain_register(enum lve_event event, lve_callback cb);
void lve_callchain_unregister(struct lve_call *call);

#endif
