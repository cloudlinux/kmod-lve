#ifndef _TAGS_H_

#define _TAGS_H_
#include <linux/version.h>
#define SWITCH_MAGIC	0x53575645

struct switch_data {
	uint32_t		sw_magic;
	struct module		*sw_owner;
	uint32_t		sw_cookie; /* cookie used for enter */
	struct light_ve		*sw_from;
	uint32_t		sw_flags;
	uint32_t		sw_failmask;
	struct task_struct	*sw_task;
	atomic_t		sw_refcnt;
	struct lve_namespace	sw_ns;
	struct list_head	sw_list; /* for delayed release */
};

struct task_struct;
struct switch_data * switch_tag_attach(struct task_struct *task);
void switch_free(struct switch_data *sw_data);
void switch_tag_fork(struct task_struct * task);
void switch_tag_account(struct switch_data *sw_data,
			struct light_ve *ve);
void switch_tag_release(const struct switch_data *sw_data);

#if RHEL_MAJOR == 6
/* Use the last element of the array to keep lve tags */
#define LVE_TAG(tsk)	((tsk)->rh_reserved[ARRAY_SIZE((tsk)->rh_reserved)-1])
#else
#if RHEL_MAJOR == 7
#define LVE_TAG(tsk)	((tsk)->rh_reserved8)
#else
#define LVE_TAG(tsk)	((tsk)->tux_info)
#endif
#endif

static inline struct switch_data *LVE_TAG_GET(struct task_struct *tsk) 
{
	struct switch_data *ret;

	task_lock(tsk);

	ret = (void *)LVE_TAG(tsk);

	if (ret == NULL || ret->sw_magic != SWITCH_MAGIC) {
		ret = NULL;
		goto out;
	}

	atomic_inc(&ret->sw_refcnt);
out:
	task_unlock(tsk);

	return ret;
}

static inline void LVE_TAG_SET(struct task_struct *tsk, struct switch_data *data)
{
	task_lock(tsk);
#if RHEL_MAJOR >= 6
	LVE_TAG(tsk) = (long)data;
#else
	LVE_TAG(tsk) = (void *)data;
#endif
	task_unlock(tsk);
}

static inline void LVE_TAG_CLEAR(struct task_struct *tsk)
{
	task_lock(tsk);
#if RHEL_MAJOR >= 6
	LVE_TAG(tsk) = 0UL;
#else
	LVE_TAG(tsk) = NULL;
#endif
	task_unlock(tsk);
}

static inline void LVE_TAG_PUT(struct switch_data *sw_data)
{
	if (atomic_dec_and_test(&sw_data->sw_refcnt))
		switch_free(sw_data);
}
void tag_free_delayed(struct switch_data *sw_data);

static inline void LVE_TAG_PUT_DELAYED(struct switch_data *sw_data)
{
	if (atomic_dec_and_test(&sw_data->sw_refcnt))
		tag_free_delayed(sw_data);
}

int switch_init(void);
void switch_fini(void);

#endif
