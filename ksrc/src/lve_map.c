#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>

#include "lve_debug.h"
#include "lve_internal.h"
#include "light_ve.h"


struct map_entry {
	uint32_t lve_id;
	uint32_t lvp_id;
};

struct map {
	struct map_entry *array;
	unsigned int total;
	unsigned int last;
	struct rw_semaphore sem;
	struct proc_dir_entry *entry;
};

static struct map lvp_map = { 0 };

#define MAP_CAPACITY	1024

static inline struct map_entry *map_entry(unsigned int idx)
{
	return &lvp_map.array[idx];
}

static int entry_cmp(const void *_a, const void *_b)
{
	const struct map_entry *a = _a;
	const struct map_entry *b = _b;

	return (a->lve_id - b->lve_id);
}

static int map_realloc(unsigned int new_total)
{
	struct map_entry *tmp, *old;

	tmp = vmalloc(sizeof(struct map_entry) * new_total);
	if (tmp == NULL)
		return -ENOMEM;

	old = lvp_map.array;
	if (old != NULL)
		memcpy(tmp, old, sizeof(struct map_entry) * min(lvp_map.last, new_total));
	lvp_map.array = tmp;

	/* If we shrink the array, *last* must be reset */
	if (lvp_map.total >= new_total)
		lvp_map.last = 0;

	lvp_map.total = new_total;
	vfree(old);

	return 0;
}

static void map_release(void)
{
	vfree(lvp_map.array);
}

static struct map_entry *map_fetch(uint32_t id)
{
	struct map_entry key = { .lve_id = id };

	return bsearch(&key, lvp_map.array, lvp_map.last,
		sizeof(struct map_entry), entry_cmp);
}

static void *map_start(struct seq_file *s, loff_t *pos)
{
	down_read(&lvp_map.sem);

	if (*pos >= lvp_map.last)
		return NULL;

	return (void *)map_entry(*pos);
}

static void *map_next(struct seq_file *s, void *v, loff_t *ppos)
{
	void *ret = NULL;

	if (++*ppos < lvp_map.last)
		ret = (void *)map_entry(*ppos);

	return ret;
}

static void map_stop(struct seq_file *s, void *v)
{
	up_read(&lvp_map.sem);
}

static int map_show(struct seq_file *s, void *v)
{
	struct map_entry *data = v;

	if (v == map_entry(0)) {
		seq_printf(s, "LVE\tLVP\n");
	}
	seq_printf(s, "%08u %08u\n", data->lve_id, data->lvp_id);
	return 0;
}

const struct seq_operations lve_map_op = {
	.start	= map_start,
	.next	= map_next,
	.stop	= map_stop,
	.show	= map_show
};

int lve_lvp_map_add(uint32_t lve_id, uint32_t lvp_id)
{
	struct map_entry *data;
	uint32_t last;
	int ret = 0;
	
	down_write(&lvp_map.sem);
	data = map_fetch(lve_id);
	if (data != NULL) {
		data->lvp_id = lvp_id;
		goto out_unlock;
	}

	last = lvp_map.last;
	if (last == lvp_map.total) {
		ret = map_realloc(last << 1);
		if (ret < 0) {
			ret = -ENOMEM;
			goto out_unlock;
		}
	}

	data = map_entry(last);
	data->lve_id = lve_id;
	data->lvp_id = lvp_id;
	lvp_map.last++;
	sort(lvp_map.array, lvp_map.last, sizeof(*data),
			entry_cmp, NULL);

out_unlock:
	up_write(&lvp_map.sem);

	return ret;
}

void lve_lvp_map_del(uint32_t lve_id)
{
	struct map_entry *ret, *next, *end;
	unsigned int size;

	/* default lve for reseler must 
	 * don't exist in map */
	if (lve_id == 0)
		return;

	down_write(&lvp_map.sem);
	ret = map_fetch(lve_id);
	if (ret == NULL)
		goto out_unlock;

	if (ret == map_entry(lvp_map.last-1))
		goto out_last;
	next = ret + 1;
	/* pointer to behind data */
	end = map_entry(lvp_map.last+1);
	size = (void *)end-(void *)next;
	memmove(ret, next, size);
out_last:
	lvp_map.last--;
out_unlock:
	up_write(&lvp_map.sem);

}

int lve_lvp_map_move(uint32_t lve_id, uint32_t lvp_id)
{
	return -ENOSYS;
}

uint32_t lve_lvp_map_get(uint32_t lve_id)
{
	struct map_entry *ret;
	uint32_t lvp_id = 0;

	if (lve_id == ROOT_LVE)
		return ROOT_LVP;

	down_read(&lvp_map.sem);
	ret = map_fetch(lve_id);
	if (ret != NULL)
		lvp_id = ret->lvp_id;
	up_read(&lvp_map.sem);

	return lvp_id;
}


int __init lve_lvp_map_init()
{
	init_rwsem(&lvp_map.sem);

	return map_realloc(MAP_CAPACITY);
}

void lve_lvp_map_fini()
{
	map_release();
}
