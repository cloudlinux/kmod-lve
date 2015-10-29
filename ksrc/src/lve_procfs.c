#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mutex.h>
#include <linux/fairsched.h>
#include <linux/time.h>

#include <asm/uaccess.h>

#include "lve_internal.h"
#include "lve_debug.h"
#include "light_ve.h"
#include "resource.h"
#include "lve_kmod_c.h"

/************************ list *********************************/

static void *
list_start(struct seq_file *m, loff_t *pos)
{
	struct list_head *p;
	struct light_ve *ret = NULL;
	struct lvp_ve_private *lvp;
	loff_t l = *pos;

	if (!l--)
		return SEQ_START_TOKEN;

	lvp = TASK_VE_PRIVATE(current);
	read_lock_irq(&lvp->lvp_lock);
	list_for_each(p, &lvp->lvp_list) {
		if (!l--) {
			ret = list_entry(p, struct light_ve, lve_link);
			light_ve_get(ret);
			break;
		}
	}
	read_unlock_irq(&lvp->lvp_lock);

	return ret;
}

#define lve_if_not_last(list, point) \
	((point)->next == list ? NULL :  \
	list_first_entry(point, struct light_ve, lve_link))

static void *
list_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct light_ve *old = v;
	struct light_ve *ret = NULL, *entry;
	struct lvp_ve_private *lvp = TASK_VE_PRIVATE(current);

	read_lock_irq(&lvp->lvp_lock);
	if (v == SEQ_START_TOKEN) {
		ret = lve_if_not_last(&lvp->lvp_list, &lvp->lvp_list);
	} else {
		if (unlikely(old->lve_unlinked)) {
			LVE_DBG("Lve %d is deleted but still in lve_list\n", old->lve_id);
			list_for_each_entry(entry, &lvp->lvp_list, lve_link) {
				if (entry->lve_id > old->lve_id) {
					LVE_DBG("Next lve is %d \n", entry->lve_id);
					ret = entry;
					break;
				}
			}
		} else {
			ret = lve_if_not_last(&lvp->lvp_list, &old->lve_link);
		}
	}
	(*pos)++;

	if (ret)
		light_ve_get(ret);
	read_unlock_irq(&lvp->lvp_lock);
	if (v != SEQ_START_TOKEN)
		light_ve_put(old);

	return ret;
}

static void
list_stop(struct seq_file *m, void *v)
{
	struct light_ve *old = v;

	if (old && v != SEQ_START_TOKEN)
		light_ve_put(old);
}

static void lve_stat_show(struct seq_file *m, int head, struct light_ve *lve)
{
	struct lve_usage usage;

	if (head != 0) {
		seq_printf(m, "8:LVE\tEP");
		seq_printf(m, "\tlCPU\tlIO\tCPU");
		seq_printf(m, "\tMEM\tIO");
		seq_printf(m, "\tlMEM\tlEP\tnCPU");
		seq_printf(m, "\tfMEM\tfEP");
		seq_printf(m, "\tlMEMPHY\tlCPUW\tlNPROC");
		seq_printf(m, "\tMEMPHY\tfMEMPHY\tNPROC\tfNPROC");
		seq_printf(m, "\tlIOPS\tIOPS");
		seq_printf(m, "\n");
	}

	lve_resource_usage(lve, &usage);

	/* XXX read long always atomic */
	seq_printf(m, "%u\t"LPU64,
		  lve->lve_id, usage.data[RES_ENTER].data);

	seq_printf(m, "\t%u\t%u\t"LPU64,
		  lve->lve_limits[LIM_CPU],
		  lve->lve_limits[LIM_IO],
		  usage.data[RES_CPU].data);

	/** MEM/IOe */
	seq_printf(m, "\t"LPU64"\t"LPU64,
		  usage.data[RES_MEM].data,
		  usage.data[RES_IO].data);

	seq_printf(m, "\t%u\t%u\t%u",
		  lve->lve_limits[LIM_MEMORY],
		  lve->lve_limits[LIM_ENTER],
		  lve->lve_limits[LIM_CPUS]);

	seq_printf(m, "\t"LPU64"\t"LPU64,
		   usage.data[RES_MEM].fail,
		   usage.data[RES_ENTER].fail);

	seq_printf(m, "\t%u\t%u\t%u",
		  lve->lve_limits[LIM_MEMORY_PHY],
		  lve->lve_limits[LIM_CPU_WEIGHT],
		  lve->lve_limits[LIM_NPROC]);

	seq_printf(m, "\t"LPU64"\t"LPU64,
		   usage.data[RES_MEM_PHY].data,
		   usage.data[RES_MEM_PHY].fail);

	seq_printf(m, "\t"LPU64"\t"LPU64,
		   usage.data[RES_NPROC].data,
		   usage.data[RES_NPROC].fail);

	seq_printf(m, "\t%u\t"LPU64,
		   lve->lve_limits[LIM_IOPS],
		   usage.data[RES_IOPS].data);

	seq_printf(m, "\n");

}

static int list_show(struct seq_file *m, void *v)
{
	struct light_ve *lve = v;
	struct lvp_ve_private *lvp;

	if (v == SEQ_START_TOKEN) {
		/* print defaults */
		lvp = TASK_VE_PRIVATE(current);
		lve = lvp->lvp_default;
	}

	lve_stat_show(m, (v == SEQ_START_TOKEN), lve);

	return 0;
}

static const struct seq_operations lve_list_op = {
	.start	= list_start,
	.next	= list_next,
	.stop	= list_stop,
	.show	= list_show
};

static int lve_list_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = seq_open(file, &lve_list_op);
	if (ret)
		return ret;

	return 0;
}

static const struct file_operations lve_list_fops = {
	.owner		= THIS_MODULE,
	.open           = lve_list_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};
/**************** list end ***************************/

static int usage_show(struct seq_file *m, void *v)
{
	struct light_ve *lve = v;
	struct lve_usage usage;
	struct lvp_ve_private *lvp = TASK_VE_PRIVATE(current);

	if (v == SEQ_START_TOKEN) {
		seq_printf(m, "LAST RESET: %lu\n", lvp->lvp_last_reset);
		seq_printf(m, "LVE\tfMEM\tfEP\tCPU\n");
		return 0;
	}

	lve_resource_usage(lve, &usage);
	seq_printf(m, "%u\t%lu\t%ld\t"LPU64"\n",
		  lve->lve_id,
		  (unsigned long)0,
		  lve->lve_stats.st_err_enters,
		  usage.data[RES_CPU].data);

	return 0;
}

static const struct seq_operations lve_usage_op = {
	.start	= list_start,
	.next	= list_next,
	.stop	= list_stop,
	.show	= usage_show
};

#define LVE_CLEAR_CMD  "clear"
static ssize_t lve_usage_write(struct file *file, const char __user *data, 
			    size_t count, loff_t *off)
{
	char d[sizeof LVE_CLEAR_CMD + 1];
	struct light_ve *lve;
	struct lvp_ve_private *lvp;
	int rc;

	if (!data || count < (sizeof(LVE_CLEAR_CMD) - 1) || *off)
		return -EINVAL;

	memset(d, 0, sizeof d);

	rc = copy_from_user(d, data, (sizeof(LVE_CLEAR_CMD) - 1));
	if (rc)
		return rc;

	if (strcmp(d, LVE_CLEAR_CMD))
		return -ENOSYS;

	lvp = TASK_VE_PRIVATE(current);
	read_lock_irq(&lvp->lvp_lock);
	list_for_each_entry(lve, &lvp->lvp_list, lve_link) {
		os_resource_usage_clear(lve_private(lve));
		spin_lock(&lve->lve_stats.enter_lock);
		lve->lve_stats.st_err_enters = 0;
		spin_unlock(&lve->lve_stats.enter_lock);
		/** XXX mem fault reset*/
	}
	read_unlock_irq(&lvp->lvp_lock);

	lvp->lvp_last_reset = get_seconds();

	return count;
}


static int lve_usage_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = seq_open(file, &lve_usage_op);
	if (ret)
		return ret;

	return 0;
}

static const struct file_operations lve_usage_fops = {
	.owner		= THIS_MODULE,
	.open           = lve_usage_open,
	.read           = seq_read,
	.write		= lve_usage_write,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

static const char *facilities[] = {
	[LVE_DEBUG_FAC_DBG]  = "debug",
	[LVE_DEBUG_FAC_WARN] = "warning",
	[LVE_DEBUG_FAC_ERR]  = "error"
};

static ssize_t lve_debug_write(struct file *file, const char __user *data,
				size_t count, loff_t *off)
{
	char str[50], *pstr = str;
	int rc, i;
	unsigned newmask = 0, op = 0;

	if (!data || count > (sizeof(str) - 1) || *off)
		return -EINVAL;

	rc = copy_from_user(str, data, count);
	if (rc)
		return -EFAULT;
	str[count] = '\0';

	/* add subsystems to the list */
	if (str[0] == '+') {
		op = +1;
		pstr++;
	}
	/* remove subsystems from the list */
	if (str[0] == '-') {
		op = -1;
		pstr++;
	}

	while (*pstr) {
		char *lstr;

		while (*pstr == ' ' || *pstr == '\t' || *pstr == '\n')
			pstr++;

		if (!*pstr)
			break;

		lstr = pstr;
		while (*lstr != ' ' && *lstr != '\t' && *lstr != '\n' && *lstr)
			lstr++;

		for (i = 0; i < ARRAY_SIZE(facilities); i++) {
			if (strlen(facilities[i]) == (lstr - pstr) &&
			    !strncmp(facilities[i], pstr, lstr - pstr)) {
				newmask |= (1 << i);
				break;
			}
		}

		if (i == ARRAY_SIZE(facilities))
			return -EINVAL;

		pstr = lstr;
	}

	switch (op) {
	case -1:
		atomic_clear_mask(newmask, &lve_debug_mask);
		break;
	case  0:
		atomic_set(&lve_debug_mask, newmask);
		break;
	case +1:
		atomic_set_mask(newmask, &lve_debug_mask);
		break;
	default:
		BUG();
	}

	return count;
}

static int debug_show(struct seq_file *m, void *v)
{
	unsigned mask, i;
	mask = atomic_read(&lve_debug_mask);

	for (i = 0; i < ARRAY_SIZE(facilities); i++, mask >>= 1) {
		if (mask & 1) {
			seq_puts(m, facilities[i]);
			if (mask > 1)
				seq_putc(m, ' ');
		}
	}

	seq_putc(m, '\n');

	return 0;
}


static int lve_debug_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = single_open(file, debug_show, NULL);
	if (ret)
		return ret;

	return 0;
}

static const struct file_operations lve_debug_fops = {
	.owner		= THIS_MODULE,
	.open		= lve_debug_open,
	.read		= seq_read,
	.write		= lve_debug_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static ssize_t lve_fail_write(struct file *file, const char __user *data,
				size_t count, loff_t *off)
{
	char str[50], *ptr;
	int rc;
	unsigned long new_value;

	if (!data || count > (sizeof(str) - 1) || *off)
		return -EINVAL;

	rc = copy_from_user(str, data, count);
	if (rc)
		return -EFAULT;
	str[count] = '\0';

	new_value = simple_strtoul(str, &ptr, 0);
	if (ptr == str)
		return -EINVAL;

	fail_value = new_value;

	return count;
}

static int fail_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%lx\n", fail_value);
	return 0;
}

static int lve_fail_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = single_open(file, fail_show, NULL);
	if (ret)
		return ret;

	return 0;
}

static const struct file_operations lve_fail_fops = {
	.owner		= THIS_MODULE,
	.open		= lve_fail_open,
	.read		= seq_read,
	.write		= lve_fail_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#ifdef HAVE_EXEC_NOTIFIER

static ssize_t lve_enter_write(struct file *file, const char __user *data,
				size_t count, loff_t *off)
{
	char str[50];
	int rc;

	if (!data || count > (sizeof(str) - 1) || *off)
		return -EINVAL;

	rc = copy_from_user(str, data, count);
	if (rc)
		return -EFAULT;
	str[count] = '\0';

	if (str[0] == '+') {
		rc = lve_exec_add_file(TASK_VE_PRIVATE(current), &str[1]);
		if (rc)
			return rc;
	} else if (str[0] == '-') {
		rc = lve_exec_del_file(TASK_VE_PRIVATE(current), &str[1]);
		if (rc)
			return rc;
	} else {
		return -EINVAL;
	}

	return count;
}

static int lve_enter_show(struct seq_file *m, void *v)
{
	struct lve_exec_entry *e;
	char pathname[256], *rpath;
	struct lvp_ve_private *lvp = TASK_VE_PRIVATE(current);

	read_lock(&lvp->lvp_exec_lock);
	list_for_each_entry(e, &lvp->lvp_exec_entries, list) {
		rpath = d_path(&e->path, pathname, sizeof(pathname));
		seq_printf(m, "%s\n", rpath);
	}
	read_unlock(&lvp->lvp_exec_lock);

	return 0;
}

static int lve_enter_open(struct inode *inode, struct file *file)
{
	return single_open(file, lve_enter_show, NULL);
}

static const struct file_operations lve_enter_fops = {
	.owner		= THIS_MODULE,
	.open		= lve_enter_open,
	.read		= seq_read,
	.write		= lve_enter_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

/*************** stat end ****************************/

static void dir_seq_entry(struct proc_dir_entry *dir, const char *name,
			  mode_t mode, const struct file_operations *f, void *data)
{
	struct proc_dir_entry *entry;

	entry = proc_create(name, mode, dir, f);
	if (entry != NULL && data != NULL)
		entry->data = data;

}

static int lve_dir_stats_show(struct seq_file *m, void *v)
{
	lve_stat_show(m, 1, m->private);
	return 0;
}

static int lve_dir_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, lve_dir_stats_show, PDE_DATA(inode));
}

static const struct file_operations lve_dir_stats_fops = {
	.owner		= THIS_MODULE,
	.open		= lve_dir_stats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int _lve_stats_dir_init(const char *name, struct light_ve *lve)
{
	struct proc_dir_entry *lve_dir;

	lve_dir = proc_mkdir(name, lve->lve_lvp->lvp_stats_root);
	if (lve_dir == NULL)
		return -EINVAL;
	lve->lve_proc_dir = lve_dir;
	dir_seq_entry(lve_dir, "stat", S_IRUGO, &lve_dir_stats_fops, lve);

	return 0;
}

void _lve_stats_dir_fini(const char *name, struct light_ve *lve)
{
	if (lve->lve_proc_dir != NULL) {
		remove_proc_entry("stat", lve->lve_proc_dir);
		remove_proc_entry(name, lve->lve_lvp->lvp_stats_root);
	}
}

int lve_stats_dir_init(struct light_ve *lve)
{
	char name[30];

	snprintf(name, sizeof(name)-1, "%u", lve->lve_id);
	return _lve_stats_dir_init(name, lve);
}

void lve_stats_dir_fini(struct light_ve *lve)
{
	char name[30];

	snprintf(name, sizeof(name)-1, "%u", lve->lve_id);
	return _lve_stats_dir_fini(name, lve);
}

/****************************************************/
static void _seq_entry(struct proc_dir_entry *lve_proc_root, char *name, mode_t mode,
		       const struct file_operations *f)
{
	struct proc_dir_entry *entry;

	entry = proc_create(name, mode, lve_proc_root, f);
}

int lvp_proc_init(struct lvp_ve_private *lvp)
{
	struct proc_dir_entry *root, *lve_proc_root;

	root = lve_procfs_root(lvp);

	lve_proc_root = proc_mkdir("lve", root);
	LVE_DBG("root=%p lve_proc_root=%p\n", root, lve_proc_root);
	if (lve_proc_root) {
		lvp->lvp_proc_root = lve_proc_root;
		_seq_entry(lve_proc_root, "list", S_IRUGO, &lve_list_fops);
		_seq_entry(lve_proc_root, "usage", S_IRUGO, &lve_usage_fops);
		_seq_entry(lve_proc_root, "debug", S_IRUGO, &lve_debug_fops);
		_seq_entry(lve_proc_root, "fail", S_IRUGO, &lve_fail_fops);
#ifdef HAVE_EXEC_NOTIFIER
		_seq_entry(lve_proc_root, "enter", S_IRUGO, &lve_enter_fops);
#endif
		lvp->lvp_stats_root = proc_mkdir("per-lve", lve_proc_root);
		return _lve_stats_dir_init("default", lvp->lvp_default);
	}
	return -ENOMEM;
}

int lvp_proc_fini(struct lvp_ve_private *lvp)
{
	struct proc_dir_entry *root;

	if (lvp->lvp_proc_root) {
#ifdef HAVE_EXEC_NOTIFIER
		remove_proc_entry("enter", lvp->lvp_proc_root);
#endif
		remove_proc_entry("debug", lvp->lvp_proc_root);
		remove_proc_entry("usage", lvp->lvp_proc_root);
		remove_proc_entry("list", lvp->lvp_proc_root);
		remove_proc_entry("fail", lvp->lvp_proc_root);
		/* */
		_lve_stats_dir_fini("default", lvp->lvp_default);
		remove_proc_entry("per-lve", lvp->lvp_proc_root);
		/* */
		root = lve_procfs_root(lvp);
		remove_proc_entry("lve", root);
	}
	return 0;
}
