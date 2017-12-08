/*
 * os/mm.c
 *
 * Common memory-management routines
 */

#include <linux/mm.h>

#include "mm.h"

/*
 * make_pages_present_ext() - "pre-fault" user pages for a given virtual range
 *
 * This is a slightly extended version of make_pages_present() in mm/memory.c
 * to be able to "pre-fault" an arbitrary virtual address space.
 *
 * Note, we use "read-faults" to avoid COW and anon. pages allocations
 *
 * @mm:		 target virtual address space
 * @addr:	 start address of the range (in bytes)
 * @end:	 end address of the range + 1 (in bytes)
 * @task:	 task_struct used for a fault accounting, NULL if you don't need it
 *
 * Must be called with mmap_sem held for read or write
 */
int make_pages_present_ext(struct mm_struct *mm,
			unsigned long addr, unsigned long end,
			struct task_struct *task)
{
	int ret, len, write;
	struct vm_area_struct * vma;

	vma = find_vma(mm, addr);
	if (!vma)
		return -ENOMEM;
	/*
	 * Setting write = 0, so we:
	 * 1. Don't force COW to occur
	 * 2. Don't force anonymous allocations
	 * (for read-fault, just the same zeroed page is always used)
	 */
        write = 0;
        BUG_ON(addr >= end);
        BUG_ON(end > vma->vm_end);
        len = DIV_ROUND_UP(end, PAGE_SIZE) - (addr >> PAGE_SHIFT);
        ret = get_user_pages(task, mm, addr,
                        len, write, 0, NULL, NULL);
        if (ret < 0)
                return ret;
        return ret == len ? 0 : -EFAULT;
}
