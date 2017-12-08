#ifndef _MM_H_
#define _MM_H_

int make_pages_present_ext(struct mm_struct *mm,
			unsigned long addr, unsigned long end,
			struct task_struct *task);
#endif
