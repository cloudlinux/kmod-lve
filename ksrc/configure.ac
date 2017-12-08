#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

# Generic configuration
AC_PREREQ(2.59)
AC_INIT(lve-kmod, 1.1, umka@sevcity.net)
AC_PREFIX_DEFAULT([/usr])
AC_CONFIG_HEADER([src/include/lve_kmod_c.h])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AC_DEFUN([LVE_LINUX_INIT_CONFIG], [
rm -fr config > /dev/null 2>&1
mkdir config
cat >config/Makefile <<_ACEOF
obj-m := conftest.o

modules:
	\$(MAKE) -C \$(KERNEL_OBJ) M=\`pwd\` modules
_ACEOF
])


SYMVERFILE="Module.symvers"
MAPFILE=""

sym_addr=0
AC_DEFUN([LVE_SYM_ADDR],[
sym_addr=`awk -v sym=$1 -v sym_addr=0 '{if (( \
		($ 2 == "T") || ($ 2 == "t") || ($ 2 == "D") || ($ 2 == "d") || \
		($ 2 == "b")) \
		&& ($ 3 == sym)) {sym_addr=$ 1;}}END {print "0x"sym_addr;}' $MAPFILE`
])

# New macros for checking various things
AC_DEFUN([LVE_LINUX_SYMVER],[
        AC_MSG_CHECKING([for symbols file])
        if grep -q Modules.symvers $KERNEL/scripts/Makefile.modpost ; then
                SYMVERFILE=Modules.symvers
	fi
	AC_MSG_RESULT([$KERNEL/$SYMVERFILE])
])

AC_DEFUN([LVE_LINUX_MAPFILE],[
		AC_MSG_CHECKING([for map file])
		if test -e "$KERNEL/System.map"; then
			MAPFILE="$KERNEL/System.map"
		else
			unm=`${MAKE-make} -s -C $KERNEL_OBJ kernelrelease`
			if test -e "/boot/System.map-$unm"; then
				MAPFILE="/boot/System.map-$unm"
			fi
		fi
	if test -z "$MAPFILE"; then
		AC_MSG_ERROR([can not find an Mapfile!])
	fi
	AC_MSG_RESULT([$MAPFILE])
])

# New macros for checking various things
AC_DEFUN([LVE_LINUX_CHECK_SYMBOL],[
        AC_MSG_CHECKING([for symbol $1 exported])
        grep -q -E '[[[:space:]]]$1[[[:space:]]]' $KERNEL/$SYMVERFILE 2>/dev/null
        rc=$?
        if test $rc -eq 0; then
                AC_MSG_RESULT([yes])
                $2
        else
                AC_MSG_RESULT([no])
                $3
        fi
])

AC_DEFUN([LVE_LINUX_CONFTEST],
[cat >conftest.c <<_ACEOF
$1
_ACEOF
])

AC_DEFUN([LVE_C_PROGRAM],
[
#include <linux/kernel.h>
$1
int
main (void)
{
dnl Do *not* indent the following line: there may be CPP directives.
dnl Don't move the `;' right after for the same reason.
$2
  ;
  return 0;
}])

AC_DEFUN([LVE_LINUX_COMPILE_IFELSE],
[m4_ifvaln([$1], [LVE_LINUX_CONFTEST([$1])])
rm -f config/conftest.o config/conftest.mod.c config/conftest.ko
AS_IF([AC_TRY_COMMAND([cp conftest.c config && cd config && make -d $2 ${LD:+"LD=$LD"} CC="$CC" KERNEL_OBJ=$KERNEL_OBJ]) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])])
rm -f config/conftest.o config/conftest.mod.c config/conftest.mod.o config/conftest.ko m4_ifval([$1], [config/conftest.c conftest.c])[]
])

AC_DEFUN([LVE_LINUX_TRY_COMPILE],[
        LVE_LINUX_COMPILE_IFELSE(
                [AC_LANG_SOURCE([LVE_C_PROGRAM([[$1]], [[$2]])])],
                [modules],
                [test -s config/conftest.o],
                [$3], [$4])
])

AC_DEFUN([LVE_LINUX_CONFIG], [
LVE_LINUX_TRY_COMPILE([
#ifndef $1
#error $1 not defined
#endif
],[
],[
 [$2]
 AC_MSG_RESULT([$1 defined on kernel config])
],[
 AC_MSG_RESULT([$1 not defined on kernel config])
])
])

AC_DEFUN([LVE_LINUX_INCLUDE], [
if test -r $KERNEL/include/linux/$1; then
 $2
 AC_MSG_RESULT([$1 exist on kernel])
else
 AC_MSG_RESULT([$1 not exist on kernel])
fi
])

AC_DEFUN([LVE_EXEC_NOTIFIER],[
AC_MSG_CHECKING([virtinfo.h has VIRTINFO_EXEC])
LVE_LINUX_TRY_COMPILE([
        #include <linux/virtinfo.h>
],[
	int v;

	v = VIRTINFO_EXEC;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_EXEC_NOTIFIER, 1,
                  [virtinfo.h has VIRTINFO_EXEC])
],[
        AC_MSG_RESULT(NO)
])
])

AC_DEFUN([LVE_CRED_EUID_IS_PLAIN],[
AC_MSG_CHECKING([cred->euid is integer])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cred.h>
],[
	struct cred cred;
	cred.euid = 0;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_PLAIN_CRED_EUID, 1,
		[cred->euid is integer])
],[
	AC_MSG_RESULT(no)
])
])

### symbols

AC_DEFUN([LVE_SYM_COPY_FS],[
AC_MSG_CHECKING([copy_fs_struct exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
],[
	struct fs_struct *(*lve_copy_fs_struct)(struct fs_struct *);

	lve_copy_fs_struct = copy_fs_struct;
],[
	LVE_SYM_ADDR(copy_fs_struct)
	if test $sym_addr != "0x0"; then
		SYM_COPY_FS="lve_copy_fs_struct = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_COPY_FS])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_FS_PWD],[
AC_MSG_CHECKING([set_fs_pwd exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
],[
#ifdef HAVE_3ARGS_FS_SET_ROOT
	void (*lve_set_fs_pwd)(struct fs_struct *, struct vfsmount *, struct dentry *);
#else
	void (*lve_set_fs_pwd)(struct fs_struct *, struct path *);
#endif

	lve_set_fs_pwd = set_fs_pwd;
],[
	LVE_SYM_ADDR(set_fs_pwd)
	if test $sym_addr != "0x0"; then
		SYM_FS_PWD="_lve_set_fs_pwd = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FS_PWD])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_FS_ROOT],[
AC_MSG_CHECKING([set_fs_root exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
],[
	void (*lve_set_fs_root)(struct fs_struct *, struct path *);

	lve_set_fs_root = set_fs_root;
],[
	LVE_SYM_ADDR(set_fs_root)
	if test $sym_addr != "0x0"; then
		SYM_FS_ROOT="_lve_set_fs_root = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FS_ROOT])
AC_MSG_RESULT([$sym_addr])
])

# -- GROUP_KERNEL_ATTACH
AC_DEFUN([LVE_SYM_CGROUP_KERNEL_ATTACH],[
AC_MSG_CHECKING([cgroup_kernel_attach exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/module.h>
	#include <linux/cgroup.h>
	#include <linux/sched.h>
],[
	int (*lve_sym)(struct cgroup *cgrp, struct task_struct *tsk);

	lve_sym = cgroup_kernel_attach;
],[
	LVE_SYM_ADDR(cgroup_kernel_attach)
	if test $sym_addr != "0x0"; then
		SYM_CGROUP_KERNEL_ATTACH="_lve_cgroup_kernel_attach = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_CGROUP_KERNEL_ATTACH])
AC_MSG_RESULT([$sym_addr])
])

# -- FREE_FS_STRUCT
AC_DEFUN([LVE_SYM_FREE_FS_STRUCT],[
AC_MSG_CHECKING([free_fs_struct exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/module.h>
	#include <linux/fs_struct.h>
],[
	void (*lve_sym)(struct fs_struct *fs);

	lve_sym = free_fs_struct;
],[
	LVE_SYM_ADDR(free_fs_struct)
	if test $sym_addr != "0x0"; then
		SYM_FREE_FS_STRUCT="lve_free_fs_struct = $sym_addr;"
		AC_DEFINE([HAVE_KILL_FS], [], [new FS struct API])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FREE_FS_STRUCT])
AC_MSG_RESULT([$sym_addr])
])

# OpenVZ-el6 ub_precharge_snapshot
AC_DEFUN([LVE_SYM_UB_SNAPSHOT],[
AC_MSG_CHECKING([ub_precharge_snapshot exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	void (*lve_sym)(struct user_beancounter *ub, int *precharge);

	lve_sym = ub_precharge_snapshot;
],[
	LVE_SYM_ADDR(ub_precharge_snapshot)
	if test $sym_addr != "0x0"; then
		SYM_UB_SNAPSHOT="lve_ub_prechange_snapshot = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_UB_SNAPSHOT])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_UB_SETLIMIT_BY_ID],[
AC_MSG_CHECKING([do_setublimit_by_id exists in kernel])
	LVE_SYM_ADDR(do_setublimit_by_id)
	if test $sym_addr != "0x0"; then
		AC_DEFINE(UBC_CL_API, 1, [use CL based api to change limits])
		AC_MSG_RESULT(YES)
	else
		AC_MSG_RESULT(NO)
	fi
])

# not exist at any header :(
AC_DEFUN([LVE_SYM_UB_SETLIMIT],[
AC_MSG_CHECKING([do_setublimit exists in kernel])
	LVE_SYM_ADDR(do_setublimit)
	if test $sym_addr != "0x0"; then
		SYM_UB_SETLIMIT="lve_setublimit = $sym_addr;"
	fi
AC_SUBST([SYM_UB_SETLIMIT])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM___FPUT],[
AC_MSG_CHECKING([__fput exists in kernel])
	LVE_SYM_ADDR(__fput)
	if test $sym_addr != "0x0"; then
		SYM___FPUT="__fput = $sym_addr;"
		AC_DEFINE([HAVE___FPUT], [], [use __fput])
	fi
AC_SUBST([SYM___FPUT])
AC_MSG_RESULT([$sym_addr])
])

# -- FIND_TASK_BY_VPID
AC_DEFUN([LVE_SYM_FIND_TASK_BY_VPID],[
AC_MSG_CHECKING([find_task_by_vpid exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/pid.h>
	#include <linux/sched.h>
],[
	struct task_struct *(*lve_sym)(pid_t nr);

	lve_sym = find_task_by_vpid;
],[
	LVE_SYM_ADDR(find_task_by_vpid)
	if test $sym_addr != "0x0"; then
		SYM_FIND_TASK_BY_VPID="lve_find_task_by_vpid = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FIND_TASK_BY_VPID])
AC_MSG_RESULT([$sym_addr])
])

# -- FIND_UB_ATTACH_TASK
AC_DEFUN([LVE_SYM_UB_ATTACH_TASK],[
AC_MSG_CHECKING([ub_attach_task exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
	#include <linux/sched.h>
],[
	int (*lve_sym)(struct user_beancounter *ub, struct task_struct *task);

	lve_sym = ub_attach_task;
],[
	LVE_SYM_ADDR(ub_attach_task)
	if test $sym_addr != "0x0"; then
		AC_DEFINE([HAVE_UB_ATTACH_TASK], [], [use ub_attach_task])
		SYM_UB_ATTACH_TASK="_lve_ub_attach_task = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_UB_ATTACH_TASK])
AC_MSG_RESULT([$sym_addr])
])

# -- FIND_UB_ATTACH
AC_DEFUN([LVE_SYM_UB_ATTACH],[
AC_MSG_CHECKING([ub_attach exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
	#include <bc/task.h>
],[
	int (*lve_sym)(struct user_beancounter *ub);

	lve_sym = ub_attach;
],[
	LVE_SYM_ADDR(ub_attach)
	if test $sym_addr != "0x0"; then
		SYM_UB_ATTACH="_lve_ub_attach = $sym_addr;"
		AC_DEFINE([HAVE_UB_ATTACH], [], [use ub_attach])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_UB_ATTACH])
AC_MSG_RESULT([$sym_addr])
])

# -- UB_GET_CSS
AC_DEFUN([LVE_SYM_UB_GET_CSS],[
AC_MSG_CHECKING([ub_get_css exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
	#include <bc/beancounter.h>
],[
	struct cgroup_subsys_state *(*lve_sym)(struct user_beancounter *ub, int idx);

	lve_sym = __ub_get_css;
],[
	LVE_SYM_ADDR(__ub_get_css)
	if test $sym_addr != "0x0"; then
		SYM_UB_GET_CSS="lve_ub_get_css = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_UB_GET_CSS])
AC_MSG_RESULT([$sym_addr])
])

# -- GET_BEANCOUNTER_BYUID
AC_DEFUN([LVE_SYM_GET_BEANCOUNTER_BYUID],[
AC_MSG_CHECKING([get_beancounter_byuid exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	struct user_beancounter *(*lve_sym)(uid_t uid, int create);

	lve_sym = get_beancounter_byuid;
],[
	LVE_SYM_ADDR(get_beancounter_byuid)
	if test $sym_addr != "0x0"; then
		AC_DEFINE(HAVE_GET_BEANCOUNTER_BYUID, 1,
			[get_beancounter_by_uid exists])
		SYM_GET_BEANCOUNTER_BYUID="lve_get_beancounter_byuid = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_GET_BEANCOUNTER_BYUID])
AC_MSG_RESULT([$sym_addr])
])

# -- GET_BEANCOUNTER_BYUID
AC_DEFUN([LVE_SYM_GET_BEANCOUNTER_BY_NAME],[
AC_MSG_CHECKING([get_beancounter_byuid exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	struct user_beancounter *(*lve_sym)(const char *name, int create);

	lve_sym = get_beancounter_by_name;
],[
	LVE_SYM_ADDR(get_beancounter_by_name)
	if test $sym_addr != "0x0"; then
		AC_DEFINE(HAVE_GET_BEANCOUNTER_BYNAME, 1,
			[get_beancounter_by_name exists])
		SYM_GET_BEANCOUNTER_BYNAME="lve_get_beancounter_by_name = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_GET_BEANCOUNTER_BYNAME])
AC_MSG_RESULT([$sym_addr])
])

# -- UB_CGROUP_ROOT
AC_DEFUN([LVE_SYM_UB_CGROUP_ROOT],[
AC_MSG_CHECKING([ub_cgroup_root exists in kernel])
	LVE_SYM_ADDR(ub_cgroup_root)
	if test $sym_addr != "0x0"; then
		SYM_UB_CGROUP_ROOT="lve_ub_cgroup_root = $sym_addr;"
		AC_DEFINE(HAVE_UB_CGROUP_ROOT, 1,
			[ub_cgroup_root exists])
	fi
AC_SUBST([SYM_UB_CGROUP_ROOT])
AC_MSG_RESULT([$sym_addr])
])

# -- VE_TASK_INFO
AC_DEFUN([LVE_VE_CLEANUP_CHAIN],[
AC_MSG_CHECKING([VE_CLEANUP_CHAIN in ve_proto.h])
LVE_LINUX_TRY_COMPILE([
	#include <linux/ve_proto.h>
],[
	int chain;

	chain = VE_CLEANUP_CHAIN;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_VE_CLEANUP_CHAIN], [], [have ve_cleanup_chain in ve_proto.h])
],[
	AC_MSG_RESULT(no)
])
])

AC_DEFUN([LVE_DO_EACH_THREAD_ALL],[
AC_MSG_CHECKING([do_each_thread_all in sched.h])
LVE_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	struct task_struct *t, *p;

	do_each_thread_all(t, p) {
	} while_each_thread_all(t, p);
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_DO_EACH_THREAD_ALL], [], [have do_each_thread_all in sched.h])
],[
	AC_MSG_RESULT(no)
])
])

AC_DEFUN([LVE_IN_UB_MEMCG_ATTACH],[
AC_MSG_CHECKING([in_ub_memcg_attach in sched.h])
LVE_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	struct task_struct *t;
	t->in_ub_memcg_attach = 0;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_IN_UB_MEMCG_ATTACH], [], [have in_ub_memcg_attach in sched.h])
],[
	AC_MSG_RESULT(no)
])
])

# -- UB_SYNC_MEMCG
AC_DEFUN([LVE_SYM_UB_SYNC_MEMCG],[
AC_MSG_CHECKING([ub_sync_memcg is exported])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	void (*lve_sym)(struct user_beancounter *ub);

	lve_sym = ub_sync_memcg;
],[
	LVE_SYM_ADDR(ub_sync_memcg)
	if test $sym_addr != "0x0"; then
		SYM_UB_SYNC_MEMCG="ub_sync_memcg = $sym_addr;"
		AC_DEFINE([HAVE_UB_SYNC_MEMCG], [], [ub_sync_memcg exported])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_UB_SYNC_MEMCG])
AC_MSG_RESULT([$sym_addr])
])

# -- UB_CGROUP_MNT
AC_DEFUN([LVE_SYM_UB_CGROUP_MNT],[
AC_MSG_CHECKING([ub_cgroup_mnt exists in kernel])
	LVE_SYM_ADDR(ub_cgroup_mnt)
	if test $sym_addr != "0x0"; then
		SYM_UB_CGROUP_MNT="lve_ub_cgroup_mnt = $sym_addr;"
		AC_DEFINE(HAVE_UB_CGROUP_MNT, 1, [ub_cgroup_mnt exists])
	fi
AC_SUBST([SYM_UB_CGROUP_MNT])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_CGROUP_ITER_START],[
AC_MSG_CHECKING([cgroup_iter_start is exported])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
],[
	struct cgroup *cg = NULL;
	struct cgroup_iter *iter = NULL;

	cgroup_iter_start(cg, iter);
],[
	LVE_SYM_ADDR(cgroup_iter_start)
	if test $sym_addr != "0x0"; then
		SYM_CGROUP_ITER_START="cgroup_iter_start = $sym_addr;"
		AC_DEFINE([HAVE_CGROUP_ITER_START], [], [cgroup_iter_start exported])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_CGROUP_ITER_START])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_CGROUP_ITER_NEXT],[
AC_MSG_CHECKING([cgroup_iter_next is exported])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
],[
	struct cgroup *cg = NULL;
	struct cgroup_iter *iter = NULL;
	struct task_struct *task;

	task = cgroup_iter_next(cg, iter);
],[
	LVE_SYM_ADDR(cgroup_iter_next)
	if test $sym_addr != "0x0"; then
		SYM_CGROUP_ITER_NEXT="cgroup_iter_next = $sym_addr;"
		AC_DEFINE([HAVE_CGROUP_ITER_NEXT], [], [cgroup_iter_next exported])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_CGROUP_ITER_NEXT])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_CGROUP_ITER_END],[
AC_MSG_CHECKING([cgroup_iter_end is exported])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
],[
	struct cgroup *cg = NULL;
	struct cgroup_iter *iter = NULL;

	cgroup_iter_end(cg, iter);
],[
	LVE_SYM_ADDR(cgroup_iter_end)
	if test $sym_addr != "0x0"; then
		SYM_CGROUP_ITER_END="cgroup_iter_end = $sym_addr;"
		AC_DEFINE([HAVE_CGROUP_ITER_END], [], [cgroup_iter_end exported])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_CGROUP_ITER_END])
AC_MSG_RESULT([$sym_addr])
])

# -- CGROUP_ATTACH_TASK
AC_DEFUN([LVE_SYM_CGROUP_ATTACH_TASK],[
AC_MSG_CHECKING([cgroup_attach_task exists in kernel])
	LVE_SYM_ADDR(cgroup_attach_task)
	if test $sym_addr != "0x0"; then
		SYM_CGROUP_ATTACH_TASK="lve_cgroup_attach_task = $sym_addr;"
		AC_DEFINE([HAVE_CGROUP_ATTACH_TASK], [], [cgroup_attach_task exists])
	fi
AC_SUBST([SYM_CGROUP_ATTACH_TASK])
AC_MSG_RESULT([$sym_addr])
])

# -- CGROUP_ATTACH_TASK HAS 2 ARGC
AC_DEFUN([LVE_2ARGS_CGROUP_ATTACH_TASK],[
AC_MSG_CHECKING([cgroup_attach_task has 2 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
	#include <linux/sched.h>
],[
	int (*lve_sym)(struct cgroup *cg, struct task_struct *tsk);

	lve_sym = cgroup_attach_task;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_2ARGS_CGROUP_ATTACH_TASK, 1, [cgroup_attach_task has 2 args])
],[
	AC_MSG_RESULT(no)
])
])

# -- CGROUP_MUTEX
AC_DEFUN([LVE_SYM_CGROUP_MUTEX],[
AC_MSG_CHECKING([cgroup_mutex exists in kernel])
	LVE_SYM_ADDR(cgroup_mutex)
	if test $sym_addr != "0x0"; then
		SYM_CGROUP_MUTEX="lve_cgroup_mutex = $sym_addr;"
		AC_DEFINE(HAVE_CGROUP_MUTEX, [], [cgroup_mutex exists])
	fi
AC_SUBST([SYM_CGROUP_MUTEX])
AC_MSG_RESULT([$sym_addr])
])

# -- CSS_SET_LOCK
AC_DEFUN([LVE_SYM_CSS_SET_LOCK],[
AC_MSG_CHECKING([css_set_lock exists in kernel])
        LVE_SYM_ADDR(css_set_lock)
        if test $sym_addr != "0x0"; then
                SYM_CSS_SET_LOCK="lve_css_set_lock = $sym_addr;"
                AC_DEFINE(HAVE_CSS_SET_LOCK, [], [css_set_lock exists])
        fi
AC_SUBST([SYM_CSS_SET_LOCK])
AC_MSG_RESULT([$sym_addr])
])

# -- FREEZER_CHANGE_STATE
AC_DEFUN([LVE_SYM_FREEZER_CHANGE_STATE],[
AC_MSG_CHECKING([freezer_change_state exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
	#include <linux/freezer.h>
],[
	int (*lve_sym)(struct cgroup *c, enum freezer_state s);

	lve_sym = freezer_change_state;
],[
	LVE_SYM_ADDR(freezer_change_state)
	if test $sym_addr != "0x0"; then
		SYM_FREEZER_CHANGE_STATE="lve_freezer_change_state = $sym_addr;"
		AC_DEFINE(HAVE_FREEZER_CHANGE_STATE, [], [freezer_change_state exists])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FREEZER_CHANGE_STATE])
AC_MSG_RESULT([$sym_addr])
])

# -- TRY_TO_FREE_GANG_PAGES
AC_DEFUN([LVE_SYM_TRY_TO_FREE_GANG_PAGES],[
AC_MSG_CHECKING([try_to_free_gang_pages exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	#include <linux/swap.h>
],[
	unsigned long (*lve_sym)(struct gang_set *gs, gfp_t gfp_mask);

	lve_sym = try_to_free_gang_pages;
],[
	LVE_SYM_ADDR(try_to_free_gang_pages)
	if test $sym_addr != "0x0"; then
		SYM_TRY_TO_FREE_GANG_PAGES="lve_try_to_free_gang_pages = $sym_addr;"
		AC_DEFINE(HAVE_TRY_TO_FREE_GANG_PAGES, [], [try_to_free_gang_pages exists])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_TRY_TO_FREE_GANG_PAGES])
AC_MSG_RESULT([$sym_addr])
])

# -- TRY_TO_FREE_MEM_CGROUP_PAGES
AC_DEFUN([LVE_SYM_TRY_TO_FREE_MEM_CGROUP_PAGES],[
AC_MSG_CHECKING([try_to_free_mem_cgroup_pages exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
	#include <linux/swap.h>
],[
	unsigned long (*lve_sym)(struct mem_cgroup *memcg,
				unsigned long nr_pages,
				gfp_t gfp_mask,
				bool noswap);

	lve_sym = try_to_free_mem_cgroup_pages;
],[
	LVE_SYM_ADDR(try_to_free_mem_cgroup_pages)
	if test $sym_addr != "0x0"; then
		SYM_TRY_TO_FREE_MEM_CGROUP_PAGES="lve_try_to_free_mem_cgroup_pages = $sym_addr;"
		AC_DEFINE(HAVE_TRY_TO_FREE_MEM_CGROUP_PAGES, [], [try_to_free_mem_cgroup_pages exists])
	fi
],[
	sym_addr=0
])

AC_SUBST([SYM_TRY_TO_FREE_MEM_CGROUP_PAGES])
AC_MSG_RESULT([$sym_addr])
])


# -- MEM_CGROUP_FROM_CONT
AC_DEFUN([LVE_SYM_MEM_CGROUP_FROM_CONT],[
AC_MSG_CHECKING([mem_cgroup_from_cont exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/memcontrol.h>
],[
	struct mem_cgroup *(*lve_sym)(struct cgroup *cont);

	lve_sym = mem_cgroup_from_cont;
],[
	LVE_SYM_ADDR(mem_cgroup_from_cont)
	if test $sym_addr != "0x0"; then
		SYM_MEM_CGROUP_FROM_CONT="lve_mem_cgroup_from_cont = $sym_addr;"
		AC_DEFINE(HAVE_MEM_CGROUP_FROM_CONT, [], [mem_cgroup_from_cont exists])
	fi
],[
	sym_addr=0
])

AC_SUBST([SYM_MEM_CGROUP_FROM_CONT])
AC_MSG_RESULT([$sym_addr])
])

# -- TASKLIST_LOCK
AC_DEFUN([LVE_SYM_TASKLIST_LOCK],[
AC_MSG_CHECKING([tasklist_lock exists in kernel])
	LVE_SYM_ADDR(tasklist_lock)
	if test $sym_addr != "0x0"; then
		SYM_TASKLIST_LOCK="tasklist_lock = $sym_addr;"
		AC_DEFINE(HAVE_TASKLIST_LOCK, [], [tasklist_lock exists])
	fi
AC_SUBST([SYM_TASKLIST_LOCK])
AC_MSG_RESULT([$sym_addr])
])

# -- SWITCH_TASK_NS
AC_DEFUN([LVE_SYM_SWITCH_TASK_NS],[
AC_MSG_CHECKING([switch_task_namespaces exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/nsproxy.h>
],[
	void (*lve_sym)(struct task_struct *tsk, struct nsproxy *new);

	lve_sym = switch_task_namespaces;
],[
	LVE_SYM_ADDR(switch_task_namespaces)
	if test $sym_addr != "0x0"; then
		SYM_SWITCH_TASK_NS="switch_task_namespaces = $sym_addr;"
	fi
],[
	sym_addr=0
])

AC_SUBST([SYM_SWITCH_TASK_NS])
AC_MSG_RESULT([$sym_addr])
])

# -- FREE_NSPROXY
AC_DEFUN([LVE_SYM_FREE_NSPROXY],[
AC_MSG_CHECKING([free_nsproxy exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/nsproxy.h>
],[
	void (*lve_sym)(struct nsproxy *p);

	lve_sym = free_nsproxy;
],[
	LVE_SYM_ADDR(free_nsproxy)
	if test $sym_addr != "0x0"; then
		SYM_FREE_NSPROXY="free_nsproxy = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FREE_NSPROXY])
AC_MSG_RESULT([$sym_addr])
])

# -- COPY_NAMESPACES - prototype checked before
AC_DEFUN([LVE_SYM_COPY_NAMESPACES],[
AC_MSG_CHECKING([copy_namespaces export from kernel ])
	LVE_SYM_ADDR(copy_namespaces)
	if test $sym_addr != "0x0"; then
		SYM_COPY_NAMESPACES="copy_namespaces = $sym_addr;"
	fi
AC_SUBST([SYM_COPY_NAMESPACES])
AC_MSG_RESULT([$sym_addr])
])

# -- NETWORK TRAFFIC CONTROL
AC_DEFUN([LVE_TRAF_CONTROL],[
AC_MSG_CHECKING([network traffic control exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/virtinfo.h>
],[
	int rc;

	rc = VIRTINFO_TRAF_IN_ACCOUNT | VIRTINFO_TRAF_OUT_ACCOUNT | VIRTINFO_TRAF_OUT_MARK;
],[
	AC_DEFINE(HAVE_LVE_TRAF_CONTROL, [], [network traffic control exists])
	AC_MSG_RESULT(yes)
],[
	AC_MSG_RESULT(no)
])
])

AC_DEFUN([LVE_PORT_CONTROL],[
AC_MSG_CHECKING([virtinfo.h has VIRTINFO_SOCKADDR])
LVE_LINUX_TRY_COMPILE([
	#include <linux/virtinfo.h>
],[
	int rc;

	rc = VIRTINFO_SOCKADDR;
],[
	AC_DEFINE(HAVE_LVE_PORT_CONTROL, [], [network tcp port control exists])
	AC_MSG_RESULT(yes)
],[
	AC_MSG_RESULT(no)
])
])

AC_DEFUN([LVE_CHECK_1ARG_CGROUP_POST_FORK],[
AC_MSG_CHECKING([cgroup_post_fork has 1 arg])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
],[
	cgroup_post_fork(NULL);
],[
	AC_DEFINE(HAVE_CGROUP_POST_FORK_WITH_1ARG, 1, [cgroup_post_fork has 1 arg])
	AC_MSG_RESULT(yes)
],[
	AC_MSG_RESULT(no)
])
])

AC_DEFUN([LVE_CHECK_2ARGS_CGROUP_POST_FORK],[
AC_MSG_CHECKING([cgroup_post_fork has 2 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
],[
	void *ss_priv[CGROUP_CANFORK_COUNT];
	cgroup_post_fork(NULL, ss_priv);
],[
	AC_DEFINE(HAVE_CGROUP_POST_FORK_WITH_2ARGS, 1, [cgroup_post_fork has 2 args])
	AC_MSG_RESULT(yes)
],[
	AC_MSG_RESULT(no)
])
])

# resolve symbols into addresses
# todo: add kernel<>symbol present verification, fail if symbol not present
#       templates for a symbols
#       symplify with other configure checks
AC_DEFUN([LVE_SYMBOLS],[
#common
	LVE_SYM_FS_PWD
	LVE_SYM_FS_ROOT
	LVE_TRAF_CONTROL
	LVE_PORT_CONTROL
#el6
	LVE_SYM_COPY_FS
	LVE_SYM_FREEZER_CHANGE_STATE
	LVE_SYM_TRY_TO_FREE_GANG_PAGES
	LVE_SYM_CSS_SET_LOCK
#el7
	LVE_SYM_UB_SYNC_MEMCG
	LVE_SYM_UB_CGROUP_MNT
	LVE_SYM_CGROUP_ITER_START
	LVE_SYM_CGROUP_ITER_NEXT
	LVE_SYM_CGROUP_ITER_END
	LVE_SYM_CGROUP_ATTACH_TASK
	LVE_2ARGS_CGROUP_ATTACH_TASK
	LVE_SYM_CGROUP_MUTEX
	LVE_SYM_TRY_TO_FREE_MEM_CGROUP_PAGES
	LVE_SYM_MEM_CGROUP_FROM_CONT
	LVE_SYM___FPUT

#un-patched RH
	LVE_SYM_CGROUP_KERNEL_ATTACH
	LVE_SYM_FREE_FS_STRUCT
	LVE_SYM_TASKLIST_LOCK
	LVE_SYM_SWITCH_TASK_NS
	LVE_SYM_FREE_NSPROXY
	LVE_SYM_COPY_NAMESPACES
	
#unpathced VZ
	LVE_VE_CLEANUP_CHAIN
	LVE_SYM_UB_SNAPSHOT
	LVE_SYM_UB_SETLIMIT

	LVE_SYM_FIND_TASK_BY_VPID
	LVE_SYM_UB_ATTACH_TASK
	LVE_SYM_UB_GET_CSS
	LVE_SYM_UB_ATTACH
	LVE_SYM_GET_BEANCOUNTER_BYUID
	LVE_SYM_GET_BEANCOUNTER_BY_NAME
	LVE_SYM_UB_CGROUP_ROOT
])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE

# Checks for library functions.

# Compiler settings

# Other settings
AC_MSG_CHECKING([for linux sources dir])
AC_ARG_WITH([kernel],
        [AC_HELP_STRING([--with-kernel=path], [set path to linux sources])],
        [KERNEL=$with_kernel],
        [KERNEL=/lib/modules/`uname -r`/build]
)
AC_MSG_RESULT([$KERNEL])
AC_SUBST([KERNEL])

AC_MSG_CHECKING([for linux objects dir])
AC_ARG_WITH([kernel-obj],
        [AC_HELP_STRING([--with-kernel-obj=path], [set path to linux objects dir])],
                [KERNEL_OBJ=$with_kernel_obj],
                [KERNEL_OBJ=$KERNEL]
)
AC_MSG_RESULT([$KERNEL_OBJ])
AC_SUBST([KERNEL_OBJ])

AC_MSG_CHECKING([for build id - ])
BID=$(git describe --tags)
SWV=${BID%-*}
AC_SUBST(SWV)
AC_DEFINE_UNQUOTED(SWV, "$SWV", [nearest lve version tag])

GIT=$(git log | awk '{print $2; exit}')
AC_DEFINE_UNQUOTED(GIT_HASH, "$GIT", [git hash for build])
AC_SUBST(GIT)
AC_MSG_RESULT([$SWV - $GIT])

PWD=$(pwd)
PWD="${PWD}/src"
COMMON=$(cd ../common; pwd)
AC_SUBST(PWD)
AC_SUBST(COMMON)

DEBUG_FL="-DSTRICT_LA -g"
AC_ARG_ENABLE([debug],
	[AC_HELP_STRING([--enable-debug], [enable debug features])],
	[DEBUG_FL="$DEBUG_FL -DLVE_DEBUG=-1"])
AC_SUBST(DEBUG_FL)

LVE_PER_VE=""
AC_ARG_ENABLE([lve-per-ve],
	[AC_HELP_STRING([--enable-lve-per-ve], [enable lve per ve support])],
	[LVE_PER_VE="-DLVE_PER_VE"])
AC_SUBST(LVE_PER_VE)

LVE_LINUX_INIT_CONFIG
LVE_LINUX_SYMVER
LVE_LINUX_MAPFILE

CGROUP=0
OPENVZ=0
rhver=$(awk '/RHEL_MAJOR =/ {print [$]3;}' $KERNEL/Makefile)
LVE_LINUX_CONFIG(CONFIG_CGROUPS, CGROUP=1)
LVE_LINUX_CONFIG(CONFIG_BEANCOUNTERS, OPENVZ=$rhver)
AC_SUBST(CGROUP)
AC_SUBST(OPENVZ)

AC_DEFINE_UNQUOTED([OPENVZ_VERSION], [$OPENVZ], [OpenVZ kernel version])

LVE_DO_EACH_THREAD_ALL
LVE_IN_UB_MEMCG_ATTACH

LVE_LINUX_CHECK_SYMBOL([proc_root], 
			[AC_DEFINE([HAVE_PROC_ROOT], [], [proc_root exist on kernel])])

LVE_LINUX_CHECK_SYMBOL([loadavg_ptr_init],
			[AC_DEFINE([HAVE_LOADAVG_PTR], [], [new loadavg hook])])

# ub_set_shortage_cb is "static inline" function so we can't use LVE_LINUX_CHECK_SYMBOL
AC_MSG_CHECKING([for ub_set_shortage_cb exist])
LVE_LINUX_TRY_COMPILE([
    #include <bc/beancounter.h>
    static struct user_beancounter ub; // too big to store it on stack
    static void cb(struct user_beancounter * ubc, int resource) {}
],[
    ub_set_shortage_cb(&ub, cb);
],[
    AC_MSG_RESULT(yes)
    AC_DEFINE([HAVE_UB_SHORTAGE_CB], [1], [user beancounter shortage callback])
],[
    AC_MSG_RESULT(no)
])

# -- UB_CGROUP
AC_MSG_CHECKING([ub_cgroup in struct user_beancounter])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	struct user_beancounter ub;
	ub.ub_cgroup = NULL;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_UB_CGROUP], [], [have ub_cgroup in struct user_beancounter])
],[
	AC_MSG_RESULT(no)
])

# -- PROC_ROOT
AC_MSG_CHECKING([proc_root in struct ve_struct])
LVE_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
	#include <linux/ve.h>
],[
	struct ve_struct ve;
	ve.proc_root = NULL;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_VE_PROC_ROOT], [], [have proc_root in struct ve_struct])
],[
	AC_MSG_RESULT(no)
])

# -- VE_TASK_INFO
AC_MSG_CHECKING([ve_task_info in struct task_struct])
LVE_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
	#include <linux/ve.h>
],[
	struct task_struct task;
	task.ve_task_info.owner_env->proc_root = NULL;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_VE_TASK_INFO], [], [have ve_task_info in struct task_struct])
],[
	AC_MSG_RESULT(no)
])

# -- HAVE_DENTRY_OPEN_PATH
AC_MSG_CHECKING([dentry_open uses path as parameter])
LVE_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	#include <linux/path.h>
	#include <linux/file.h>
],[
	struct file *file;
	file = dentry_open((const struct path *)0, 0, NULL);
],[
	AC_DEFINE(HAVE_DENTRY_OPEN_PATH, 1, [dentry_open has path parameter])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE_VFS_RENAME_WITH_6ARGS
AC_MSG_CHECKING([vfs_rename has 6 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	vfs_rename(NULL, NULL, NULL, NULL, NULL, 0);
],[
	AC_DEFINE(HAVE_VFS_RENAME_WITH_6ARGS, 1, [vfs_rename has 6 args])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE_VFS_RENAME_WITH_5ARGS
AC_MSG_CHECKING([vfs_rename has 5 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	vfs_rename(NULL, NULL, NULL, NULL, NULL);
],[
	AC_DEFINE(HAVE_VFS_RENAME_WITH_5ARGS, 1, [vfs_rename has 5 args])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE_COPY_NS_WITH_2ARGS
AC_MSG_CHECKING([copy_namespaces has 2 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/nsproxy.h>
],[
	copy_namespaces(0UL, NULL);
],[
	AC_DEFINE(HAVE_COPY_NS_WITH_2ARGS, 1, [copy_namespaces has 2 args])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE_COPY_NS_WITH_3ARGS
AC_MSG_CHECKING([copy_namespaces has 3 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/nsproxy.h>
],[
	copy_namespaces(0UL, NULL, -1);
],[
	AC_DEFINE(HAVE_COPY_NS_WITH_3ARGS, 1, [copy_namespaces has 3 args])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE_WAIT_BIT_4ARGS
AC_MSG_CHECKING([wait_on_bit have 4 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/wait.h>
],[
	wait_on_bit(NULL, 0, NULL, 0);
],[
	AC_DEFINE(HAVE_WAIT_BIT_4ARGS, 1, [wait_on_bit have 4 args])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE_BSEARCH
AC_MSG_CHECKING([bsearch exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/bsearch.h>
],[
	bsearch(NULL, NULL, 0, 0, NULL);
],[
	AC_DEFINE(HAVE_BSEARCH, 1, [bsearch exist in kernel])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE SUB UBC
AC_MSG_CHECKING([sub ubc exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	get_sub_beancounter_by_name(NULL, 10, 1);
],[
	AC_DEFINE(HAVE_SUB_UBC, 1, [sub ubc exist in kernel])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

# -- HAVE PROC EXIT CONNECTOR
AC_MSG_CHECKING([proc_exit_connector properly defined in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cn_proc.h>
],[
	struct task_struct *tsk = NULL;
	proc_exit_connector(tsk);
],[
	AC_DEFINE(HAVE_PROC_EXIT_CONNECTOR, 1, [proc_exit_connector properly defined in kernel])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])

LVE_EXEC_NOTIFIER
LVE_UB_SETLIMIT_BY_ID
LVE_CRED_EUID_IS_PLAIN

LVE_CHECK_1ARG_CGROUP_POST_FORK
LVE_CHECK_2ARGS_CGROUP_POST_FORK

LVE_SYMBOLS
# Output
AC_CONFIG_FILES([src/Makefile src/mod_info.h src/ld/lve.ldscript])
AC_OUTPUT
