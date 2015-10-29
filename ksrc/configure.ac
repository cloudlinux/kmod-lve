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
AC_CONFIG_HEADER([src/lve_kmod_c.h])

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

AC_DEFUN([LVE_3ARGS_COPY_MNT_NS], [
AC_MSG_CHECKING([check copy_mnt_ns has 3 args])
LVE_LINUX_TRY_COMPILE([
	#include <linux/nsproxy.h>
	#include <linux/mnt_namespace.h>
],[
	copy_mnt_ns(NULL, NULL, NULL);
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_3ARGS_COPY_MNT_NS, 1,
		[copy_mnt_ns has 3 args])
],[
	AC_MSG_RESULT(NO)
])
])

AC_DEFUN([LVE_EXEC_NOTIFIER],[
AC_MSG_CHECKING([virtinfo.h has VIRTINFO_EXEC])
LVE_LINUX_TRY_COMPILE([
        #include <linux/virtinfo.h>
],[
	int v = VIRTINFO_EXEC;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_EXEC_NOTIFIER, 1,
                  [virtinfo.h has VIRTINFO_EXEC])
],[
        AC_MSG_RESULT(NO)
])
])

AC_DEFUN([LVE_BC_FORK_SUB],[
AC_MSG_CHECKING([bc_fork_sub exist in kernel])
LVE_LINUX_TRY_COMPILE([
        #include <include/bc/task.h.h>
],[
        struct task_beancounter bc;
        
        bc.fork_sub = NULL;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_BC_FORK_SUB, 1,
                  [bc have a fork_sub exist CL patch])
],[
        AC_MSG_RESULT(NO)
])
])

AC_DEFUN([LVE_UB_HAS_RL_STEP],[
AC_MSG_CHECKING([ub->rl_step exists in kernel])
LVE_LINUX_TRY_COMPILE([
        #include <bc/beancounter.h>
],[
        struct user_beancounter bc;

        bc.rl_step = 0;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_UB_RL_STEP, 1,
                  [ub->rl_step defined])
],[
        AC_MSG_RESULT(NO)
])
])

AC_DEFUN([LVE_PATH_LOOKUP],[
AC_MSG_CHECKING([path_lookup exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/namei.h>
],[
	int rc = path_lookup(NULL, 0, NULL);
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_PATH_LOOKUP, 1,
		[path_lookup is exported])
],[
	AC_MSG_RESULT(no)
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

AC_DEFUN([LVE_SYM_SYM_GET],[
AC_MSG_CHECKING([__symbol_get exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/module.h>
],[
	void (*lve_sym)(const char *p) = __symbol_get;
],[
	LVE_SYM_ADDR(__symbol_get)
	if test $sym_addr != "0x0"; then
		SYM_SYM_GET="lve_sym_get = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_SYM_GET])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_COPY_FS],[
AC_MSG_CHECKING([copy_fs_struct exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
],[
	struct fs_struct *(*lve_copy_fs_struct)(struct fs_struct *) = copy_fs_struct;
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

AC_DEFUN([LVE_SYM_FS_PUT],[
AC_MSG_CHECKING([put_fs_struct exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
],[
	void (*lve_fs_put)(struct fs_struct *) = put_fs_struct;
],[
	LVE_SYM_ADDR(put_fs_struct)
	if test $sym_addr != "0x0"; then
		SYM_FS_PUT="lve_fs_put = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FS_PUT])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_FS_PWD],[
AC_MSG_CHECKING([set_fs_pwd exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
],[
#ifdef HAVE_3ARGS_FS_SET_ROOT
	void (*lve_set_fs_pwd)(struct fs_struct *, struct vfsmount *, struct dentry *) = set_fs_pwd
#else
	void (*lve_set_fs_pwd)(struct fs_struct *, struct path *) = set_fs_pwd;
#endif
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
	void (*lve_set_fs_root)(struct fs_struct *, struct path *) = set_fs_root;
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

AC_DEFUN([LVE_SYM_JPROBE_RET],[
AC_MSG_CHECKING([jprobe_return exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kprobes.h>
],[
	void *(*lve_jprobe_ret)(void) = jprobe_return;
],[
	LVE_SYM_ADDR(jprobe_return)
	if test $sym_addr != "0x0"; then
		SYM_JPROBE_RET="lve_jprobe_ret = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_JPROBE_RET])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_JPROBES_REG],[
AC_MSG_CHECKING([register_jprobes exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kprobes.h>
],[
	int (*lve_jprobes_reg)(struct jprobe **p, int num) = register_jprobes;
],[
	LVE_SYM_ADDR(register_jprobes)
	if test $sym_addr != "0x0"; then
		SYM_JPROBES_REG="lve_jprobes_reg = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_JPROBES_REG])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_JPROBES_UNREG],[
AC_MSG_CHECKING([unregister_jprobes exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kprobes.h>
],[
	void (*lve_jprobes_unreg)(struct jprobe **p, int num) = unregister_jprobes;
],[
	LVE_SYM_ADDR(unregister_jprobes)
	if test $sym_addr != "0x0"; then
		SYM_JPROBES_UNREG="lve_jprobes_unreg = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_JPROBES_UNREG])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_NS_PUT_FINAL],[
AC_MSG_CHECKING([__put_namespace exist in kernel])
LVE_LINUX_TRY_COMPILE([
		#include <linux/namespace.h>
],[
	void (*lve_ns_put_final)(struct namespace *namespace) = __put_namespace;
],[
	LVE_SYM_ADDR(__put_namespace)
	if test $sym_addr != "0x0"; then
		SYM_NS_PUT_FINAL="lve_ns_put_final = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_NS_PUT_FINAL])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_TASK_PUT_FINAL],[
AC_MSG_CHECKING([__put_task_struct exist in kernel])
LVE_LINUX_TRY_COMPILE([
		#include <linux/sched.h>
],[
	void (*lve_task_put_final)(struct task_struct *arg) = __put_task_struct;
],[
	LVE_SYM_ADDR(__put_task_struct)
	if test $sym_addr != "0x0"; then
		SYM_TASK_PUT_FINAL="lve_task_put_final = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_TASK_PUT_FINAL])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_NSPROXY_DUP],[
AC_MSG_CHECKING([duplicate_nsproxy exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/nsproxy.h>
],[
	struct nsproxy *(*lve_sym)(struct nsproxy *) = duplicate_nsproxy;
],[
	LVE_SYM_ADDR(duplicate_nsproxy)
	if test $sym_addr != "0x0"; then
		SYM_NSPROXY_DUP="lve_nsproxy_dup = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_NSPROXY_DUP])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_NS_SWITCH],[
AC_MSG_CHECKING([switch_task_namespaces exist in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/nsproxy.h>
],[
	struct nsproxy *(*lve_switch_ns)(struct nsproxy *, struct task *) = switch_task_namespaces;
],[
	LVE_SYM_ADDR(switch_task_namespaces)
	if test $sym_addr != "0x0"; then
		SYM_SWITCH_NS="lve_switch_ns = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_SWITCH_NS])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_FTRACE_PRINTK],[
AC_MSG_CHECKING([__ftrace_vprintk in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kernel.h>
],[
	int (*lve_sym)(unsigned long ip, const char *fmt, va_list ap) = __ftrace_vprintk;
],[
	LVE_SYM_ADDR(__ftrace_vprintk)
	if test $sym_addr != "0x0"; then
		SYM_FTRACE_VPRINTK="lve_vprintk = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FTRACE_VPRINTK])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_CSS_PUT],[
AC_MSG_CHECKING([__css_put in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/cgroup.h>
],[
	void (*lve_sym)(struct cgroup_subsys_state *css) = __css_put;
],[
	LVE_SYM_ADDR(__css_put)
	if test $sym_addr != "0x0"; then
		SYM_CSS_PUT="__css_put = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_CSS_PUT])
AC_MSG_RESULT([$sym_addr])
])

AC_DEFUN([LVE_SYM_COPY_MNT_NS],[
AC_MSG_CHECKING([copy_mnt_ns in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
	#include <linux/nsproxy.h>
	#include <linux/mnt_namespace.h>
	#include <linux/user_namespace.h>
],[

#ifdef HAVE_3ARGS_COPY_MNT_NS
	struct mnt_namespace * (*lve_sym)(unsigned long flags, struct mnt_namespace *ns,
		struct fs_struct *new_fs) = copy_mnt_ns;
#else
	struct mnt_namespace * (*lve_sym)(unsigned long flags, struct mnt_namespace *ns,
		struct user_namespace *us, struct fs_struct *new_fs) = copy_mnt_ns;
#endif
],[
	LVE_SYM_ADDR(copy_mnt_ns)
	if test $sym_addr != "0x0"; then
		SYM_COPY_MNT_NS="_lve_copy_mnt_ns = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_COPY_MNT_NS])
AC_MSG_RESULT([$sym_addr])
])


# -- TASKLIST_LOCK
AC_DEFUN([LVE_SYM_TASKLIST_LOCK],[
AC_MSG_CHECKING([tasklist_lock exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kernel.h>
	#include <linux/sched.h>
],[
	rwlock_t sym_addr = tasklist_lock;
],[
	LVE_SYM_ADDR(tasklist_lock)
	if test $sym_addr != "0x0"; then
		SYM_TASKLIST_LOCK="lve_tasklist_lock = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_TASKLIST_LOCK])
AC_MSG_RESULT([$sym_addr])
])

# -- GET_FS_TYPE
AC_DEFUN([LVE_SYM_GET_FS_TYPE],[
AC_MSG_CHECKING([get_fs_type exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kernel.h>
	#include <linux/fs.h>
],[
	struct file_system_type *(*sym_addr)(const char *name) = get_fs_type;
],[
	LVE_SYM_ADDR(get_fs_type)
	if test $sym_addr != "0x0"; then
		SYM_GET_FS_TYPE="lve_get_fs_type = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_GET_FS_TYPE])
AC_MSG_RESULT([$sym_addr])
])

# -- VFS_KERN_MOUNT
AC_DEFUN([LVE_SYM_VFS_KERN_MOUNT],[
AC_MSG_CHECKING([vfs_kern_mount exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/module.h>
	#include <linux/fs.h>
	#include <linux/mount.h>
],[
	struct vfsmount *(*lve_sym)(struct file_system_type *type, int flags, const char *name, void *p) = vfs_kern_mount;
],[
	LVE_SYM_ADDR(vfs_kern_mount)
	if test $sym_addr != "0x0"; then
		SYM_VFS_KERN_MOUNT="lve_vfs_kern_mount = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_VFS_KERN_MOUNT])
AC_MSG_RESULT([$sym_addr])
])

# -- CHECK_FOR_RELEASE
AC_DEFUN([LVE_SYM_CHECK_FOR_RELEASE],[
AC_MSG_CHECKING([check_for_release exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kernel.h>
	#include <linux/cgroup.h>
],[
	void (*lve_sym)(struct cgroup *cgrp) = 0x0;
],[
	LVE_SYM_ADDR(check_for_release)
	if test $sym_addr != "0x0"; then
		SYM_CHECK_FOR_RELEASE="lve_check_for_release = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_CHECK_FOR_RELEASE])
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
	int (*lve_sym)(struct cgroup *cgrp, struct task_struct *tsk) = cgroup_kernel_attach;
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
	void (*lve_sym)(struct fs_struct *fs) = free_fs_struct;
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

# -- PUT_MNT_NS
AC_DEFUN([LVE_SYM_PUT_MNT_NS],[
AC_MSG_CHECKING([put_mnt_ns exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/module.h>
	#include <linux/nsproxy.h>
	#include <linux/mnt_namespace.h>
],[
	int (*lve_sym)(struct mnt_namespace *ns) = put_mnt_ns;
],[
	LVE_SYM_ADDR(put_mnt_ns)
	if test $sym_addr != "0x0"; then
		SYM_PUT_MNT_NS="lve_put_mnt_ns = $sym_addr;"
		AC_DEFINE([HAVE_PUT_MNT_NS], [], [put_mnt_ns])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_PUT_MNT_NS])
AC_MSG_RESULT([$sym_addr])
])

# -- FREE_NSPROXY
AC_DEFUN([LVE_SYM_FREE_NSPROXY],[
AC_MSG_CHECKING([free_nsproxy exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/module.h>
	#include <linux/nsproxy.h>
],[
	void (*lve_sym)(struct nsproxy *ns) = free_nsproxy;
],[
	LVE_SYM_ADDR(free_nsproxy)
	if test $sym_addr != "0x0"; then
		SYM_FREE_NSPROXY="lve_free_nsproxy = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_FREE_NSPROXY])
AC_MSG_RESULT([$sym_addr])
])

# OpenVZ-el6 ub_precharge_snapshot
AC_DEFUN([LVE_SYM_UB_SNAPSHOT],[
AC_MSG_CHECKING([ub_precharge_snapshot exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	void (*lve_sym)(struct user_beancounter *ub, int *precharge) = ub_precharge_snapshot;
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

# -- UMOUNT_TREE
AC_DEFUN([LVE_SYM_UMOUNT_TREE],[
AC_MSG_CHECKING([umount_tree exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/kernel.h>
	#include <linux/fs.h>
	#include <linux/mount.h>
],[
	void (*lve_sym)(struct vfsmount *mnt, int propagate, struct list_head *kill) = 0x0;
],[
	LVE_SYM_ADDR(umount_tree)
	if test $sym_addr != "0x0"; then
		SYM_UMOUNT_TREE="lve_umount_tree = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_UMOUNT_TREE])
AC_MSG_RESULT([$sym_addr])
])

# -- RELEASE_MOUNTS
AC_DEFUN([LVE_SYM_RELEASE_MOUNTS],[
AC_MSG_CHECKING([release_mounts exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/list.h>
],[
	void (*lve_sym)(struct list_head *head) = 0x0;
],[
	LVE_SYM_ADDR(release_mounts)
	if test $sym_addr != "0x0"; then
		SYM_RELEASE_MOUNTS="lve_release_mounts = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_RELEASE_MOUNTS])
AC_MSG_RESULT([$sym_addr])
])

# -- VFSMOUNT_LOCK
AC_DEFUN([LVE_SYM_VFSMOUNT_LOCK],[
AC_MSG_CHECKING([vfsmount_lock exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/mount.h>
	#include <linux/spinlock.h>
],[
	spinlock_t sym_addr = vfsmount_lock;
],[
	LVE_SYM_ADDR(vfsmount_lock)
	if test $sym_addr != "0x0"; then
		SYM_VFSMOUNT_LOCK="lve_vfsmount_lock = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_VFSMOUNT_LOCK])
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

# -- FIND_TASK_BY_VPID
AC_DEFUN([LVE_SYM_FIND_TASK_BY_VPID],[
AC_MSG_CHECKING([find_task_by_vpid exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <linux/pid.h>
	#include <linux/sched.h>
],[
	struct task_struct *(*lve_sym)(pid_t nr) = find_task_by_vpid;
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
	int (*lve_sym)(struct user_beancounter *ub, struct task_struct *task) = ub_attach_task;
],[
	LVE_SYM_ADDR(ub_attach_task)
	if test $sym_addr != "0x0"; then
		SYM_UB_ATTACH_TASK="_lve_ub_attach_task = $sym_addr;"
		AC_DEFINE([HAVE_UB_ATTACH_TASK], [], [use ub_attach_task])
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
	int (*lve_sym)(struct user_beancounter *ub) = ub_attach;
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

# -- GET_BEANCOUNTER_BYUID
AC_DEFUN([LVE_SYM_GET_BEANCOUNTER_BYUID],[
AC_MSG_CHECKING([get_beancounter_byuid exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	struct user_beancounter *(*lve_sym)(uid_t uid, int create) = get_beancounter_byuid;
],[
	LVE_SYM_ADDR(get_beancounter_byuid)
	if test $sym_addr != "0x0"; then
		SYM_GET_BEANCOUNTER_BYUID="lve_get_beancounter_byuid = $sym_addr;"
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_GET_BEANCOUNTER_BYUID])
AC_MSG_RESULT([$sym_addr])
])

# -- MEM_CGROUP_ROOT
AC_DEFUN([LVE_SYM_MEM_CGROUP_ROOT],[
AC_MSG_CHECKING([mem_cgroup_root exists in kernel])
	LVE_SYM_ADDR(mem_cgroup_root)
	if test $sym_addr != "0x0"; then
		SYM_MEM_CGROUP_ROOT="lve_mem_cgroup_root = $sym_addr;"
		AC_DEFINE(HAVE_MEM_CGROUP_ROOT, 1,
			[mem_cgroup_root exists])
	fi
AC_SUBST([SYM_MEM_CGROUP_ROOT])
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
AC_MSG_CHECKING([VE_CLEANUP_CHAIN in ve_proto.h])
LVE_LINUX_TRY_COMPILE([
	#include <linux/ve_proto.h>
],[
	int chain = VE_CLEANUP_CHAIN;
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE([HAVE_VE_CLEANUP_CHAIN], [], [have ve_cleanup_chain in ve_proto.h])
],[
	AC_MSG_RESULT(no)
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

# -- UB_GET_MEM_CGROUP_PARMS
AC_DEFUN([LVE_SYM_UB_GET_MEM_CGROUP_PARMS],[
AC_MSG_CHECKING([ub_get_mem_cgroup_parms exists in kernel])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	void (*lve_sym)(struct user_beancounter *ub, struct ubparm *p, \
			struct ubparm *s, struct ubparm *k) = ub_get_mem_cgroup_parms;
],[
	LVE_SYM_ADDR(ub_get_mem_cgroup_parms)
	if test $sym_addr != "0x0"; then
		SYM_UB_GET_MEM_CGROUP_PARMS="lve_ub_get_mem_cgroup_parms = $sym_addr;"
		AC_DEFINE([HAVE_UB_GET_MEM_CGROUP_PARMS], [], [have ub_get_mem_cgroup_parms])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_UB_GET_MEM_CGROUP_PARMS])
AC_MSG_RESULT([$sym_addr])
])

# -- COMPAT_ALLOC_USER_SPACE
AC_DEFUN([LVE_COMPAT_ALLOC_USER_SPACE],[
AC_MSG_CHECKING([compat_alloc_user_space is exported])
LVE_LINUX_TRY_COMPILE([
	#include <linux/compat.h>
],[
	void __user *ptr = compat_alloc_user_space(1000);
],[
	LVE_SYM_ADDR(compat_alloc_user_space)
	if test $sym_addr != "0x0"; then
		SYM_COMPAT_ALLOC_USER_SPACE="lve_compat_alloc_user_space = $sym_addr;"
		AC_DEFINE([HAVE_COMPAT_ALLOC_USER_SPACE], [], [compat_alloc_user_space exported])
	fi
],[
	sym_addr=0
])
AC_SUBST([SYM_COMPAT_ALLOC_USER_SPACE])
AC_MSG_RESULT([$sym_addr])
])

# -- UB_SYNC_MEMCG
AC_DEFUN([LVE_SYM_UB_SYNC_MEMCG],[
AC_MSG_CHECKING([ub_sync_memcg is exported])
LVE_LINUX_TRY_COMPILE([
	#include <bc/beancounter.h>
],[
	void (*lve_sym)(struct user_beancounter *ub) = ub_sync_memcg;
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

# -- CREATE_NEW_NAMESPACES
AC_DEFUN([LVE_SYM_CREATE_NEW_NAMESPACES],[
AC_MSG_CHECKING([create_new_namespaces exists in kernel])
	LVE_SYM_ADDR(create_new_namespaces)
	if test $sym_addr != "0x0"; then
		SYM_CREATE_NEW_NAMESPACES="create_new_namespaces = $sym_addr;"
		AC_DEFINE(HAVE_CREATE_NEW_NAMESPACES, 1,
			[create_new_namespaces exists])
	fi
AC_SUBST([SYM_CREATE_NEW_NAMESPACES])
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

# -- UB_BOUND_CGROUP_MNT
AC_DEFUN([LVE_SYM_UB_BOUND_CGROUP_MNT],[
AC_MSG_CHECKING([ub_bound_cgroup_mnt exists in kernel])
	LVE_SYM_ADDR(ub_bound_cgroup_mnt)
	if test $sym_addr != "0x0"; then
		SYM_UB_BOUND_CGROUP_MNT="lve_ub_bound_cgroup_mnt = $sym_addr;"
		AC_DEFINE(HAVE_UB_BOUND_CGROUP_MNT, 1,
			[ub_bound_cgroup_mnt exists])
	fi
	AC_SUBST([SYM_UB_BOUND_CGROUP_MNT])
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
	int (*lve_sym)(struct cgroup *cg, struct task_struct *tsk) = cgroup_attach_task;
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

# resolve symbols into addresses
# todo: add kernel<>symbol present verification, fail if symbol not present
#       templates for a symbols
#       symplify with other configure checks
AC_DEFUN([LVE_SYMBOLS],[
#common
	LVE_SYM_SYM_GET
	LVE_SYM_JPROBE_RET
	LVE_SYM_JPROBES_REG
	LVE_SYM_JPROBES_UNREG
	LVE_SYM_TASK_PUT_FINAL
	LVE_SYM_FS_PWD
	LVE_SYM_FS_ROOT
#el5
	LVE_SYM_FS_PUT
	LVE_SYM_NS_PUT_FINAL
#el6
	LVE_SYM_COPY_FS
	LVE_SYM_NSPROXY_DUP
	LVE_SYM_NS_SWITCH
	LVE_SYM_FTRACE_PRINTK
#el7
	LVE_COMPAT_ALLOC_USER_SPACE
	LVE_SYM_CSS_PUT
	LVE_SYM_UB_SYNC_MEMCG
	LVE_SYM_CREATE_NEW_NAMESPACES
	LVE_SYM_UB_CGROUP_MNT
	LVE_SYM_UB_BOUND_CGROUP_MNT
	LVE_SYM_CGROUP_ITER_START
	LVE_SYM_CGROUP_ITER_NEXT
	LVE_SYM_CGROUP_ITER_END
	LVE_SYM_CGROUP_ATTACH_TASK
	LVE_2ARGS_CGROUP_ATTACH_TASK
	LVE_SYM_CGROUP_MUTEX

#un-patched RH
	LVE_SYM_TASKLIST_LOCK
	LVE_SYM_GET_FS_TYPE
	LVE_SYM_VFS_KERN_MOUNT
	LVE_SYM_CHECK_FOR_RELEASE
	LVE_SYM_CGROUP_KERNEL_ATTACH
	LVE_SYM_FREE_FS_STRUCT
	LVE_SYM_PUT_MNT_NS
	LVE_SYM_FREE_NSPROXY
	LVE_SYM_COPY_MNT_NS
	LVE_SYM_UMOUNT_TREE
	LVE_SYM_RELEASE_MOUNTS
	LVE_SYM_VFSMOUNT_LOCK

#unpathced VZ
	LVE_SYM_UB_SNAPSHOT
	LVE_SYM_UB_SETLIMIT

	LVE_SYM_FIND_TASK_BY_VPID
	LVE_SYM_UB_ATTACH_TASK
	LVE_SYM_UB_ATTACH
	LVE_SYM_GET_BEANCOUNTER_BYUID
	LVE_SYM_MEM_CGROUP_ROOT
	LVE_SYM_UB_CGROUP_ROOT
	LVE_SYM_UB_GET_MEM_CGROUP_PARMS
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
LVE_LINUX_CONFIG(CONFIG_CGROUPS, CGROUP=1)
LVE_LINUX_CONFIG(CONFIG_BEANCOUNTERS, OPENVZ=1)
AC_SUBST(CGROUP)
AC_SUBST(OPENVZ)

LVE_LINUX_INCLUDE([namespace.h], 
		  [AC_DEFINE([HAVE_NAMESPACE_H], [], [namespace.h exist on kernel])]) 

LVE_LINUX_INCLUDE([mnt_namespace.h], 
		  [AC_DEFINE([HAVE_MNT_NAMESPACE_H], [], [mnt_namespace.h exist on kernel])]) 

LVE_LINUX_INCLUDE([path.h],
		  [AC_DEFINE([HAVE_PATH_H], [], [path.h exists on kernel])])

LVE_DO_EACH_THREAD_ALL
LVE_IN_UB_MEMCG_ATTACH

# CL patched kernel
LVE_LINUX_CHECK_SYMBOL([dup_mnt_ns],
			[AC_DEFINE([HAVE_DUP_MNT_NS], [], [dup_mnt_ns exist on kernel])])

LVE_LINUX_CHECK_SYMBOL([proc_root], 
			[AC_DEFINE([HAVE_PROC_ROOT], [], [proc_root exist on kernel])])

# new NS API
LVE_LINUX_CHECK_SYMBOL([switch_task_namespaces],
			[AC_DEFINE([HAVE_SWITCH_NS], [], [switch_task_namespace exist on kernel])])

LVE_LINUX_CHECK_SYMBOL([find_task_by_pid_type_ve],
			[AC_DEFINE([HAVE_TASK_PID_TYPE_VE], [], [new pid API])])

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

LVE_3ARGS_COPY_MNT_NS
LVE_EXEC_NOTIFIER
LVE_BC_FORK_SUB
LVE_UB_SETLIMIT_BY_ID
LVE_PATH_LOOKUP
LVE_CRED_EUID_IS_PLAIN
LVE_UB_HAS_RL_STEP

LVE_SYMBOLS
# Output
AC_CONFIG_FILES([src/Makefile src/mod_info.h src/lve.ldscript])
AC_OUTPUT
