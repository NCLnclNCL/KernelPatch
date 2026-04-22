/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */
// [CKB-MOD] Anti side-channel G5: 与 supercall.c 保持一致
#define ANTI_SIDECHANNEL_V4G

// [CKB-MOD] G5: 统一函数指针类型（execve/fstatat/faccessat wrapper 共用）
#ifdef ANTI_SIDECHANNEL_V4G
typedef long (*orig_syscall_func_t)(long, long, long, long, long, long);
#endif
#include <linux/list.h>
#include <ktypes.h>
#include <compiler.h>
#include <stdbool.h>
#include <linux/syscall.h>
#include <ksyms.h>
#include <hook.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <stdbool.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <uapi/scdefs.h>
#include <kputils.h>
#include <linux/ptrace.h>
#include <accctl.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <taskob.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <syscall.h>
#include <predata.h>
#include <predata.h>
#include <kconfig.h>
#include <linux/vmalloc.h>
#include <sucompat.h>
#include <symbol.h>
#include <uapi/linux/limits.h>
#include <predata.h>
#include <kstorage.h>

const char sh_path[] = SH_PATH;
const char default_su_path[] = SU_PATH;

#ifdef ANDROID
const char legacy_su_path[] = LEGACY_SU_PATH;
const char apd_path[] = APD_PATH;
#endif

static const char *current_su_path = 0;

static int su_kstorage_gid = -1;
static int exclude_kstorage_gid = -1;

int is_su_allow_uid(uid_t uid)
{
    int rc = 0;
    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR_OR_NULL(ks) || ks->dlen <= 0) goto out;

    struct su_profile *profile = (struct su_profile *)ks->data;
    rc = profile->uid == uid;

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int su_add_allow_uid(uid_t uid, uid_t to_uid, const char *scontext)
{
    if (!scontext) scontext = "";
    struct su_profile profile = {
        uid,
        to_uid,
    };
    memcpy(profile.scontext, scontext, SUPERCALL_SCONTEXT_LEN);
    int rc = write_kstorage(su_kstorage_gid, uid, &profile, 0, sizeof(struct su_profile), false);
    logkfd("uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, scontext, rc);
    return rc;
}
KP_EXPORT_SYMBOL(su_add_allow_uid);

int su_remove_allow_uid(uid_t uid)
{
    return remove_kstorage(su_kstorage_gid, uid);
}
KP_EXPORT_SYMBOL(su_remove_allow_uid);

int su_allow_uid_nums()
{
    return kstorage_group_size(su_kstorage_gid);
}
KP_EXPORT_SYMBOL(su_allow_uid_nums);

static int allow_uids_cb(struct kstorage *kstorage, void *udata)
{
    struct
    {
        int is_user;
        uid_t *out_uids;
        int idx;
        int out_num;
    } *up = (typeof(up))udata;

    if (up->idx >= up->out_num) {
        return -ENOBUFS;
    }

    struct su_profile *profile = (struct su_profile *)kstorage->data;

    if (up->is_user) {
        int cprc = compat_copy_to_user(up->out_uids + up->idx, &profile->uid, sizeof(uid_t));
        if (cprc <= 0) {
            logkfd("compat_copy_to_user error: %d", cprc);
            return cprc;
        }
    } else {
        up->out_uids[up->idx] = profile->uid;
    }

    up->idx++;

    return 0;
}

int su_allow_uids(int is_user, uid_t *out_uids, int out_num)
{
    struct
    {
        int iu;
        uid_t *up;
        int idx;
        int out_num;
    } udata = { is_user, out_uids, 0, out_num };

    on_each_kstorage_elem(su_kstorage_gid, allow_uids_cb, &udata);

    return udata.idx;
}
KP_EXPORT_SYMBOL(su_allow_uids);

int su_allow_uid_profile(int is_user, uid_t uid, struct su_profile *out_profile)
{
    int rc = 0;

    rcu_read_lock();
    const struct kstorage *ks = get_kstorage(su_kstorage_gid, uid);
    if (IS_ERR(ks)) {
        rc = -ENOENT;
        goto out;
    }
    struct su_profile *profile = (struct su_profile *)ks->data;

    if (is_user) {
        rc = compat_copy_to_user(out_profile, profile, sizeof(struct su_profile));
        if (rc <= 0) {
            logkfd("compat_copy_to_user error: %d", rc);
            goto out;
        }
    } else {
        memcpy(out_profile, profile, sizeof(struct su_profile));
    }

out:
    rcu_read_unlock();
    return rc;
}
KP_EXPORT_SYMBOL(su_allow_uid_profile);

// no free, no lock
int su_reset_path(const char *path)
{
    if (!path) return -EINVAL;
    if (IS_ERR(path)) return PTR_ERR(path);
    current_su_path = path;
    logkfd("%s\n", current_su_path);
    dsb(ish);
    return 0;
}
KP_EXPORT_SYMBOL(su_reset_path);

const char *su_get_path()
{
    if (!current_su_path) current_su_path = default_su_path;
    return current_su_path;
}
KP_EXPORT_SYMBOL(su_get_path);

static void handle_before_execve(char **__user u_filename_p, char **__user uargv, void *udata)
{
    char __user *ufilename = *u_filename_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        uid_t uid = current_uid();
        struct su_profile profile;
        if (su_allow_uid_profile(0, uid, &profile)) return;

        uid_t to_uid = profile.to_uid;
        const char *sctx = profile.scontext;
        commit_su(to_uid, sctx);

#ifdef ANDROID
        struct file *filp = filp_open(apd_path, O_RDONLY, 0);
        if (!filp || IS_ERR(filp)) {
#endif
            void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
            if (uptr && !IS_ERR(uptr)) {
                *u_filename_p = (char *__user)uptr;
            }
            logkfi("call su uid: %d, to_uid: %d, sctx: %s, uptr: %llx\n", uid, to_uid, sctx, uptr);
#ifdef ANDROID
        } else {
            filp_close(filp, 0);

            // command
            uint64_t sp = 0;
            sp = current_user_stack_pointer();
            sp -= sizeof(apd_path);
            sp &= 0xFFFFFFFFFFFFFFF8;
            int cplen = compat_copy_to_user((void *)sp, apd_path, sizeof(apd_path));
            if (cplen > 0) {
                *u_filename_p = (char *)sp;
            }

            // argv
            int argv_cplen = 0;
            if (strcmp(legacy_su_path, filename)) {
                if (argv_cplen <= 0) {
                    sp = sp ?: current_user_stack_pointer();
                    sp -= sizeof(legacy_su_path);
                    sp &= 0xFFFFFFFFFFFFFFF8;
                    argv_cplen = compat_copy_to_user((void *)sp, legacy_su_path, sizeof(legacy_su_path));
                    if (argv_cplen > 0) {
                        int rc = set_user_arg_ptr(0, *uargv, 0, sp);
                        if (rc < 0) { // todo: modify entire argv
                            logkfi("call apd argv error, uid: %d, to_uid: %d, sctx: %s, rc: %d\n", uid, to_uid, sctx,
                                   rc);
                        }
                    }
                }
            }
            logkfi("call apd uid: %d, to_uid: %d, sctx: %s, cplen: %d, %d\n", uid, to_uid, sctx, cplen, argv_cplen);
        }
#endif // ANDROID
    } else if (!strcmp(SUPERCMD, filename)) {
        void handle_supercmd(char **__user u_filename_p, char **__user uargv);
        handle_supercmd(u_filename_p, uargv);
        return;
    }
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2107
// COMPAT_SYSCALL_DEFINE3(execve, const char __user *, filename,
// 	const compat_uptr_t __user *, argv,
// 	const compat_uptr_t __user *, envp)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2087
// SYSCALL_DEFINE3(execve, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp)

// =====================================================================
// [CKB-MOD] G7: execve fp_hook + KPM 回调注册机制（2026-04-11）
//
// 问题：execve 用 hook_syscalln 时，transit 框架有 ~40 cycles 固有开销。
//       IO_Redirect KPM 也 hook execve，两个 fp_hook 不能共存。
//
// 方案：sucompat 用 fp_hook 替换 execve，导出注册接口让 KPM 注册回调。
//       sucompat 的 wrapper 里依次调用所有注册的回调 + 自己的逻辑。
//       IO_Redirect 不再自己 hook execve，改为注册回调。
// =====================================================================
#ifdef ANTI_SIDECHANNEL_V4G

#define MAX_EXECVE_CALLBACKS 4

// KPM 注册的 execve before 回调
typedef void (*execve_before_callback_t)(void *args, void *udata);
static execve_before_callback_t g_execve_callbacks[MAX_EXECVE_CALLBACKS] = {};
static void *g_execve_cb_udata[MAX_EXECVE_CALLBACKS] = {};
static int g_execve_cb_count = 0;

// 注册 execve before 回调（KPM 模块调用）
int register_execve_before_hook(void *callback, void *udata)
{
    if (g_execve_cb_count >= MAX_EXECVE_CALLBACKS) return -1;
    g_execve_callbacks[g_execve_cb_count] = (execve_before_callback_t)callback;
    g_execve_cb_udata[g_execve_cb_count] = udata;
    g_execve_cb_count++;
    logkfi("registered execve callback[%d]: %llx\n", g_execve_cb_count - 1, (unsigned long long)callback);
    return 0;
}
KP_EXPORT_SYMBOL(register_execve_before_hook);

// 注销 execve before 回调
void unregister_execve_before_hook(void *callback)
{
    for (int i = 0; i < g_execve_cb_count; i++) {
        if ((void *)g_execve_callbacks[i] == callback) {
            // 移除：后面的前移
            for (int j = i; j < g_execve_cb_count - 1; j++) {
                g_execve_callbacks[j] = g_execve_callbacks[j + 1];
                g_execve_cb_udata[j] = g_execve_cb_udata[j + 1];
            }
            g_execve_cb_count--;
            logkfi("unregistered execve callback: %llx\n", (unsigned long long)callback);
            return;
        }
    }
}
KP_EXPORT_SYMBOL(unregister_execve_before_hook);

static void *g_orig_execve = NULL;
static void *g_orig_compat_execve = NULL;

// execve wrapper：调用 sucompat 逻辑和 KPM 回调
static long sucompat_execve_wrapper(long arg0, long arg1, long arg2,
                                     long arg3, long arg4, long arg5)
{
    // [CKB-MOD] G7: 不加 uid 预检查！
    // APatch Manager 第一次执行 truncate superkey 时，uid 可能还没在 su_allow_uid 列表里
    // （鸡生蛋问题：superkey 验证本身就是通过 execve truncate 完成的）
    // 踩坑记录：G4 和 G7 都因为 uid 预检查导致 APatch 崩溃

    // 调试计数器
    static unsigned long wrapper_count = 0;
    wrapper_count++;
    if ((wrapper_count % 5000) == 0) {
        logki("G7-debug: execve_wrapper called %lu times, uid=%d\n", wrapper_count, current_uid());
    }
    // 构造 fargs 结构给 KPM 回调使用
    hook_fargs3_t fargs;
    fargs.skip_origin = 0;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        fargs.arg0 = (uint64_t)regs->regs[0];
        fargs.arg1 = (uint64_t)regs->regs[1];
        fargs.arg2 = (uint64_t)regs->regs[2];
    } else {
        fargs.arg0 = (uint64_t)arg0;
        fargs.arg1 = (uint64_t)arg1;
        fargs.arg2 = (uint64_t)arg2;
    }

    // 1. sucompat 自己的逻辑
    void *arg0p, *arg1p;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        arg0p = &regs->regs[0];
        arg1p = &regs->regs[1];
    } else {
        arg0p = &arg0;
        arg1p = &arg1;
    }
    handle_before_execve((char **)arg0p, (char **)arg1p, (void *)0);

    // 2. KPM 注册的回调（如 IO_Redirect）
    for (int i = 0; i < g_execve_cb_count; i++) {
        if (g_execve_callbacks[i]) {
            g_execve_callbacks[i](&fargs, g_execve_cb_udata[i]);
        }
    }

    // 3. 检查是否有回调设置了 skip_origin
    if (fargs.skip_origin) {
        return fargs.ret;
    }

    // 4. 调用原始 execve
    return ((orig_syscall_func_t)g_orig_execve)(arg0, arg1, arg2, arg3, arg4, arg5);
}

// compat execve wrapper
static long sucompat_compat_execve_wrapper(long arg0, long arg1, long arg2,
                                            long arg3, long arg4, long arg5)
{
    hook_fargs3_t fargs;
    fargs.skip_origin = 0;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        fargs.arg0 = (uint64_t)regs->regs[0];
        fargs.arg1 = (uint64_t)regs->regs[1];
        fargs.arg2 = (uint64_t)regs->regs[2];
    } else {
        fargs.arg0 = (uint64_t)arg0;
        fargs.arg1 = (uint64_t)arg1;
        fargs.arg2 = (uint64_t)arg2;
    }

    void *arg0p, *arg1p;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        arg0p = &regs->regs[0];
        arg1p = &regs->regs[1];
    } else {
        arg0p = &arg0;
        arg1p = &arg1;
    }
    handle_before_execve((char **)arg0p, (char **)arg1p, (void *)1);

    for (int i = 0; i < g_execve_cb_count; i++) {
        if (g_execve_callbacks[i]) {
            g_execve_callbacks[i](&fargs, g_execve_cb_udata[i]);
        }
    }

    if (fargs.skip_origin) {
        return fargs.ret;
    }

    return ((orig_syscall_func_t)g_orig_compat_execve)(arg0, arg1, arg2, arg3, arg4, arg5);
}

#endif // ANTI_SIDECHANNEL_V4G

static void before_execve(hook_fargs3_t *args, void *udata)
{
    // [CKB-MOD] G5 调试：计数器，确认 Hunter 是否测 execve
    static unsigned long execve_count = 0;
    execve_count++;
    if ((execve_count % 5000) == 0) {
        logki("anti-sc-debug: before_execve called %lu times, uid=%d\n", execve_count, current_uid());
    }
    void *arg0p = syscall_argn_p(args, 0);
    void *arg1p = syscall_argn_p(args, 1);
    handle_before_execve((char **)arg0p, (char **)arg1p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2114
// COMPAT_SYSCALL_DEFINE5(execveat, int, fd,
// 		       const char __user *, filename,
// 		       const compat_uptr_t __user *, argv,
// 		       const compat_uptr_t __user *, envp,
// 		       int,  flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/exec.c#L2095
// SYSCALL_DEFINE5(execveat, int, fd, const char __user *, filename, const char __user *const __user *, argv,
//                 const char __user *const __user *, envp, int, flags)
__maybe_unused static void before_execveat(hook_fargs5_t *args, void *udata)
{
    void *arg1p = syscall_argn_p(args, 1);
    void *arg2p = syscall_argn_p(args, 2);
    handle_before_execve((char **)arg1p, (char **)arg2p, udata);
}

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L431
// SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,
// 		struct stat __user *, statbuf, int, flag)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L492
// SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)

// https://elixir.bootlin.com/linux/v6.1/source/fs/open.c#L497
// SYSCALL_DEFINE4(faccessat2, int, dfd, const char __user *, filename, int, mode, int, flags)

// https://elixir.bootlin.com/linux/v6.1/source/fs/stat.c#L661
// SYSCALL_DEFINE5(statx,
// 		int, dfd, const char __user *, filename, unsigned, flags,
// 		unsigned int, mask,
// 		struct statx __user *, buffer)
static void su_handler_arg1_ufilename_before(hook_fargs6_t *args, void *udata)
{
    // [CKB-MOD] G5 调试：计数器，确认 Hunter 是否测 fstatat/faccessat
    static unsigned long fstat_count = 0;
    fstat_count++;
    if ((fstat_count % 5000) == 0) {
        logki("anti-sc-debug: su_handler(fstatat/faccessat) called %lu times, uid=%d\n", fstat_count, current_uid());
    }

    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) return;

    char __user **u_filename_p = (char __user **)syscall_argn_p(args, 1);

    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, *u_filename_p, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr)) {
            *u_filename_p = uptr;
        } else {
            logkfi("su uid: %d, cp stack error: %d\n", uid, uptr);
        }
    }
}

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    int rc = 0;
    if (exclude) {
        rc = write_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    } else {
        rc = remove_kstorage(exclude_kstorage_gid, uid);
    }
    return rc;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    int exclude = 0;
    int rc = read_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    if (rc < 0) return 0;
    return exclude;
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int list_ap_mod_exclude(uid_t *uids, int len)
{
    long ids[len];
    int cnt = list_kstorage_ids(exclude_kstorage_gid, ids, len, false);
    for (int i = 0; i < len; i++) {
        uids[i] = (uid_t)ids[i];
    }
    return cnt;
}
KP_EXPORT_SYMBOL(list_ap_mod_exclude);

// =====================================================================
// [CKB-MOD] G5: fstatat/faccessat 直接替换 wrapper（2026-04-11）
//
// 绕过 transit 框架，消除 ~40 cycles 固有开销。
// 快速路径：uid 不在 su 授权列表 → 直接调用原始函数（零额外开销）
// 慢路径：uid 已授权 → 检查文件名是否是 su_path → 替换为 sh_path
// =====================================================================
#ifdef ANTI_SIDECHANNEL_V4G

// 原始函数指针（.data 段，可写）
static void *g_orig_fstatat = NULL;
static void *g_orig_faccessat = NULL;
static void *g_orig_compat_fstatat = NULL;
static void *g_orig_compat_faccessat = NULL;

// 慢路径：已授权 uid，检查文件名并替换
// 从 su_handler_arg1_ufilename_before 提取核心逻辑
static __noinline void sucompat_check_and_replace_path(long *arg1_p)
{
    char __user *ufilename = (char __user *)*arg1_p;
    char filename[SU_PATH_MAX_LEN];
    int flen = compat_strncpy_from_user(filename, ufilename, sizeof(filename));
    if (flen <= 0) return;

    if (!strcmp(current_su_path, filename)) {
        void *uptr = copy_to_user_stack(sh_path, sizeof(sh_path));
        if (uptr && !IS_ERR(uptr)) {
            *arg1_p = (long)uptr;
        }
    }
}

// 64 位 fstatat wrapper
static long sucompat_fstatat_wrapper(long arg0, long arg1, long arg2,
                                      long arg3, long arg4, long arg5)
{
    // 快速路径：非授权 uid 直接调用原始函数
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) {
        return ((orig_syscall_func_t)g_orig_fstatat)(arg0, arg1, arg2, arg3, arg4, arg5);
    }
    // 慢路径：检查并替换 su_path
    // fstatat(dfd, filename, statbuf, flag) — filename 是 arg1
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        sucompat_check_and_replace_path((long *)&regs->regs[1]);
    } else {
        sucompat_check_and_replace_path(&arg1);
    }
    return ((orig_syscall_func_t)g_orig_fstatat)(arg0, arg1, arg2, arg3, arg4, arg5);
}

// 64 位 faccessat wrapper
static long sucompat_faccessat_wrapper(long arg0, long arg1, long arg2,
                                        long arg3, long arg4, long arg5)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) {
        return ((orig_syscall_func_t)g_orig_faccessat)(arg0, arg1, arg2, arg3, arg4, arg5);
    }
    // faccessat(dfd, filename, mode) — filename 是 arg1
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        sucompat_check_and_replace_path((long *)&regs->regs[1]);
    } else {
        sucompat_check_and_replace_path(&arg1);
    }
    return ((orig_syscall_func_t)g_orig_faccessat)(arg0, arg1, arg2, arg3, arg4, arg5);
}

// 32 位 compat fstatat wrapper
static long sucompat_compat_fstatat_wrapper(long arg0, long arg1, long arg2,
                                             long arg3, long arg4, long arg5)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) {
        return ((orig_syscall_func_t)g_orig_compat_fstatat)(arg0, arg1, arg2, arg3, arg4, arg5);
    }
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        sucompat_check_and_replace_path((long *)&regs->regs[1]);
    } else {
        sucompat_check_and_replace_path(&arg1);
    }
    return ((orig_syscall_func_t)g_orig_compat_fstatat)(arg0, arg1, arg2, arg3, arg4, arg5);
}

// 32 位 compat faccessat wrapper
static long sucompat_compat_faccessat_wrapper(long arg0, long arg1, long arg2,
                                               long arg3, long arg4, long arg5)
{
    uid_t uid = current_uid();
    if (!is_su_allow_uid(uid)) {
        return ((orig_syscall_func_t)g_orig_compat_faccessat)(arg0, arg1, arg2, arg3, arg4, arg5);
    }
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        sucompat_check_and_replace_path((long *)&regs->regs[1]);
    } else {
        sucompat_check_and_replace_path(&arg1);
    }
    return ((orig_syscall_func_t)g_orig_compat_faccessat)(arg0, arg1, arg2, arg3, arg4, arg5);
}

#endif // ANTI_SIDECHANNEL_V4G

int su_compat_init()
{
    current_su_path = default_su_path;

    su_kstorage_gid = try_alloc_kstroage_group();
    if (su_kstorage_gid != KSTORAGE_SU_LIST_GROUP) return -ENOMEM;

    exclude_kstorage_gid = try_alloc_kstroage_group();
    if (exclude_kstorage_gid != KSTORAGE_EXCLUDE_LIST_GROUP) return -ENOMEM;

#ifdef ANDROID
    // default shell
    if (!all_allow_sctx[0]) {
        strcpy(all_allow_sctx, ALL_ALLOW_SCONTEXT_MAGISK);
    }
    su_add_allow_uid(2000, 0, all_allow_sctx);
    su_add_allow_uid(0, 0, all_allow_sctx);
#endif

    hook_err_t rc = HOOK_NO_ERR;

    uint8_t su_config = patch_config->patch_su_config;
    bool enable = !!(su_config & PATCH_CONFIG_SU_ENABLE);
    bool wrap = !!(su_config & PATCH_CONFIG_SU_HOOK_NO_WRAP);
    log_boot("su config: %x, enable: %d, wrap: %d\n", su_config, enable, wrap);

    // execve: G7 用 fp_hook + KPM 回调注册机制
#ifdef ANTI_SIDECHANNEL_V4G
    fp_hook((uintptr_t)(sys_call_table + __NR_execve),
            (void *)sucompat_execve_wrapper,
            (void **)&g_orig_execve);
    log_boot("G7 fp_hook __NR_execve, orig=%llx\n", (unsigned long long)(uintptr_t)g_orig_execve);
#else
    rc = hook_syscalln(__NR_execve, 3, before_execve, 0, (void *)0);
    log_boot("hook __NR_execve rc: %d\n", rc);
#endif

#ifdef ANTI_SIDECHANNEL_V4G
    // =====================================================================
    // [CKB-MOD] G5: fstatat/faccessat 改用 fp_hook 直接替换
    // 绕过 transit 框架，消除 ~40 cycles 固有开销
    // Hunter 测 fstatat/faccessat 延迟时走快速路径（uid 检查 + tail-call）
    // =====================================================================
    log_boot("sucompat G7: fp_hook ALL + execve callback registry for KPM\n");

    fp_hook((uintptr_t)(sys_call_table + __NR3264_fstatat),
            (void *)sucompat_fstatat_wrapper,
            (void **)&g_orig_fstatat);
    log_boot("G5 fp_hook __NR3264_fstatat, orig=%llx\n", (unsigned long long)(uintptr_t)g_orig_fstatat);

    fp_hook((uintptr_t)(sys_call_table + __NR_faccessat),
            (void *)sucompat_faccessat_wrapper,
            (void **)&g_orig_faccessat);
    log_boot("G5 fp_hook __NR_faccessat, orig=%llx\n", (unsigned long long)(uintptr_t)g_orig_faccessat);

    // 32 位 compat 表
    if (compat_sys_call_table) {
        fp_hook((uintptr_t)(compat_sys_call_table + 327),
                (void *)sucompat_compat_fstatat_wrapper,
                (void **)&g_orig_compat_fstatat);
        log_boot("G5 fp_hook compat fstatat64(327), orig=%llx\n", (unsigned long long)(uintptr_t)g_orig_compat_fstatat);

        fp_hook((uintptr_t)(compat_sys_call_table + 334),
                (void *)sucompat_compat_faccessat_wrapper,
                (void **)&g_orig_compat_faccessat);
        log_boot("G5 fp_hook compat faccessat(334), orig=%llx\n", (unsigned long long)(uintptr_t)g_orig_compat_faccessat);
    }
#else
    rc = hook_syscalln(__NR3264_fstatat, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR3264_fstatat rc: %d\n", rc);

    rc = hook_syscalln(__NR_faccessat, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook __NR_faccessat rc: %d\n", rc);
#endif
    // __NR_execve 11 (compat)
#ifdef ANTI_SIDECHANNEL_V4G
    if (compat_sys_call_table) {
        fp_hook((uintptr_t)(compat_sys_call_table + 11),
                (void *)sucompat_compat_execve_wrapper,
                (void **)&g_orig_compat_execve);
        log_boot("G7 fp_hook compat execve(11), orig=%llx\n", (unsigned long long)(uintptr_t)g_orig_compat_execve);
    }
#else
    rc = hook_compat_syscalln(11, 3, before_execve, 0, (void *)1);
    log_boot("hook 32 __NR_execve rc: %d\n", rc);
#endif

#ifndef ANTI_SIDECHANNEL_V4G
    // __NR_fstatat64 327
    rc = hook_compat_syscalln(327, 4, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_fstatat64 rc: %d\n", rc);

    //  __NR_faccessat 334
    rc = hook_compat_syscalln(334, 3, su_handler_arg1_ufilename_before, 0, (void *)0);
    log_boot("hook 32 __NR_faccessat rc: %d\n", rc);
#endif

    return 0;
}