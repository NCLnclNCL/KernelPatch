/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <ktypes.h>
#include <uapi/scdefs.h>
#include <hook.h>
#include <common.h>
#include <log.h>
#include <predata.h>
#include <pgtable.h>
#include <linux/syscall.h>
#include <uapi/asm-generic/errno.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <asm/current.h>
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <syscall.h>
#include <accctl.h>
#include <module.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <kputils.h>
#include <predata.h>
#include <linux/random.h>
#include <sucompat.h>
#include <accctl.h>
#include <kstorage.h>
#ifdef ANDROID
#include <userd.h>
#endif

#define MAX_KEY_LEN 128

#include <linux/umh.h>

static long call_test(long arg1, long arg2, long arg3)
{
    return 0;
}

static long call_bootlog()
{
    print_bootlog();
    return 0;
}

static long call_panic()
{
    unsigned long panic_addr = kallsyms_lookup_name("panic");
    ((void (*)(const char *fmt, ...))panic_addr)("!!!! kernel_patch panic !!!!");
    return 0;
}

static long call_klog(const char __user *arg1)
{
    char buf[1024];
    long len = compat_strncpy_from_user(buf, arg1, sizeof(buf));
    if (len <= 0) return -EINVAL;
    if (len > 0) logki("user log: %s", buf);
    return 0;
}

static long call_buildtime(char __user *out_buildtime, int u_len)
{
    const char *buildtime = get_build_time();
    int len = strlen(buildtime);
    if (len >= u_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_buildtime, buildtime, len + 1);
    return rc;
}

static long call_kpm_load(const char __user *arg1, const char *__user arg2, void *__user reserved)
{
    char path[1024], args[KPM_ARGS_LEN];
    long pathlen = compat_strncpy_from_user(path, arg1, sizeof(path));
    if (pathlen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return load_module_path(path, arglen <= 0 ? 0 : args, reserved);
}

static long call_kpm_control(const char __user *arg1, const char *__user arg2, void *__user out_msg, int outlen)
{
    char name[KPM_NAME_LEN], args[KPM_ARGS_LEN];
    long namelen = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (namelen <= 0) return -EINVAL;
    long arglen = compat_strncpy_from_user(args, arg2, sizeof(args));
    return module_control0(name, arglen <= 0 ? 0 : args, out_msg, outlen);
}

static long call_kpm_unload(const char *__user arg1, void *__user reserved)
{
    char name[KPM_NAME_LEN];
    long len = compat_strncpy_from_user(name, arg1, sizeof(name));
    if (len <= 0) return -EINVAL;
    return unload_module(name, reserved);
}

static long call_kpm_nums()
{
    return get_module_nums();
}

static long call_kpm_list(char *__user names, int len)
{
    if (len <= 0) return -EINVAL;
    char buf[4096];
    int sz = list_modules(buf, sizeof(buf));
    if (sz > len) return -ENOBUFS;
    sz = compat_copy_to_user(names, buf, len);
    return sz;
}

static long call_kpm_info(const char *__user uname, char *__user out_info, int out_len)
{
    if (out_len <= 0) return -EINVAL;
    char name[64];
    char buf[2048];
    int len = compat_strncpy_from_user(name, uname, sizeof(name));
    if (len <= 0) return -EINVAL;
    int sz = get_module_info(name, buf, sizeof(buf));
    if (sz < 0) return sz;
    if (sz > out_len) return -ENOBUFS;
    sz = compat_copy_to_user(out_info, buf, sz);
    return sz;
}

static long call_su(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = commit_su(profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_su_task(pid_t pid, struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    profile->scontext[sizeof(profile->scontext) - 1] = '\0';
    int rc = task_su(pid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_skey_get(char *__user out_key, int out_len)
{
    const char *key = get_superkey();
    int klen = strlen(key);
    if (klen >= out_len) return -ENOMEM;
    int rc = compat_copy_to_user(out_key, key, klen + 1);
    return rc;
}

static long call_skey_set(char *__user new_key)
{
    char buf[SUPER_KEY_LEN];
    int len = compat_strncpy_from_user(buf, new_key, sizeof(buf));
    if (len >= SUPER_KEY_LEN && buf[SUPER_KEY_LEN - 1]) return -E2BIG;
    reset_superkey(new_key);
    return 0;
}

static long call_skey_root_enable(int enable)
{
    enable_auth_root_key(enable);
    return 0;
}

static long call_grant_uid(struct su_profile *__user uprofile)
{
    struct su_profile *profile = memdup_user(uprofile, sizeof(struct su_profile));
    if (!profile || IS_ERR(profile)) return PTR_ERR(profile);
    int rc = su_add_allow_uid(profile->uid, profile->to_uid, profile->scontext);
    kvfree(profile);
    return rc;
}

static long call_revoke_uid(uid_t uid)
{
    return su_remove_allow_uid(uid);
}

static long call_su_allow_uid_nums()
{
    return su_allow_uid_nums();
}

#ifdef ANDROID
extern int android_is_safe_mode;
static long call_su_get_safemode()
{
    int result = android_is_safe_mode;
    logkfd("[call_su_get_safemode] %d\n", result);
    return result;
}

extern int load_ap_package_config(void);
static long call_ap_load_package_config()
{
    int result = load_ap_package_config();
    logkfd("[call_ap_load_package_config] loaded %d entries\n", result);
    return result;
}
#endif

static long call_su_list_allow_uid(uid_t *__user uids, int num)
{
    return su_allow_uids(1, uids, num);
}

static long call_su_allow_uid_profile(uid_t uid, struct su_profile *__user uprofile)
{
    return su_allow_uid_profile(1, uid, uprofile);
}

static long call_reset_su_path(const char *__user upath)
{
    return su_reset_path(strndup_user(upath, SU_PATH_MAX_LEN));
}

static long call_su_get_path(char *__user ubuf, int buf_len)
{
    const char *path = su_get_path();
    int len = strlen(path);
    if (buf_len <= len) return -ENOBUFS;
    return compat_copy_to_user(ubuf, path, len + 1);
}

static long call_su_get_allow_sctx(char *__user usctx, int ulen)
{
    int len = strlen(all_allow_sctx);
    if (ulen <= len) return -ENOBUFS;
    return compat_copy_to_user(usctx, all_allow_sctx, len + 1);
}

static long call_su_set_allow_sctx(char *__user usctx)
{
    char buf[SUPERCALL_SCONTEXT_LEN];
    buf[0] = '\0';
    int len = compat_strncpy_from_user(buf, usctx, sizeof(buf));
    if (len >= SUPERCALL_SCONTEXT_LEN && buf[SUPERCALL_SCONTEXT_LEN - 1]) return -E2BIG;
    return set_all_allow_sctx(buf);
}

static long call_kstorage_read(int gid, long did, void *out_data, int offset, int dlen)
{
    return read_kstorage(gid, did, out_data, offset, dlen, true);
}

static long call_kstorage_write(int gid, long did, void *data, int offset, int dlen)
{
    return write_kstorage(gid, did, data, offset, dlen, true);
}

static long call_list_kstorage_ids(int gid, long *ids, int ids_len)
{
    return list_kstorage_ids(gid, ids, ids_len, false);
}

static long call_kstorage_remove(int gid, long did)
{
    return remove_kstorage(gid, did);
}

static long supercall(int is_key_auth, long cmd, long arg1, long arg2, long arg3, long arg4)
{
    switch (cmd) {
    case SUPERCALL_HELLO:
        logki(SUPERCALL_HELLO_ECHO "\n");
        return SUPERCALL_HELLO_MAGIC;
    case SUPERCALL_KLOG:
        return call_klog((const char *__user)arg1);
    case SUPERCALL_KERNELPATCH_VER:
        return kpver;
    case SUPERCALL_KERNEL_VER:
        return kver;
    case SUPERCALL_BUILD_TIME:
        return call_buildtime((char *__user)arg1, (int)arg2);
    #ifdef ANDROID
    case SUPERCALL_AP_LOAD_PACKAGE_CONFIG:
        return call_ap_load_package_config();
    #endif
    }

    switch (cmd) {
    case SUPERCALL_SU:
        return call_su((struct su_profile * __user) arg1);
    case SUPERCALL_SU_TASK:
        return call_su_task((pid_t)arg1, (struct su_profile * __user) arg2);

    case SUPERCALL_SU_GRANT_UID:
        return call_grant_uid((struct su_profile * __user) arg1);
    case SUPERCALL_SU_REVOKE_UID:
        return call_revoke_uid((uid_t)arg1);
    case SUPERCALL_SU_NUMS:
        return call_su_allow_uid_nums();
    case SUPERCALL_SU_LIST:
        return call_su_list_allow_uid((uid_t *)arg1, (int)arg2);
    case SUPERCALL_SU_PROFILE:
        return call_su_allow_uid_profile((uid_t)arg1, (struct su_profile * __user) arg2);
    case SUPERCALL_SU_RESET_PATH:
        return call_reset_su_path((const char *)arg1);
    case SUPERCALL_SU_GET_PATH:
        return call_su_get_path((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_GET_ALLOW_SCTX:
        return call_su_get_allow_sctx((char *__user)arg1, (int)arg2);
    case SUPERCALL_SU_SET_ALLOW_SCTX:
        return call_su_set_allow_sctx((char *__user)arg1);

    case SUPERCALL_KSTORAGE_READ:
        return call_kstorage_read((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32), (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_WRITE:
        return call_kstorage_write((int)arg1, (long)arg2, (void *)arg3, (int)((long)arg4 >> 32),
                                   (long)arg4 << 32 >> 32);
    case SUPERCALL_KSTORAGE_LIST_IDS:
        return call_list_kstorage_ids((int)arg1, (long *)arg2, (int)arg3);
    case SUPERCALL_KSTORAGE_REMOVE:
        return call_kstorage_remove((int)arg1, (long)arg2);

#ifdef ANDROID
    case SUPERCALL_SU_GET_SAFEMODE:
        return call_su_get_safemode();
#endif
    default:
        break;
    }

    switch (cmd) {
    case SUPERCALL_BOOTLOG:
        return call_bootlog();
    case SUPERCALL_PANIC:
        return call_panic();
    case SUPERCALL_TEST:
        return call_test(arg1, arg2, arg3);
    default:
        break;
    }

    if (!is_key_auth) return -EPERM;

    switch (cmd) {
    case SUPERCALL_SKEY_GET:
        return call_skey_get((char *__user)arg1, (int)arg2);
    case SUPERCALL_SKEY_SET:
        return call_skey_set((char *__user)arg1);
    case SUPERCALL_SKEY_ROOT_ENABLE:
        return call_skey_root_enable((int)arg1);
        break;
    }

    switch (cmd) {
    case SUPERCALL_KPM_LOAD:
        return call_kpm_load((const char *__user)arg1, (const char *__user)arg2, (void *__user)arg3);
    case SUPERCALL_KPM_UNLOAD:
        return call_kpm_unload((const char *__user)arg1, (void *__user)arg2);
    case SUPERCALL_KPM_CONTROL:
        return call_kpm_control((const char *__user)arg1, (const char *__user)arg2, (char *__user)arg3, (int)arg4);
    case SUPERCALL_KPM_NUMS:
        return call_kpm_nums();
    case SUPERCALL_KPM_LIST:
        return call_kpm_list((char *__user)arg1, (int)arg2);
    case SUPERCALL_KPM_INFO:
        return call_kpm_info((const char *__user)arg1, (char *__user)arg2, (int)arg3);
    }

    switch (cmd) {
    default:
        break;
    }

    return -ENOSYS;
}

// =====================================================================
// [CKB-MOD] Anti side-channel detection bypass
//
// ANTI_SIDECHANNEL_V4 (方案 F, 2026-03-23):
//   直接用 fp_hook() 替换 sys_call_table[45] 函数指针为自定义 wrapper，
//   绕过 fp_hook_wrap 的 transit 框架开销。
//   - out-of-range cmd: tail-call 原始函数，零额外开销
//   - in-range cmd + 非特权进程: uid 预检查后 tail-call，极小开销
//   - in-range cmd + 特权进程: 走完整 supercall 逻辑
//   结果: 绝对延迟 ratio → ~1.0，in/out ratio → ~1.0
//
// 不定义 ANTI_SIDECHANNEL_V4 则使用 v3 方案（before/after 框架）。
// =====================================================================
// [CKB-MOD] Anti side-channel 编译开关
//
// ANTI_SIDECHANNEL_V4G — 方案 G：纯 ARM64 汇编 trampoline（2026-04-11）
//   快速路径 ~7 条指令，手写 br tail-jump，零额外开销
//   慢路径调用 C 函数处理完整 supercall 逻辑
//
// ANTI_SIDECHANNEL_V4 — 方案 F2：C wrapper + fp_hook（2026-03-23）
//   统一路径消除 in/out ratio，但绝对延迟仍 ~2.2x
//
// 都不定义 → v3 方案（before/after 框架）
// =====================================================================

#define ANTI_SIDECHANNEL_V4G
// #define ANTI_SIDECHANNEL_V4

#ifdef ANTI_SIDECHANNEL_V4G

// =====================================================================
// 方案 G：ARM64 汇编 trampoline + C 慢路径
//
// 汇编 trampoline（supercall_trampoline.S）替换 sys_call_table[45]：
//   - 快速路径：cmd 不在范围 → br 原始函数（零开销）
//   - 慢路径：cmd 在范围 → bl 到下面的 C 函数
//
// 与官方升级兼容：
//   - supercall_trampoline.S 是独立新增文件
//   - 本文件用 #ifdef 隔离，不删除任何现有代码
//   - 升级时只需保留 #ifdef 分支和 .S 文件
// =====================================================================

// 汇编 trampoline 导出的符号
extern void supercall_trampoline_wrapper(void);
extern void supercall_trampoline_nowrap(void);
extern void supercall_trampoline_compat(void);

// 原始函数指针（存在 .data 段，可写）
// fp_hook 的 backup 参数指向这里
// 汇编 trampoline 通过 adrp + ldr 直接访问这些变量（不能是 static）
void *g_orig_wrapper = NULL;
void *g_orig_nowrap  = NULL;
void *g_orig_compat  = NULL;

// -----------------------------------------------------------------------
// C 慢路径：has_syscall_wrapper 模式（被汇编 bl 调用）
// x0 = struct pt_regs *regs
// -----------------------------------------------------------------------
long supercall_g_slow_path_wrapper(struct pt_regs *regs)
{
    // [CKB-MOD] G5 调试：计数器
    static unsigned long sc_slow_count = 0;
    sc_slow_count++;
    if ((sc_slow_count % 5000) == 0) {
        logki("anti-sc-debug: supercall_slow_path called %lu times, uid=%d\n", sc_slow_count, current_uid());
    }

    static int logged = 0;
    if (!logged) {
        logki("supercall: anti-sidechannel v4-G (ASM trampoline, wrapper mode)\n");
        logged = 1;
    }

    const char *__user ukey = (const char *__user)regs->regs[0];
    long cmd = (long)regs->regs[1] & 0xFFFF;
    long a1 = (long)regs->regs[2];
    long a2 = (long)regs->regs[3];
    long a3 = (long)regs->regs[4];
    long a4 = (long)regs->regs[5];

    char key[SUPERCALL_KEY_MAX_LEN];
    long len = compat_strncpy_from_user(key, ukey, SUPERCALL_KEY_MAX_LEN);

    int is_key_auth = 0;
    int is_su_uid = 0;
    is_trusted_manager = is_trusted_manager_uid(current_uid());
    if (is_trusted_manager) {
        is_key_auth = 1;
    }
    if (len > 0) {
        if (!auth_superkey(key)) {
            is_key_auth = 1;
        } else if (len == 2 && key[0] == 's' && key[1] == 'u') {
            uid_t uid = current_uid();
            is_su_uid = is_su_allow_uid(uid);
        }
    }

    if (!is_key_auth && !is_su_uid) {
        // key 验证失败 → 调用原始 sys_truncate
        typedef long (*orig_func_t)(struct pt_regs *);
        return ((orig_func_t)g_orig_wrapper)(regs);
    }

    return supercall(is_key_auth, cmd, a1, a2, a3, a4);
}

// -----------------------------------------------------------------------
// C 慢路径：无 wrapper 模式（旧内核 < 4.17）
// 6 个参数直接传递
// -----------------------------------------------------------------------
long supercall_g_slow_path_nowrap(const char *__user ukey, long ver_xx_cmd,
                                   long a1, long a2, long a3, long a4)
{
    static int logged = 0;
    if (!logged) {
        logki("supercall: anti-sidechannel v4-G (ASM trampoline, nowrap mode)\n");
        logged = 1;
    }

    long cmd = ver_xx_cmd & 0xFFFF;

    char key[SUPERCALL_KEY_MAX_LEN];
    long len = compat_strncpy_from_user(key, ukey, SUPERCALL_KEY_MAX_LEN);

    int is_key_auth = 0;
    int is_su_uid = 0;
    if (len > 0) {
        if (!auth_superkey(key)) {
            is_key_auth = 1;
        } else if (len == 2 && key[0] == 's' && key[1] == 'u') {
            uid_t uid = current_uid();
            is_su_uid = is_su_allow_uid(uid);
        }
    }

    if (!is_key_auth && !is_su_uid) {
        typedef long (*orig_func_t)(const char *, long, long, long, long, long);
        return ((orig_func_t)g_orig_nowrap)(ukey, ver_xx_cmd, a1, a2, a3, a4);
    }

    return supercall(is_key_auth, cmd, a1, a2, a3, a4);
}

// -----------------------------------------------------------------------
// 安装
// -----------------------------------------------------------------------
int supercall_install()
{
    if (!sys_call_table) {
        log_boot("supercall v4-G: sys_call_table not found\n");
        return -1;
    }

    // 64 位表
    if (has_syscall_wrapper) {
        fp_hook((uintptr_t)(sys_call_table + __NR_supercall),
                (void *)supercall_trampoline_wrapper,
                (void **)&g_orig_wrapper);
        log_boot("supercall v4-G: wrapper trampoline on sys_call_table[%d]\n", __NR_supercall);
    } else {
        fp_hook((uintptr_t)(sys_call_table + __NR_supercall),
                (void *)supercall_trampoline_nowrap,
                (void **)&g_orig_nowrap);
        log_boot("supercall v4-G: nowrap trampoline on sys_call_table[%d], orig=%llx\n",
                 __NR_supercall,
                 (unsigned long long)(uintptr_t)g_orig_nowrap);
    }

    // 32 位 compat 表
    if (compat_sys_call_table) {
        fp_hook((uintptr_t)(compat_sys_call_table + __NR_supercall),
                (void *)supercall_trampoline_compat,
                (void **)&g_orig_compat);
        log_boot("supercall v4-G: compat trampoline on compat_sys_call_table[%d]\n", __NR_supercall);
    }

    return 0;
}

#elif defined(ANTI_SIDECHANNEL_V4)

// 原始函数指针（安装时由 fp_hook 填入）
static void *orig_sys_truncate = NULL;
static void *orig_compat_sys_brk = NULL;

// 统一 6 参数函数指针类型
typedef long (*orig_syscall_func_t)(long, long, long, long, long, long);

// -----------------------------------------------------------------------
// 慢路径：cmd 在范围内 + 需要完整 supercall 逻辑
// 单独 __noinline 函数，避免栈上的 key[] 数组影响 wrapper 的 tail-call 优化
// -----------------------------------------------------------------------
static __noinline long supercall_slow_path(long arg0, long arg1, long arg2,
                                           long arg3, long arg4, long arg5,
                                           long cmd, uid_t uid)
{
    const char *__user ukey;
    long a1, a2, a3, a4;

    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        ukey = (const char *__user)regs->regs[0];
        a1 = (long)regs->regs[2];
        a2 = (long)regs->regs[3];
        a3 = (long)regs->regs[4];
        a4 = (long)regs->regs[5];
    } else {
        ukey = (const char *__user)arg0;
        a1 = arg2; a2 = arg3; a3 = arg4; a4 = arg5;
    }

    char key[SUPERCALL_KEY_MAX_LEN];
    long len = compat_strncpy_from_user(key, ukey, SUPERCALL_KEY_MAX_LEN);

    int is_key_auth = 0;
    int is_su_uid = 0;
    if (len > 0) {
        if (!auth_superkey(key)) {
            is_key_auth = 1;
        } else if (len == 2 && key[0] == 's' && key[1] == 'u') {
            is_su_uid = is_su_allow_uid(uid);
        }
    }

    // ★ 统一路径核心：无论 cmd 是否在范围内，上面的 strncpy + auth 都已执行
    //   这保证了 in-range 和 out-of-range 路径的时间开销一致

    // cmd 不在 supercall 范围 → 直接调用原始函数（strncpy + auth 已执行，时间已对齐）
    if (cmd < SUPERCALL_HELLO || cmd > SUPERCALL_MAX) {
        return ((orig_syscall_func_t)orig_sys_truncate)(arg0, arg1, arg2, arg3, arg4, arg5);
    }

    // cmd 在范围内但 key 验证失败 → 调用原始函数
    if (!is_key_auth && !is_su_uid) {
        return ((orig_syscall_func_t)orig_sys_truncate)(arg0, arg1, arg2, arg3, arg4, arg5);
    }

    // key 验证成功 → 执行 supercall
    return supercall(is_key_auth, cmd, a1, a2, a3, a4);
}

// -----------------------------------------------------------------------
// 64 位 wrapper：替换 sys_call_table[45]
//
// ★ 方案 F2 (2026-03-23)：统一路径消除 in/out ratio 差异
//
// 核心问题：方案 F 的快速路径（out-of-range → tail-call）虽然零开销，
//   但 in-range 路径要做 strncpy_from_user + auth_superkey，
//   导致 in/out ratio ≈ 1.45，被 Hunter 检测到。
//
// 解决方案：所有路径都走 supercall_slow_path（统一做 strncpy + auth），
//   消除 in/out 时间差异。同时因为绕过了 transit 框架，
//   绝对延迟比 v3 低（v3 ratio ≈ 2.3，F2 预期 ≈ 1.0-1.2）。
//
// 执行路径：
//   out-of-range cmd → slow_path → strncpy + auth → 失败 → tail-call 原始函数
//   in-range cmd     → slow_path → strncpy + auth → 失败/成功 → tail-call/supercall
//   两条路径做完全相同的操作，ratio → ~1.0
// -----------------------------------------------------------------------
static long supercall_wrapper(long arg0, long arg1, long arg2,
                              long arg3, long arg4, long arg5)
{
    static int logged = 0;
    if (!logged) {
        logki("supercall: anti-sidechannel v4-F2 (unified path, no transit)\n");
        logged = 1;
    }

    // 获取 cmd
    long cmd;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        cmd = (long)regs->regs[1] & 0xFFFF;
    } else {
        cmd = arg1 & 0xFFFF;
    }

    uid_t uid = current_uid();

    // ★ 统一路径：无论 cmd 是否在范围内，都走 slow_path
    //   slow_path 内部：strncpy_from_user + auth_superkey（两条路径开销一致）
    //   - out-of-range cmd: slow_path 中 cmd 不在范围 → key 验证后 tail-call 原始函数
    //   - in-range cmd:     slow_path 中 cmd 在范围 → key 验证 → supercall 或 tail-call
    //
    // 但 slow_path 当前只处理 in-range cmd 的 supercall 分发。
    // 需要让 slow_path 对 out-of-range cmd 也做 strncpy + auth 然后 tail-call。
    return supercall_slow_path(arg0, arg1, arg2, arg3, arg4, arg5, cmd, uid);
}

// -----------------------------------------------------------------------
// 32 位 compat wrapper：替换 compat_sys_call_table[45]
// compat 表 nr 45 = sys_brk，不处理 supercall。
// 也需要做统一路径对齐：strncpy + auth，保证与 64 位表时间一致。
// -----------------------------------------------------------------------
static long supercall_compat_wrapper(long arg0, long arg1, long arg2,
                                     long arg3, long arg4, long arg5)
{
    static int logged = 0;
    if (!logged) {
        logki("supercall: anti-sidechannel v4-F2 compat (unified path)\n");
        logged = 1;
    }

    // 获取 ukey 指针（compat 模式下 arg0 是第一个参数）
    const char *__user ukey;
    if (has_syscall_wrapper) {
        struct pt_regs *regs = (struct pt_regs *)arg0;
        ukey = (const char *__user)regs->regs[0];
    } else {
        ukey = (const char *__user)arg0;
    }

    // 统一路径：做 strncpy + auth，对齐 64 位表的时间开销
    char key[SUPERCALL_KEY_MAX_LEN];
    long len = compat_strncpy_from_user(key, ukey, SUPERCALL_KEY_MAX_LEN);
    if (len > 0) {
        (void)auth_superkey(key);
    }

    // compat 表不处理 supercall，直接调用原始 sys_brk
    return ((orig_syscall_func_t)orig_compat_sys_brk)(arg0, arg1, arg2, arg3, arg4, arg5);
}

int supercall_install()
{
    if (!sys_call_table) {
        log_boot("supercall v4-F2: sys_call_table not found\n");
        return -1;
    }

    // 64 位表：直接替换 sys_call_table[45] 函数指针（绕过 transit 框架）
    fp_hook((uintptr_t)(sys_call_table + __NR_supercall),
            (void *)supercall_wrapper,
            &orig_sys_truncate);
    log_boot("supercall v4-F2: fp_hook on sys_call_table[%d], orig=%llx\n",
             __NR_supercall, (unsigned long long)(uintptr_t)orig_sys_truncate);

    // 32 位 compat 表：直接替换 compat_sys_call_table[45] 函数指针
    if (compat_sys_call_table) {
        fp_hook((uintptr_t)(compat_sys_call_table + __NR_supercall),
                (void *)supercall_compat_wrapper,
                &orig_compat_sys_brk);
        log_boot("supercall v4-F2: fp_hook on compat_sys_call_table[%d], orig=%llx\n",
                 __NR_supercall, (unsigned long long)(uintptr_t)orig_compat_sys_brk);
    }

    return 0;
}

#else // !ANTI_SIDECHANNEL_V4 → v3 方案（before/after 框架）

// Anti side-channel detection bypass (Attempt 3)
//
// Problem: Hunter detects APatch by measuring timing difference of syscall 45 (brk).
//   - In-range cmd (0x1000~0x1200): hook does key verify + supercall dispatch + skip_origin
//   - Out-of-range cmd (e.g. 0x999): hook returns early → original brk executes
//   The structural difference (skip_origin vs run original brk) is measurable.
//
// Solution: Both paths execute the SAME operations and BOTH call original brk.
//   - before(): always does copy_from_user + auth_superkey + uid check (both paths)
//   - before(): for in-range cmd, computes supercall result, stores in local.data0
//   - skip_origin is NEVER set → original brk always runs (both paths identical)
//   - after(): for in-range cmd, overwrites ret with the stored supercall result
//
// Result: Both paths have identical timing profile. Detection ratio → ~1.0

// local.data0 = supercall result (when in-range)
// local.data1 = 1 if in-range cmd was handled, 0 otherwise

int is_trusted_manager_uid(uid_t uid)
{
    #ifdef ANDROID
    return is_trusted_manager_uid_android(uid);
    #endif
    return 0;
}



static void before(hook_fargs6_t *args, void *udata)
{
    static int logged = 0;
    if (!logged) {
        logki("supercall before: anti-sidechannel v3 (no skip_origin)\n");
        logged = 1;
    }
    const char *__user ukey = (const char *__user)syscall_argn(args, 0);
    long ver_xx_cmd = (long)syscall_argn(args, 1);

    // todo: from 0.10.5
    // uint32_t ver = (ver_xx_cmd & 0xFFFFFFFF00000000ul) >> 32;
    // long xx = (ver_xx_cmd & 0xFFFF0000) >> 16;

    long cmd = ver_xx_cmd & 0xFFFF;
    
    args->local.data1 = 0;

    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, MAX_KEY_LEN);

    int is_key_auth = 0;
    int is_trusted_manager = 0;
    int is_su_uid = 0;
    is_trusted_manager = is_trusted_manager_uid(current_uid());
    if (is_trusted_manager) {
        is_key_auth = 1;
    }

    if (len > 0) {
        if (!auth_superkey(key)) {
            is_key_auth = 1;
        } else if (!strcmp("su", key)) {
            uid_t uid = current_uid();
            is_su_uid = is_su_allow_uid(uid);
        }
    }

    if (cmd >= SUPERCALL_HELLO && cmd <= SUPERCALL_MAX) {
        if (!is_key_auth && !is_su_uid) return;

        long a1 = (long)syscall_argn(args, 2);
        long a2 = (long)syscall_argn(args, 3);
        long a3 = (long)syscall_argn(args, 4);
        long a4 = (long)syscall_argn(args, 5);

        args->local.data0 = (uint64_t)supercall(is_key_auth, cmd, a1, a2, a3, a4);
        args->local.data1 = 1;
}

}
static void after(hook_fargs6_t *args, void *udata)
{
    if (args->local.data1 == 1) {
        args->ret = args->local.data0;
    }
}

static void before_compat(hook_fargs6_t *args, void *udata)
{
    static int logged = 0;
    if (!logged) {
        logki("supercall before_compat: anti-sidechannel compat table hook\n");
        logged = 1;
    }
    const char *__user ukey = (const char *__user)syscall_argn(args, 0);
    char key[MAX_KEY_LEN];
    long len = compat_strncpy_from_user(key, ukey, MAX_KEY_LEN);

    if (len > 0) {
        if (!auth_superkey(key)) {
            // key_auth 成功，但 compat 表不处理 supercall
        } else if (!strcmp("su", key)) {
            uid_t uid = current_uid();
            (void)is_su_allow_uid(uid);
        }
    }
}

static void after_compat(hook_fargs6_t *args, void *udata)
{
    // 空回调，对齐 64 位表的 after 开销
}

int supercall_install()
{
    int rc = 0;

    hook_err_t err = hook_syscalln(__NR_supercall, 6, before, after, 0);
    if (err) {
        log_boot("install supercall 64-bit hook error: %d\n", err);
        rc = err;
        goto out;
    }
hook_err_t compat_err = hook_compat_syscalln(__NR_supercall, 6, before_compat, after_compat, 0);
    if (compat_err) {
        log_boot("install compat supercall hook error: %d\n", compat_err);
    } else {
        log_boot("compat supercall hook installed (anti-sidechannel)\n");
    }

out:
    return rc;
}

#endif // ANTI_SIDECHANNEL_V4