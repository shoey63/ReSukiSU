#include <linux/version.h>
#include <linux/preempt.h>
#include <linux/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/pgtable.h>
#else
#include <asm/pgtable.h>
#endif
#include <linux/uaccess.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/namei.h>
#include <linux/jump_label.h>
#include <linux/fs_struct.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#include <linux/minmax.h>
#include "selinux/selinux.h"
#include "objsec.h"
#include "runtime/ksud.h"
#endif

#include "compat/kernel_compat.h"
#include "arch.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "runtime/ksud.h"
#include "feature/sucompat.h"
#include "feature/adb_root.h"
#include "policy/app_profile.h"
#ifdef CONFIG_KSU_TRACEPOINT_HOOK
#include "hook/syscall_hook.h"
#else
#include "feature/adb_root.h"
#endif
#include "sulog/event.h"

#define SU_PATH "/system/bin/su"
#define SH_PATH "/system/bin/sh"

static const char sh_path[] = SH_PATH;
static const char su_path[] = SU_PATH;
static const char ksud_path[] = KSUD_PATH;

DEFINE_STATIC_KEY_TRUE(ksu_su_compat_enabled);

static int su_compat_feature_get(u64 *value)
{
    if (static_key_enabled(&ksu_su_compat_enabled))
        *value = 1;
    else
        *value = 0;
    return 0;
}

static int su_compat_feature_set(u64 value)
{
    bool enable = value != 0;
    if (enable)
        static_branch_enable(&ksu_su_compat_enabled);
    else
        static_branch_disable(&ksu_su_compat_enabled);
    pr_info("su_compat: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler su_compat_handler = {
    .feature_id = KSU_FEATURE_SU_COMPAT,
    .name = "su_compat",
    .get_handler = su_compat_feature_get,
    .set_handler = su_compat_feature_set,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    char __user *p = (void __user *)current_user_stack_pointer() - len;
    return copy_to_user(p, d, len) ? NULL : p;
}
#else
static void __user *userspace_stack_buffer(const void *d, size_t len)
{
    if (!current->mm)
        return NULL;

    volatile unsigned long start_stack = current->mm->start_stack;
    unsigned int step = 32;
    char __user *p = NULL;

    do {
        p = (void __user *)(start_stack - step - len);
        if (!copy_to_user(p, d, len)) {
            return p;
        }
        step = step + step;
    } while (step <= 2048);
    return NULL;
}
#endif

static char __user *sh_user_path(void)
{
    static const char sh_path_local[] = "/system/bin/sh";
    return userspace_stack_buffer(sh_path_local, sizeof(sh_path_local));
}

static char __user *ksud_user_path(void)
{
    static const char ksud_path_local[] = KSUD_PATH;
    return userspace_stack_buffer(ksud_path_local, sizeof(ksud_path_local));
}

static char __user *empty_user_path(void)
{
    return userspace_stack_buffer("", sizeof(""));
}

static bool is_ksud_exists(void)
{
    struct path kpath;
    if (kern_path(KSUD_PATH, LOOKUP_FOLLOW, &kpath)) {
        return false;
    }
    path_put(&kpath);
    return true;
}

#ifdef CONFIG_KSU_SUSFS
static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
    const char __user *native;

#ifdef CONFIG_COMPAT
    if (unlikely(argv.is_compat)) {
        compat_uptr_t compat;
        if (get_user(compat, argv.ptr.compat + nr))
            return ERR_PTR(-EFAULT);
        return compat_ptr(compat);
    }
#endif

    if (get_user(native, argv.ptr.native + nr))
        return ERR_PTR(-EFAULT);
    return native;
}

int ksu_handle_execveat_init(struct filename *filename, struct user_arg_ptr *argv_user, struct user_arg_ptr *envp_user)
{
    if (current->pid != 1 && is_init(get_current_cred())) {
        int ret;
        if (unlikely(strcmp(filename->name, KSUD_PATH) == 0)) {
            const char __user *argv_user_ptr = get_user_arg_ptr(*argv_user, 0);
            struct ksu_sulog_pending_event *pending_sucompat = NULL;

            pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
            ret = escape_to_root_for_init();
            if (ret) {
                pr_err("escape_to_root_for_init() failed: %d\n", ret);
                return ret;
            }
            if (!argv_user_ptr || IS_ERR(argv_user_ptr)) {
                pr_err("!argv_user_ptr || IS_ERR(argv_user_ptr)\n");
                return -EFAULT;
            }
            pending_sucompat = ksu_sulog_capture_sucompat_kernel(filename->name, (const char __user *const __user *)argv_user->ptr.native, GFP_KERNEL);
            ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
            return 0;
        } else if (likely(strstr(filename->name, "/app_process") == NULL &&
                    strstr(filename->name, "/adbd") == NULL) &&
                    !susfs_is_current_proc_umounted())
        {
            pr_info("susfs: mark no sucompat checks for pid: '%d', exec: '%s'\n", current->pid, filename->name);
            susfs_set_current_proc_umounted();
            return 0;
        }

#ifdef CONFIG_COMPAT
        if (unlikely(envp_user->is_compat))
            ret = ksu_adb_root_handle_execve(filename->name, (void ***)&envp_user->ptr.compat);
        else
            ret = ksu_adb_root_handle_execve(filename->name, (void ***)&envp_user->ptr.native);
#else
        ret = ksu_adb_root_handle_execve(filename->name, (void ***)&envp_user->ptr.native);
#endif

        if (ret) {
            pr_err("adb root failed: %d\n", ret);
            return ret;
        }
        return ret;
    }

    return -EINVAL;
}

int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,
                 void *argv_user, void *envp_user,
                 int *__never_use_flags)
{
    struct filename *filename;
    struct user_arg_ptr *argv_ptr = (struct user_arg_ptr *)argv_user;
    struct ksu_sulog_pending_event *pending_sucompat = NULL;
    int ret;

    if (unlikely(!filename_ptr))
        return 0;

    filename = *filename_ptr;
    if (IS_ERR(filename))
        return 0;

    if (!ksu_handle_execveat_init(filename, (struct user_arg_ptr*)argv_user, (struct user_arg_ptr*)envp_user))
        return 0;

    if (likely(memcmp(filename->name, su_path, sizeof(su_path))))
        return 0;

    if (current_chrooted())
    {
        pr_err("ksu_handle_execveat_sucompat: su found but NOT allowed! Because current process is running in chrooted environment\n");
        return 0;
    }

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;
    ksu_compat_sulog('x');
    pr_info("ksu_handle_execveat_sucompat: su found\n");

    pending_sucompat = ksu_sulog_capture_sucompat_kernel(filename->name,
                                                         (const char __user *const __user *)argv_ptr->ptr.native,
                                                         GFP_KERNEL);

    memcpy((void *)filename->name, ksud_path, sizeof(ksud_path));

    ret = escape_with_root_profile();
    if (ret)
        pr_err("escape_with_root_profile() failed: %d\n", ret);

    ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);

    return 0;
}

extern struct static_key_true is_first_zygote;

int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,
            void *envp, int *flags)
{
    struct ksu_sulog_pending_event *pending_root_execve = NULL;

    if (unlikely(!filename_ptr))
        return 0;

    if (IS_ERR(*filename_ptr))
        return 0;

    if (current_euid().val == 0) {
        struct user_arg_ptr *argv_ptr = (struct user_arg_ptr *)argv;
        pending_root_execve = ksu_sulog_capture_root_execve_kernel((*filename_ptr)->name,
                                                                   (const char __user *const __user *)argv_ptr->ptr.native,
                                                                   GFP_KERNEL);
        ksu_sulog_emit_pending(pending_root_execve, 0, GFP_KERNEL);
    }
    if (static_branch_unlikely(&is_first_zygote)) {
        ksu_handle_execveat_ksud((*filename_ptr)->name, argv, envp, flags);
    }

    return ksu_handle_execveat_sucompat(fd, filename_ptr, argv, envp, flags);
}
#endif

int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
                int *mode, int *__unused_flags)
{
#ifdef CONFIG_KSU_SUSFS
    char path[sizeof(su_path) + 1] = {0};
    if (strncpy_from_user_nofault(path, *filename_user, sizeof(path)) < 0)
        return 0;

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        if (current_chrooted())
        {
            pr_err("ksu_handle_faccessat: su found but NOT allowed! Because current process is running in chrooted environment\n");
            return 0;
        }

        if (!ksu_is_allow_uid_for_current(current_uid().val))
            return 0;

        ksu_compat_sulog('a');
        pr_info("ksu_handle_faccessat: su->sh!\n");
        *filename_user = sh_user_path();
    }
#else
    const char su[] = SU_PATH;

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        ksu_compat_sulog('a');
        pr_info("faccessat su->sh!\n");
        *filename_user = sh_user_path();
    }
#endif

    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0) && defined(CONFIG_KSU_SUSFS)
int ksu_handle_stat(int *dfd, struct filename **filename, int *flags) {
    if (unlikely(IS_ERR(*filename) || (*filename)->name == NULL))
        return 0;

    if (likely(memcmp((*filename)->name, su_path, sizeof(su_path))))
        return 0;

    if (current_chrooted())
    {
        pr_err("ksu_handle_stat: su found but NOT allowed! Because current process is running in chrooted environment\n");
        return 0;
    }

    if (!ksu_is_allow_uid_for_current(current_uid().val))
        return 0;

    ksu_compat_sulog('s');
    pr_info("ksu_handle_stat: su->sh!\n");
    memcpy((void *)((*filename)->name), sh_path, sizeof(sh_path));
    return 0;
}
#else
int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags)
{
#ifdef CONFIG_KSU_SUSFS
    char path[sizeof(su_path) + 1] = {0};
    if (strncpy_from_user_nofault(path, *filename_user, sizeof(path)) < 0)
        return 0;

    if (unlikely(!memcmp(path, su_path, sizeof(su_path)))) {
        if (current_chrooted())
        {
            pr_err("ksu_handle_stat: su found but NOT allowed! Because current process is running in chrooted environment\n");
            return 0;
        }

        if (!ksu_is_allow_uid_for_current(current_uid().val))
            return 0;

        ksu_compat_sulog('s');
        pr_info("ksu_handle_stat: su->sh!\n");
        *filename_user = sh_user_path();
    }
#else
    const char su[] = SU_PATH;

    if (!ksu_is_allow_uid_for_current(current_uid().val)) {
        return 0;
    }

    if (unlikely(!filename_user)) {
        return 0;
    }

    char path[sizeof(su) + 1];
    memset(path, 0, sizeof(path));
    strncpy_from_user_nofault(path, *filename_user, sizeof(path));

    if (unlikely(!memcmp(path, su, sizeof(su)))) {
        ksu_compat_sulog('s');
        pr_info("newfstatat su->sh!\n");
        *filename_user = sh_user_path();
    }
#endif

    return 0;
}
#endif

int __maybe_unused ksu_handle_devpts(struct inode *inode)
{
    return 0;
}

void __init ksu_sucompat_init()
{
    if (ksu_register_feature_handler(&su_compat_handler)) {
        pr_err("Failed to register su_compat feature handler\n");
    }
}

void __exit ksu_sucompat_exit()
{
    ksu_unregister_feature_handler(KSU_FEATURE_SU_COMPAT);
}
