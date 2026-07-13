#include "linux/cred.h"
#include "linux/sched.h"
#include "linux/security.h"
#include "linux/version.h"
#include "selinux_defs.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "compat/kernel_compat.h"

/*
 * Cached SID values for frequently checked contexts.
 * These are resolved once at init and used for fast u32 comparison
 * instead of expensive string operations on every check.
 */
static u32 cached_su_sid __read_mostly = 0;
static u32 cached_zygote_sid __read_mostly = 0;
static u32 cached_init_sid __read_mostly = 0;
u32 ksu_file_sid __read_mostly = 0;

#ifdef CONFIG_KSU_SUSFS
u32 susfs_ksu_sid __read_mostly = 0;
u32 susfs_init_sid __read_mostly = 0;
u32 susfs_zygote_sid __read_mostly = 0;
u32 susfs_priv_app_sid __read_mostly = 0;
#define KERNEL_PRIV_APP_DOMAIN "u:r:priv_app:s0:c512,c768"
#endif

/*
 * GKI2 Polyfill: struct lsm_context was introduced in newer kernels (6.6+).
 * We define it locally for older kernels to maintain a unified source base.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
    char *context;
    u32 len;
};

static inline int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
    return security_secid_to_secctx(secid, &cp->context, &cp->len);
}

static inline void __security_release_secctx(struct lsm_context *cp)
{
    security_release_secctx(cp->context, cp->len);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

static int transive_to_domain(const char *domain, struct cred *cred, bool clear_exec_sid)
{
    u32 sid;
    int error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    struct task_security_struct *tsec;
#else
    struct cred_security_struct *tsec;
#endif
    tsec = selinux_cred(cred);
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }
    error = security_secctx_to_secid(domain, strlen(domain), &sid);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n", domain, sid, error);
    }
    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
        if (clear_exec_sid) {
            tsec->exec_sid = 0;
        }
    }
    return error;
}

void setup_selinux(const char *domain, struct cred *cred)
{
    if (transive_to_domain(domain, cred, false)) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setup_ksu_cred_selinux(void)
{
    if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred, false)) {
        pr_err("setup ksu cred selinux domain failed.\n");
    }
}

void escape_to_root_for_adb_root(void)
{
    struct cred *cred = prepare_creds();
    if (!cred) {
        pr_err("Failed to prepare adbd's creds!\n");
        return;
    }

    if (transive_to_domain(KERNEL_SU_CONTEXT, cred, true)) {
        pr_err("transive domain failed.\n");
        abort_creds(cred);
        return;
    }
    commit_creds(cred);
}

void setenforce(bool enforce)
{
    __setenforce(enforce);
}

bool getenforce(void)
{
    if (is_selinux_disabled()) {
        return false;
    }

    return __is_selinux_enforcing();
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)) && !defined(KSU_COMPAT_HAS_CURRENT_SID)
/*
 * get the subjective security ID of the current task
 */
static inline u32 current_sid(void)
{
    const struct task_security_struct *tsec = current_security();
    return tsec->sid;
}
#endif

/*
 * Initialize cached SID values for frequently checked SELinux contexts.
 * Called once after SELinux policy is loaded (post-fs-data).
 * This eliminates expensive string comparisons in hot paths.
 */
void cache_sid(void)
{
    int err;

    err = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &cached_su_sid);
    if (err) {
        pr_warn("Failed to cache kernel su domain SID: %d\n", err);
        cached_su_sid = 0;
    } else {
        pr_info("Cached su SID: %u\n", cached_su_sid);
    }

    err = security_secctx_to_secid(ZYGOTE_CONTEXT, strlen(ZYGOTE_CONTEXT), &cached_zygote_sid);
    if (err) {
        pr_warn("Failed to cache zygote SID: %d\n", err);
        cached_zygote_sid = 0;
    } else {
        pr_info("Cached zygote SID: %u\n", cached_zygote_sid);
    }

    err = security_secctx_to_secid(INIT_CONTEXT, strlen(INIT_CONTEXT), &cached_init_sid);
    if (err) {
        pr_warn("Failed to cache init SID: %d\n", err);
        cached_init_sid = 0;
    } else {
        pr_info("Cached init SID: %u\n", cached_init_sid);
    }

    err = security_secctx_to_secid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT), &ksu_file_sid);
    if (err) {
        pr_warn("Failed to cache ksu_file SID: %d\n", err);
        ksu_file_sid = 0;
    } else {
        pr_info("Cached ksu_file SID: %u\n", ksu_file_sid);
    }

#ifdef CONFIG_KSU_SUSFS
    // compatible with current susfs
    err = security_secctx_to_secid(KERNEL_PRIV_APP_DOMAIN, strlen(KERNEL_PRIV_APP_DOMAIN), &susfs_priv_app_sid);
    if (err) {
        pr_warn("Failed to cache susfs_priv_app SID: %d\n", susfs_priv_app_sid);
        susfs_priv_app_sid = 0;
    } else {
        pr_info("Cached susfs_priv_app SID: %u\n", susfs_priv_app_sid);
    }

    susfs_ksu_sid = cached_su_sid;
    susfs_zygote_sid = cached_zygote_sid;
    susfs_init_sid = cached_init_sid;
#endif
}

#ifdef CONFIG_KSU_SUSFS
// SuSFS Linker Stub: 
// ReSukiSU already handles SID caching organically in cache_sid(). 
// This stub prevents undefined symbol linker errors if SuSFS tries to call it manually.
void susfs_set_batch_sid(void) {}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
static inline bool is_sid_match_tsec(const struct task_security_struct *tsec, u32 cached_sid,
                                     const char *fallback_context)
#else
static inline bool is_sid_match_tsec(const struct cred_security_struct *tsec, u32 cached_sid,
                                     const char *fallback_context)
#endif
{
    // Fast path: use cached SID if available
    if (likely(cached_sid != 0)) {
        return tsec->sid == cached_sid;
    }

    // Slow path fallback: string comparison (only before cache is initialized)
    struct lsm_context ctx;
    bool result;
    if (__security_secid_to_secctx(tsec->sid, &ctx)) {
        return false;
    }
    result = strncmp(fallback_context, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);

    return result;
}

/*
 * Fast path: compare task's SID directly against cached value.
 * Falls back to string comparison if cache is not initialized.
 */
static inline bool is_sid_match(const struct cred *cred, u32 cached_sid, const char *fallback_context)
{
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct *tsec;
#else
    const struct cred_security_struct *tsec;
#endif
    tsec = selinux_cred(cred);
    if (!tsec) {
        return false;
    }

    return is_sid_match_tsec(tsec, cached_sid, fallback_context);
}

bool is_task_ksu_domain(const struct cred *cred)
{
#ifdef CONFIG_KSU_SUSFS
    if (is_sid_match(cred, susfs_ksu_sid, KERNEL_SU_CONTEXT)) return true;
#endif
    return is_sid_match(cred, cached_su_sid, KERNEL_SU_CONTEXT);
}

bool is_ksu_domain(void)
{
    return is_task_ksu_domain(current_cred());
}

bool is_zygote(const struct cred *cred)
{
#ifdef CONFIG_KSU_SUSFS
    if (is_sid_match(cred, susfs_zygote_sid, ZYGOTE_CONTEXT)) return true;
#endif
    return is_sid_match(cred, cached_zygote_sid, ZYGOTE_CONTEXT);
}

bool is_init(const struct cred *cred)
{
#ifdef CONFIG_KSU_SUSFS
    if (is_sid_match(cred, susfs_init_sid, INIT_CONTEXT)) return true;
#endif
    return is_sid_match(cred, cached_init_sid, INIT_CONTEXT);
}

#ifdef CONFIG_KSU_SUSFS
u32 susfs_get_sid_from_name(const char *secctx_name)
{
    u32 out_sid = 0;
    int err;

    if (!secctx_name) {
        pr_err("secctx_name is NULL\n");
        return 0;
    }
    err = security_secctx_to_secid(secctx_name, strlen(secctx_name), &out_sid);
    if (err) {
        pr_err("failed getting sid from secctx_name: %s, err: %d\n", secctx_name, err);
        return 0;
    }
    return out_sid;
}

u32 susfs_get_current_sid(void)
{
    return current_sid();
}

bool susfs_is_current_zygote_domain(void)
{
    return is_zygote(current_cred());
}

bool susfs_is_current_ksu_domain(void)
{
    return is_ksu_domain();
}

bool susfs_is_current_init_domain(void)
{
    return is_init(current_cred());
}
#endif // #ifdef CONFIG_KSU_SUSFS
