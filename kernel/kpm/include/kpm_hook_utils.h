#ifndef _KPM_HOOK_UTILS_H
#define _KPM_HOOK_UTILS_H

#include <hook.h>
#include <linux/kallsyms.h>
#include <linux/printk.h>

#define hook_original(func) original_##func
#define hook_replace(func) replace_##func
#define hook_backup(func) backup_##func

#define hook_typedef(func, retType, ...) typedef retType (*func##_func_t)(__VA_ARGS__)
#define hook_original_def(func) static func##_func_t original_##func = NULL
#define hook_backup_def(func) static func##_func_t backup_##func = NULL
#define hook_replace_func_include(func, retType, ...) static retType hook_replace(func)(__VA_ARGS__)

#define hook_func_def(func, retType, ...)                  \
    hook_typedef(func, retType, __VA_ARGS__);              \
    hook_original_def(func);                               \
    hook_backup_def(func);                                 \
    hook_replace_func_include(func, retType, __VA_ARGS__); \
    static hook_err_t hook_##func##_err = HOOK_NOT_HOOK;

#define find_and_hook_func_with(func, original, replace, backup, tag)                                \
    static inline bool hook_##func()                                                                 \
    {                                                                                                \
        original = (typeof(original))kallsyms_lookup_name(#func);                                    \
        if (original) {                                                                              \
            hook_##func##_err = hook((void *)original, (void *)replace, (void **)&backup);           \
            if (hook_##func##_err != HOOK_NO_ERR) {                                                  \
                pr_info("%s: hook %s, %llx, error: %d\n", #tag, #func, original, hook_##func##_err); \
            } else                                                                                   \
                return true;                                                                         \
        } else {                                                                                     \
            hook_##func##_err = HOOK_BAD_ADDRESS;                                                    \
            pr_err("%s: no symbol: %s\n", #func);                                                    \
        }                                                                                            \
        return false;                                                                                \
    }

#define find_and_hook_func_no_info_with(func, original, replace, backup)                   \
    static inline bool hook_##func()                                                       \
    {                                                                                      \
        original = (typeof(original))kallsyms_lookup_name(#func);                          \
        if (original) {                                                                    \
            hook_##func##_err = hook((void *)original, (void *)replace, (void **)&backup); \
            return hook_##func##_err == HOOK_NO_ERR;                                       \
        } else {                                                                           \
            hook_##func##_err = HOOK_BAD_ADDRESS;                                          \
        }                                                                                  \
        return false;                                                                      \
    }

#define hook_install(func, ...) hook_##func()
#define hook_func(func, tag) find_and_hook_func_with(func, original_##func, replace_##func, backup_##func, tag)
#define hook_func_no_info(func) find_and_hook_func_no_info_with(func, original_##func, replace_##func, backup_##func)
#define hook_err(func) hook_##func##_err
#define hook_success(func) (hook_##func##_err == HOOK_NO_ERR)
#define hook_call_backup(func, ...) hook_backup(func)(__VA_ARGS__)

#define hook_before(func) func##_after
#define hook_after(func) func##_before

#endif /* _KPM_HOOK_UTILS_H */
