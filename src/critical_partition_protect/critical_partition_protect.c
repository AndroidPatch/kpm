/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 skkk. All Rights Reserved.
 * Copyright (C) 2024 GarfieldHan. All Rights Reserved.
 * Copyright (C) 2024 1f2003d5. All Rights Reserved.
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/string.h>

#include <kpm_utils.h>
#include <kpm_hook_utils.h>
#include "file.h"

KPM_NAME("Anti Format Critical Partition");
KPM_VERSION(ANTI_FORMAT_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("1f2003d5");
KPM_DESCRIPTION("通过拦截内核调用对关键分区进行保护，防止被恶意格机");

char *skfunc_def(d_path)(const struct path *path, char *buf, int buflen) = NULL;
void skfunc_def(fput)(struct file *file) = NULL;

hook_func_def(do_filp_open, struct file *, int dfd, struct filename *pathname, const struct open_flags *o);
hook_func_no_info(do_filp_open);
static struct file *hook_replace(do_filp_open)(int dfd, struct filename *pathname, const struct open_flags *o)
{
    struct file *filp = hook_call_backup(do_filp_open, dfd, pathname, o);
    if (!IS_ERR(filp)) {
        char tmp[PATH_MAX];
        memset(&tmp, 0, PATH_MAX);
        char *currFN = skfunc(d_path)(&filp->f_path, tmp, PATH_MAX);
#ifdef DEBUG
        pr_info("[AntiFormatDevice] %s", currFN);
#endif
        if (currFN) {
            if (unlikely(strstr(currFN, "/dev") != NULL) && unlikely(strstr(currFN, "/block") != NULL)) {
                // Check write mode
                if ((o->open_flag & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0) {
                    if (unlikely(strstr(currFN, "/sd") != NULL) || unlikely(strstr(currFN, "/loop") != NULL) || unlikely(strstr(currFN, "/mapper") != NULL) || unlikely(strstr(currFN, "/dm-") != NULL) || unlikely(strstr(currFN, "/by-name") != NULL) || unlikely(strstr(currFN, "/bootdevice") != NULL)) {
#ifdef DEBUG
                        pr_info("[AntiFormatDevice] %s, open_flag: %d, mode: %d", currFN, o->open_flag, o->mode);
#endif
                        pr_err("[AntiFormatDevice] Evil operation, disallowed!");
                        skfunc(fput)(filp);
                        return ERR_PTR(-EACCES);
                    }
                }
            }
        }
    }
    return filp;
}

static inline bool installHook() {
    bool ret = false;

    if (!hook_success(do_filp_open)) {
        hook_install(do_filp_open);
        if (!hook_success(do_filp_open)) goto exit;
        pr_info("[AntiFormatDevice] hook installed...\n");
    } else {
        pr_info("[AntiFormatDevice] hook already installed, skipping...\n");
    }
    ret = true;

exit:
    return ret;
}

static inline bool uninstallHook()
{
    if (hook_success(do_filp_open)) {
        unhook((void *)hook_original(do_filp_open));
        hook_err(do_filp_open) = HOOK_NOT_HOOK;
        pr_info("[AntiFormatDevice] hook uninstalled...\n");
    } else {
        pr_info("[AntiFormatDevice] Maybe it's not hooked, skipping...\n");
    }
    return true;
}

static inline bool anti_format_device_control_internal(bool enable)
{
    return enable ? installHook() : uninstallHook();
}

static long anti_format_device_init(const char *args, const char *event, void *__user reserved)
{
    long ret = 0;

    pr_info("[AntiFormatDevice] Kernel Version: %x\n", kver);
    pr_info("[AntiFormatDevice] Kernel Patch Version: %x\n", kpver);
    pr_info("[AntiFormatDevice] Initializing...\n");

    skfunc_match(d_path, NULL, NULL);
    if (!skfunc(d_path)) {
    	pr_info("[AntiFormatDevice] kernel func: 'd_path' does not exist!\n");
    	goto exit;
    }
    
    skfunc_match(fput, NULL, NULL);
    if (!skfunc(fput)) {
    	pr_info("[AntiFormatDevice] kernel func: 'fput' does not exist!\n");
    	goto exit;
    }

    if (anti_format_device_control_internal(true)) {
        pr_info("[AntiFormatDevice] Module initializing completed.\n");
        goto exit;
    }

    ret = 1;
    pr_err("[AntiFormatDevice] Module initializing failed.\n");
exit:
    return ret;
}

static long anti_format_device_control0(const char *args, char *__user out_msg, int outlen)
{
    writeOutMsg(out_msg, &outlen, "Unsupported operation");
    return 0;
}

static long anti_format_device_exit(void *__user reserved)
{
    anti_format_device_control_internal(false);
    pr_info("[AntiFormatDevice] anti_format_device_exit, uninstalled hook.\n");
    return 0;
}

KPM_INIT(anti_format_device_init);
KPM_CTL0(anti_format_device_control0);
KPM_EXIT(anti_format_device_exit);
