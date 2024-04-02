/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 skkk. All Rights Reserved.
 */

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>

#include <kpm_utils.h>
#include <kpm_hook_utils.h>

KPM_NAME("hosts_file_redirect");
KPM_VERSION(HFR_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("skkk");
KPM_DESCRIPTION("hosts file redirect: /data/adb/hosts");

static const char hostsOrigPath[] = "/system/etc/hosts";
static const char hostsRedirectPath[] = "/data/adb/hosts";

struct open_flags;
hook_func_def(do_filp_open, struct file *, int dfd, struct filename *pathname, const struct open_flags *o);
hook_func_no_info(do_filp_open);

static struct file *hook_replace(do_filp_open)(int dfd, struct filename *pathname, const struct open_flags *o)
{
    if (unlikely(!strcmp(hostsOrigPath, pathname->name))) {
        bool replace = false;
        const char *originName = NULL;
        // netd is the root user
        if (current_uid() == 0) {
            replace = true;
            originName = pathname->name;
            pathname->name = hostsRedirectPath;
            set_priv_selinx_allow(1);
        }

        struct file *f = hook_call_backup(do_filp_open, dfd, pathname, o);

        if (replace) {
            set_priv_selinx_allow(0);
            pathname->name = originName;
            //retry origin
            if (IS_ERR(f)) f = hook_call_backup(do_filp_open, dfd, pathname, o);
        }
        return f;
    }
    return hook_call_backup(do_filp_open, dfd, pathname, o);
}

static inline bool installHook()
{
    bool ret = false;

    if (!hook_success(do_filp_open)) {
        hook_install(do_filp_open);
        if (!hook_success(do_filp_open)) goto exit;
        pr_info("HFR: hosts file is: '%s'\n", hostsRedirectPath);
        pr_info("HFR: enabled !\n");
    } else {
        pr_info("HFR: Always enabled !\n");
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
        pr_info("HFR: disbaled !\n");
    } else {
        pr_info("HFR: Always disabled !\n");
    }
    return true;
}

static inline void printInfo()
{
    pr_info("Kernel Version: %x\n", kver);
    pr_info("Kernel Patch Version: %x\n", kpver);
}

static inline bool hfr_control(bool enable)
{
    return enable ? installHook() : uninstallHook();
}

static long hosts_file_redirect_init(const char *args, const char *event, void *__user reserved)
{
    long ret = 0;

    printInfo();
    pr_info("HFR: initializing ...\n");

    if (hfr_control(true)) {
        pr_info("HFR: Initialization successful!\n");
        goto exit;
    }

    ret = 1;
    pr_info("HFR: initializing failed!\n");
exit:
    return ret;
}

static long hosts_file_redirect_control0(const char *args, char *__user out_msg, int outlen)
{
    if (args) {
        if (strncmp(args, "enable", 6) == 0) {
            writeOutMsg(out_msg, &outlen, hfr_control(true) ? "HFR: enabled !" : "HFR: enable fail !");
        } else if (strncmp(args, "disable", 7) == 0) {
            writeOutMsg(out_msg, &outlen, hfr_control(false) ? "HFR: disbaled !" : "HFR: disbale fail !");
        } else {
            pr_info("HFR: ctl error, args=%s\n", args);
            writeOutMsg(out_msg, &outlen, "HFR: ctl error !");
            return -1;
        }
    }
    return 0;
}

static long hosts_file_redirect_exit(void *__user reserved)
{
    uninstallHook();
    pr_info("HFR: Exiting ...\n");
    return 0;
}

KPM_INIT(hosts_file_redirect_init);
KPM_CTL0(hosts_file_redirect_control0);
KPM_EXIT(hosts_file_redirect_exit);
