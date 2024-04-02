/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 * Copyright (C) 2024 skkk. All Rights Reserved.
 */

#include <linux/printk.h>
#include <linux/string.h>

#include <kpm_utils.h>
#include <kpm_hook_utils.h>
#include "policydb.h"

KPM_NAME("selinux_policydb_fix");
KPM_VERSION(PDBF_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("skkk");
KPM_DESCRIPTION("Make policydb report Android specific flags.");

/*
 * see: https://android-review.googlesource.com/c/kernel/common/+/3009995
 *
 */
hook_func_def(policydb_write, int, struct _policydb *p, struct _policy_file *fp);
hook_func_no_info(policydb_write);

static int hook_replace(policydb_write)(struct _policydb *p, struct _policy_file *fp)
{
    char *data = fp->data;
    int ret = hook_call_backup(policydb_write, p, fp);
    if (!ret) {
        __le32 *config = (__le32 *)(data + POLICYDB_CONFIG_OFFSET);
        __le32 before_config = *config;
        bool android_netlink_route_exists = before_config & POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
        bool android_netlink_getneigh_exists = before_config & POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
        if (p->android_netlink_route == 1 && !android_netlink_route_exists) {
            *config |= POLICYDB_CONFIG_ANDROID_NETLINK_ROUTE;
            pr_info("PDBF: add android_netlink_route\n");
        }
        if (p->android_netlink_getneigh == 1 && !android_netlink_getneigh_exists) {
            *config |= POLICYDB_CONFIG_ANDROID_NETLINK_GETNEIGH;
            pr_info("PDBF: add android_netlink_getneigh\n");
        }
        if (before_config != *config) pr_info("PDBF: config 0x%08x to 0x%08x\n", before_config, *config);
    }
    return ret;
}

static inline bool installHook()
{
    bool ret = false;

    if (!hook_success(policydb_write)) {
        hook_install(policydb_write);
        if (!hook_success(policydb_write)) goto exit;
        pr_info("PDBF: enabled !\n");
    } else {
        pr_info("PDBF: Always enabled !\n");
    }
    ret = true;

exit:
    return ret;
}

static inline bool uninstallHook()
{
    if (hook_success(policydb_write)) {
        unhook((void *)hook_original(policydb_write));
        hook_err(policydb_write) = HOOK_NOT_HOOK;
        pr_info("PDBF: disbaled !\n");
    } else {
        pr_info("PDBF: Always disabled !\n");
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

static long selinux_policydb_fix_init(const char *args, const char *event, void *__user reserved)
{
    long ret = 0;

    printInfo();
    pr_info("PDBF: initializing ...\n");

    if (hfr_control(true)) {
        pr_info("PDBF: Initialization successful!\n");
        goto exit;
    }

    ret = 1;
    pr_info("PDBF: initializing failed!\n");
exit:
    return ret;
}

static long selinux_policydb_fix_control0(const char *args, char *__user out_msg, int outlen)
{
    if (args) {
        if (strncmp(args, "enable", 6) == 0) {
            writeOutMsg(out_msg, &outlen, hfr_control(true) ? "PDBF: enabled !" : "PDBF: enable fail !");
        } else if (strncmp(args, "disable", 7) == 0) {
            writeOutMsg(out_msg, &outlen, hfr_control(false) ? "PDBF: disbaled !" : "PDBF: disbale fail !");
        } else {
            pr_info("PDBF: ctl error, args=%s\n", args);
            writeOutMsg(out_msg, &outlen, "PDBF: ctl error !");
            return -1;
        }
    }
    return 0;
}

static long selinux_policydb_fix_exit(void *__user reserved)
{
    uninstallHook();
    pr_info("PDBF: Exiting ...\n");
    return 0;
}

KPM_INIT(selinux_policydb_fix_init);
KPM_CTL0(selinux_policydb_fix_control0);
KPM_EXIT(selinux_policydb_fix_exit);
