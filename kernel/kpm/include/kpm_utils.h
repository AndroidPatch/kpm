#ifndef _KPM_UTILS_H
#define _KPM_UTILS_H

#include <asm/current.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/sched.h>

#include "sk_func.h"

#define TASK_EXT_MAGIC 0x1158115811581158

struct task_ext
{
    // first
    pid_t pid;
    pid_t tgid;
    int super;
    int _;
    int selinux_allow;
    int priv_selinux_allow;
    void *__;
    // last
    uint64_t magic;
};

static inline int task_ext_valid(struct task_ext *ext)
{
    return ext && (ext->magic == TASK_EXT_MAGIC);
}

static inline void get_current_ids(pid_t *pid, pid_t *tgid)
{
    struct task_ext *ext = current_ext; //current_ext
    if (likely(task_ext_valid(ext))) {
        *pid = ext->pid;
        *tgid = ext->tgid;
    }
}

static inline void set_priv_selinx_allow(int val)
{
    struct task_ext *ext = current_ext; //current_ext
    if (likely(task_ext_valid(ext))) {
        ext->priv_selinux_allow = val;
        dsb(ish);
    }
}

static inline uid_t current_uid()
{
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    uid_t uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    return uid;
}

static inline void writeOutMsg(char *__user out_msg, int *outlen, const char *msg)
{
    *outlen = strlen(msg);
    compat_copy_to_user(out_msg, msg, *outlen);
}

//  __task_pid_nr_ns
pid_t skfunc_def(__task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = NULL;
static inline pid_t ___task_pid_nr_ns(struct task_struct *task, enum pid_type type, struct pid_namespace *ns)
{
    return skfunc(__task_pid_nr_ns)(task, type, ns);
}
// end

static inline bool initializationKpmFuncs()
{
    bool ret = false;

    skfunc_match(__task_pid_nr_ns, NULL, NULL);
    if (!skfunc(__task_pid_nr_ns)) goto exit;
    pr_info("KPM: __task_pid_nr_ns addr: %llx\n", skfunc(__task_pid_nr_ns));

    ret = true;
exit:
    return ret;
}

#endif /* _KPM_UTILS_H */
