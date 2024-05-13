/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

/*   SPDX-License-Identifier: GPL-3.0-only   */
/*
 * Copyright (C) 2024 Nep-Timeline. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <taskext.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/string.h>

#include "re_kernel.h"
#include "re_utils.h"

KPM_NAME("re_kernel");
KPM_VERSION(RK_VERSION);
KPM_LICENSE("GPL v3");
KPM_AUTHOR("Nep-Timeline, lzghzr");
KPM_DESCRIPTION("Re:Kernel, support 4.4, 4.9, 4.14, 4.19, 5.4, 5.10, 5.15");

#define NETLINK_REKERNEL_MAX 26
#define NETLINK_REKERNEL_MIN 22
#define REKERNEL_USER_PORT 100
#define REKERNEL_PACKET_SIZE 128
#define REKERNEL_MIN_USERAPP_UID 10000
#define REKERNEL_MAX_SYSTEM_UID 2000
#define REKERNEL_WARN_AHEAD_MSGS 3
#define REKERNEL_RESERVE_ORDER 17
#define REKERNEL_WARN_AHEAD_SPACE (1 << REKERNEL_RESERVE_ORDER)

#define IZERO (1UL << 0x10)
#define UZERO (1UL << 0x20)

// 延迟加载, KernelPatch支持 事件加载 后弃用
static struct file* (*do_filp_open)(int dfd, struct filename* pathname, const struct open_flags* op);
// rcu_read_lock && rcu_read_unlock
void kfunc_def(__rcu_read_lock)(void);
void kfunc_def(__rcu_read_unlock)(void);
// binder_inner_proc_lock && binder_inner_proc_unlock
void kfunc_def(_binder_inner_proc_lock)(struct binder_proc* proc, int line);
void kfunc_def(_binder_inner_proc_unlock)(struct binder_proc* proc, int line);
// pid
struct pid* kfunc_def(get_task_pid)(struct task_struct* task, enum pid_type type);
pid_t kfunc_def(pid_vnr)(struct pid* pid);
// frozen_task_group
atomic_t kvar_def(system_freezing_cnt);
bool kfunc_def(freezing_slow_path)(struct task_struct* p);
// send_netlink_message
struct sk_buff* kfunc_def(__alloc_skb)(unsigned int size, gfp_t gfp_mask, int flags, int node);
struct nlmsghdr* kfunc_def(__nlmsg_put)(struct sk_buff* skb, u32 portid, u32 seq, int type, int len, int flags);
void kfunc_def(kfree_skb)(struct sk_buff* skb);
int kfunc_def(netlink_unicast)(struct sock* ssk, struct sk_buff* skb, u32 portid, int nonblock);
// start_rekernel_server
static struct net kvar_def(init_net);
struct sock* kfunc_def(__netlink_kernel_create)(struct net* net, int unit, struct module* module, struct netlink_kernel_cfg* cfg);
void kfunc_def(netlink_kernel_release)(struct sock* sk);
// prco
struct proc_dir_entry* kfunc_def(proc_mkdir)(const char* name, struct proc_dir_entry* parent);
struct proc_dir_entry* kfunc_def(proc_create_data)(const char* name, umode_t mode, struct proc_dir_entry* parent, const struct file_operations* proc_fops, void* data);
void kfunc_def(proc_remove)(struct proc_dir_entry* de);
// hook binder_alloc_new_buf_locked
static struct binder_buffer* (*binder_alloc_new_buf_locked)(struct binder_alloc* alloc, size_t data_size, size_t offsets_size, size_t extra_buffers_size, int is_async, int pid);
// hook binder_transaction
static struct binder_node* (*binder_get_node_from_ref)(struct binder_proc* proc, u32 desc, bool need_strong_ref, struct binder_ref_data* rdata);
static void (*binder_dec_node_tmpref)(struct binder_node* node);
static int (*security_binder_transaction)(struct task_struct* from, struct task_struct* to);
static void (*binder_transaction)(struct binder_proc* proc, struct binder_thread* thread, struct binder_transaction_data* tr, int reply, binder_size_t extra_buffers_size);
// hook do_send_sig_info
static int (*do_send_sig_info)(int sig, struct siginfo* info, struct task_struct* p, enum pid_type type);

static uint64_t task_struct_flags_offset = UZERO, task_struct_frozen_offset = UZERO, task_struct_css_set_offset = UZERO,
binder_proc_context_offset = UZERO, binder_proc_binder_alloc_offset = UZERO,
binder_alloc_vma_offset = UZERO, binder_alloc_free_async_space_offset = UZERO, binder_alloc_pid_offset = UZERO,
css_set_dfl_cgrp_offset = UZERO,
cgroup_flags_offset = UZERO,
task_struct_frozen_bit = UZERO,
oneway = UZERO;

static struct sock* rekernel_netlink;
static long rekernel_netlink_unit = UZERO;
static struct proc_dir_entry* rekernel_dir, * rekernel_unit_entry;

static const struct file_operations rekernel_unit_fops = {
    .open = NULL,
    .read = NULL,
    .release = NULL,
    .owner = THIS_MODULE,
};
// pid
static inline pid_t task_pid(struct task_struct* task) {
    struct pid* pid = get_task_pid(task, PIDTYPE_PID);
    return pid_vnr(pid);
}
// 判断线程是否进入 frozen 状态
static inline bool cgroup_task_frozen(struct task_struct* task)
{
    bool ret = false;
    if (task_struct_frozen_offset == UZERO) {
        return ret;
    }
    unsigned int frozen = *(unsigned int*)((uintptr_t)task + task_struct_frozen_offset);
    ret = bit(frozen, task_struct_frozen_bit);
    return ret;
}
static inline bool cgroup_task_freeze(struct task_struct* task)
{
    bool ret = false;
    if (task_struct_css_set_offset == UZERO || css_set_dfl_cgrp_offset == UZERO || cgroup_flags_offset == UZERO) {
        return ret;
    }
    unsigned int task_flags = *(unsigned int*)((uintptr_t)task + task_struct_flags_offset);
    if (task_flags & PF_KTHREAD) {
        return ret;
    }

    rcu_read_lock();
    struct css_set __rcu* css_set = *(struct css_set __rcu**)((uintptr_t)task + task_struct_css_set_offset);
    struct cgroup* cgrp = *(struct cgroup**)((uintptr_t)css_set + css_set_dfl_cgrp_offset);
    unsigned long cgrp_flags = *(unsigned long*)((uintptr_t)cgrp + cgroup_flags_offset);
    ret = test_bit(CGRP_FREEZE, &cgrp_flags);
    rcu_read_unlock();
    return ret;
}
static inline bool frozen(struct task_struct* p)
{
    unsigned int flags = *(unsigned int*)((uintptr_t)p + task_struct_flags_offset);
    return flags & PF_FROZEN;
}
static inline bool freezing(struct task_struct* p)
{
    if (likely(!atomic_read(kvar(system_freezing_cnt))))
        return false;
    return freezing_slow_path(p);
}
static inline bool frozen_task_group(struct task_struct* task)
{
    return (cgroup_task_frozen(task) || cgroup_task_freeze(task) || frozen(task) || freezing(task));
}

// 发送 netlink 消息
static int send_netlink_message(char* msg, uint16_t len)
{
    struct sk_buff* skbuffer;
    struct nlmsghdr* nlhdr;

    skbuffer = nlmsg_new(len, GFP_ATOMIC);
    if (!skbuffer) {
        printk("netlink alloc failure.\n");
        return -1;
    }

    nlhdr = nlmsg_put(skbuffer, 0, 0, rekernel_netlink_unit, len, 0);
    if (!nlhdr) {
        printk("nlmsg_put failaure.\n");
        nlmsg_free(skbuffer);
        return -1;
    }

    memcpy(nlmsg_data(nlhdr), msg, len);
    return netlink_unicast(rekernel_netlink, skbuffer, REKERNEL_USER_PORT, MSG_DONTWAIT);
}

// 创建 netlink 服务
static int start_rekernel_server(void)
{
    struct netlink_kernel_cfg rekernel_cfg = {
        .input = NULL,
    };
    for (rekernel_netlink_unit = NETLINK_REKERNEL_MAX; rekernel_netlink_unit >= NETLINK_REKERNEL_MIN; rekernel_netlink_unit--) {
        rekernel_netlink = netlink_kernel_create(kvar(init_net), rekernel_netlink_unit, &rekernel_cfg);
        if (rekernel_netlink != NULL) {
            break;
        }
    }
    if (rekernel_netlink == NULL) {
        printk("Failed to create Re:Kernel server!\n");
        return -1;
    }
    printk("Created Re:Kernel server! NETLINK UNIT: %d\n", rekernel_netlink_unit);

    rekernel_dir = proc_mkdir("rekernel", NULL);
    if (!rekernel_dir) {
        printk("create /proc/rekernel failed!\n");
    } else {
        char buff[32];
        sprintf(buff, "%d", rekernel_netlink_unit);
        rekernel_unit_entry = proc_create_data(buff, 0644, rekernel_dir, &rekernel_unit_fops, NULL);
        if (!rekernel_unit_entry) {
            printk("create rekernel unit failed!\n");
        }
    }

    return 0;
}

static void security_binder_transaction_before(hook_fargs2_t* args, void* udata)
{
    struct task_struct* from_task = (struct task_struct*)args->arg0;
    struct task_struct* to_task = (struct task_struct*)args->arg1;
    if (from_task != NULL
        && to_task != NULL
        && (task_uid(to_task).val > REKERNEL_MIN_USERAPP_UID)
        && (get_task_ext(from_task)->pid != get_task_ext(to_task)->pid)
        && frozen_task_group(to_task)) {
        char binder_kmsg[REKERNEL_PACKET_SIZE];
        snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", oneway, get_task_ext(from_task)->pid, task_uid(from_task).val, get_task_ext(to_task)->pid, task_uid(to_task).val);
#ifdef DEBUG
        printk("re_kernel: %s\n", binder_kmsg);
#endif /* DEBUG */
        send_netlink_message(binder_kmsg, strlen(binder_kmsg));
    }
}

static void binder_alloc_new_buf_locked_before(hook_fargs6_t* args, void* udata)
{
    struct binder_alloc* alloc = (struct binder_alloc*)args->arg0;
    size_t data_size = (size_t)args->arg1;
    size_t offsets_size = (size_t)args->arg2;
    size_t extra_buffers_size = (size_t)args->arg3;
    int is_async = (int)args->arg4;
    // 计算 free_async_space_offset
    if (binder_alloc_free_async_space_offset == UZERO) {
        binder_alloc_free_async_space_offset = IZERO;
        int first = 0;
        for (u64 i = 0x30;i < 0x100;i += 0x8) {
            u64 ptr = *(u64*)((uintptr_t)alloc + i);
            if (ptr > 1L << 0x8 && ptr < UZERO) {
                if (first && (i - first) == 0x10) {
                    binder_alloc_vma_offset = i - 0x48;
                    binder_alloc_free_async_space_offset = i - 0x10;
                    // buffer_size_offset = i;
                    binder_alloc_pid_offset = i + 0xC;
                    break;
                } else {
                    first = i;
                }
            }
        }
    }
    // 计算 binder_proc_binder_alloc_offset
    if (binder_proc_binder_alloc_offset == UZERO && binder_alloc_pid_offset != UZERO) {
        binder_proc_binder_alloc_offset = IZERO;
        u32 pid = *(u32*)((uintptr_t)alloc + binder_alloc_pid_offset);
        for (u64 i = 0;i < 0x200;i += 0x8) {
            if (pid == *(u32*)((uintptr_t)alloc - i)) {
                binder_proc_binder_alloc_offset = i + 0x40;
                break;
            }
        }
    }

    if (binder_alloc_free_async_space_offset == IZERO || binder_proc_binder_alloc_offset == IZERO) {
        return;
    }
    if (!*(struct vm_area_struct**)((uintptr_t)alloc + binder_alloc_vma_offset)) {
        return;
    }
    size_t size, data_offsets_size;
    data_offsets_size = ALIGN(data_size, sizeof(void*)) + ALIGN(offsets_size, sizeof(void*));
    if (data_offsets_size < data_size || data_offsets_size < offsets_size) {
        return;
    }
    size = data_offsets_size + ALIGN(extra_buffers_size, sizeof(void*));
    if (size < data_offsets_size || size < extra_buffers_size) {
        return;
    }
    size_t free_async_space = *(size_t*)((uintptr_t)alloc + binder_alloc_free_async_space_offset);
    if (is_async
        && (free_async_space < REKERNEL_WARN_AHEAD_MSGS * (size + sizeof(struct binder_buffer))
            || (free_async_space < REKERNEL_WARN_AHEAD_SPACE))) {
        struct binder_proc* target_proc = *(struct binder_proc**)((uintptr_t)alloc - binder_proc_binder_alloc_offset);
        if (target_proc
            && (NULL != target_proc->tsk)
            && frozen_task_group(target_proc->tsk)) {
            char binder_kmsg[REKERNEL_PACKET_SIZE];
            snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=free_buffer_full,oneway=1,from_pid=%d,from=%d,target_pid=%d,target=%d;", get_current_task_ext()->pid, task_uid(current).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
            printk("re_kernel: %s\n", binder_kmsg);
#endif /* DEBUG */
            send_netlink_message(binder_kmsg, strlen(binder_kmsg));
        }
    }
}

static void binder_transaction_before(hook_fargs5_t* args, void* udata)
{
    struct binder_proc* proc = (struct binder_proc*)args->arg0;
    struct binder_thread* thread = (struct binder_thread*)args->arg1;
    struct binder_transaction_data* tr = (struct binder_transaction_data*)args->arg2;
    int reply = (int)args->arg3;

    struct binder_proc* target_proc = NULL;
    struct binder_node* target_node = NULL;
    if (reply) {
        binder_inner_proc_lock(proc);
        struct binder_transaction* in_reply_to = thread->transaction_stack;
        if (in_reply_to == NULL || in_reply_to->to_thread != thread) {
            binder_inner_proc_unlock(proc);
            return;
        }
        struct binder_thread* target_thread = in_reply_to->from;
        if (target_thread == NULL || target_thread->transaction_stack != in_reply_to) {
            binder_inner_proc_unlock(proc);
            return;
        }
        target_proc = target_thread->proc;

        if (target_proc
            && (NULL != target_proc->tsk)
            && (NULL != proc->tsk)
            && (task_uid(target_proc->tsk).val <= REKERNEL_MAX_SYSTEM_UID)
            && (proc->pid != target_proc->pid)
            && frozen_task_group(target_proc->tsk)) {
            char binder_kmsg[REKERNEL_PACKET_SIZE];
            snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=reply,oneway=0,from_pid=%d,from=%d,target_pid=%d,target=%d;", proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
            printk("re_kernel: %s\n", binder_kmsg);
#endif /* DEBUG */
            binder_inner_proc_unlock(proc);
            send_netlink_message(binder_kmsg, strlen(binder_kmsg));
            return;
        }
        binder_inner_proc_unlock(proc);
    } else {
        if (binder_get_node_from_ref) {
            if (tr->target.handle) {
                target_node = binder_get_node_from_ref(proc, tr->target.handle, true, NULL);
                if (target_node) {
                    target_proc = target_node->proc;
                }
            } else if (binder_proc_context_offset != IZERO) {
                struct binder_context* context = *(struct binder_context**)((uintptr_t)proc + binder_proc_context_offset);
                target_node = context->binder_context_mgr_node;
                if (target_node) {
                    target_proc = target_node->proc;
                }
            }
            if (target_proc
                && (NULL != target_proc->tsk)
                && (NULL != proc->tsk)
                && (task_uid(target_proc->tsk).val > REKERNEL_MIN_USERAPP_UID)
                && (proc->pid != target_proc->pid)
                && frozen_task_group(target_proc->tsk)) {
                char binder_kmsg[REKERNEL_PACKET_SIZE];
                snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Binder,bindertype=transaction,oneway=%d,from_pid=%d,from=%d,target_pid=%d,target=%d;", (tr->flags & TF_ONE_WAY), proc->pid, task_uid(proc->tsk).val, target_proc->pid, task_uid(target_proc->tsk).val);
#ifdef DEBUG
                printk("re_kernel: %s\n", binder_kmsg);
#endif /* DEBUG */
                send_netlink_message(binder_kmsg, strlen(binder_kmsg));
            }
        } else {
            // 4.4 并没有处理并发
            oneway = (tr->flags & TF_ONE_WAY);
        }
    }
}

static void do_send_sig_info_before(hook_fargs4_t* args, void* udata)
{
    int sig = (int)args->arg0;
    struct task_struct* dst = (struct task_struct*)args->arg2;

    if ((sig == SIGKILL || sig == SIGTERM || sig == SIGABRT || sig == SIGQUIT)
        && frozen_task_group(dst)) {
        char binder_kmsg[REKERNEL_PACKET_SIZE];
        // SIGKILL 信号可能会直接释放内存, 导致 get_task_ext 崩溃, 需使用 refcount_inc(&pid->count) 告知线程正在使用
        snprintf(binder_kmsg, sizeof(binder_kmsg), "type=Signal,signal=%d,killer_pid=%d,killer=%d,dst_pid=%d,dst=%d;", sig, task_pid(current), task_uid(current).val, task_pid(dst), task_uid(dst).val);
#ifdef DEBUG
        printk("re_kernel: %s\n", binder_kmsg);
#endif /* DEBUG */
        send_netlink_message(binder_kmsg, strlen(binder_kmsg));
    }
}

static long start_hook()
{
    if (start_rekernel_server() != 0) {
        return -1;
    }
    if (security_binder_transaction) {
        hook_func(security_binder_transaction, 2, security_binder_transaction_before, 0, 0);
    }
    hook_func(binder_alloc_new_buf_locked, 6, binder_alloc_new_buf_locked_before, 0, 0);
    hook_func(binder_transaction, 5, binder_transaction_before, 0, 0);
    hook_func(do_send_sig_info, 4, do_send_sig_info_before, 0, 0);
    return 0;
}

static char ap[] = "/proc/";
static void do_filp_open_after(hook_fargs3_t* args, void* udata)
{
    char** fname = *(char***)args->arg1;
    if (unlikely(!memcmp(fname, ap, sizeof(ap) - 1))) {
        start_hook();
        unhook_func(do_filp_open);
    }
}

static long calculate_offsets() {
    // 获取 binder_proc 相关偏移，没有就是不支持, 目前只有 4.4 不支持
    // binder_proc->context
    uint32_t* binder_transaction_src = (uint32_t*)binder_transaction;
    for (u32 i = 0; i < 0x20; i++) {
        if (binder_transaction_src[i] == ARM64_RET) {
            break;
        } else if ((binder_transaction_src[i] & MASK_LDR_64_X0) == INST_LDR_64_X0) {
            uint64_t imm12 = bits32(binder_transaction_src[i], 21, 10);
            binder_proc_context_offset = sign64_extend((imm12 << 0b11u), 16u);
            break;
        }
    }
    // 获取 cgroup 相关偏移，没有就是不支持 CGRP_FREEZE
    // cgroup_exit_count = 1; task->css_set
    // cgroup_exit_count = 2; css_set->dfl_cgrp
    // cgroup_exit_count = 3; cgroup->flags
    void (*cgroup_exit)(struct task_struct* task);
    lookup_name(cgroup_exit);

    bool cgroup_exit_start = false;
    u32 cgroup_exit_count = 0;
    uint32_t* cgroup_exit_src = (uint32_t*)cgroup_exit;
    for (u32 i = 0; i < 0x50; i++) {
        if (cgroup_exit_src[i] == ARM64_RET) {
            break;
        } else if (cgroup_exit_start && cgroup_exit_count == 2 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            cgroup_flags_offset = sign64_extend((imm12 << 0b11u), 16u);
            break;
        } else if (cgroup_exit_start && cgroup_exit_count == 1 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            css_set_dfl_cgrp_offset = sign64_extend((imm12 << 0b11u), 16u);
            cgroup_exit_count = 2;
        } else if (cgroup_exit_start && cgroup_exit_count == 0 && (cgroup_exit_src[i] & MASK_LDR_64_) == INST_LDR_64_) {
            uint64_t imm12 = bits32(cgroup_exit_src[i], 21, 10);
            task_struct_css_set_offset = sign64_extend((imm12 << 0b11u), 16u);
            cgroup_exit_count = 1;
        } else if (cgroup_exit_start && cgroup_exit_count == 0 && (cgroup_exit_src[i] & MASK_ADD_64) == INST_ADD_64) {
            uint32_t sh = bit(cgroup_exit_src[i], 22);
            uint64_t imm12 = imm12 = bits32(cgroup_exit_src[i], 21, 10);
            if (sh) {
                task_struct_css_set_offset = sign64_extend((imm12 << 12u), 16u);
            } else {
                task_struct_css_set_offset = sign64_extend((imm12), 16u);
            }
            cgroup_exit_count = 1;
        } else if ((cgroup_exit_src[i] & MASK_TBNZ) == INST_TBNZ) {
            cgroup_exit_start = true;
        }
    }
    // 获取 task->frozen, 没有就是不支持 PF_FROZEN
    void (*recalc_sigpending_and_wake)(struct task_struct* t);
    lookup_name(recalc_sigpending_and_wake);

    uint32_t* recalc_sigpending_and_wake_src = (uint32_t*)recalc_sigpending_and_wake;
    for (u32 i = 0; i < 0x20; i++) {
        if (recalc_sigpending_and_wake_src[i] == ARM64_RET) {
            break;
        } else if ((recalc_sigpending_and_wake_src[i] & MASK_TBZ) == INST_TBZ || (recalc_sigpending_and_wake_src[i] & MASK_TBNZ) == INST_TBNZ) {
            if ((recalc_sigpending_and_wake_src[i - 1] & MASK_LDRB) == INST_LDRB) {
                task_struct_frozen_bit = bits32(recalc_sigpending_and_wake_src[i], 23, 19);
                uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i - 1], 21, 10);
                task_struct_frozen_offset = sign64_extend((imm12), 16u);
                break;
            } else if ((recalc_sigpending_and_wake_src[i - 1] & MASK_LDRH) == INST_LDRH) {
                task_struct_frozen_bit = bits32(recalc_sigpending_and_wake_src[i], 23, 19);
                uint64_t imm12 = bits32(recalc_sigpending_and_wake_src[i - 1], 21, 10);
                task_struct_frozen_offset = sign64_extend((imm12 << 1u), 16u);
                break;
            }
        }
    }

    // 获取 task->flags
    uint32_t* freezing_slow_path_src = (uint32_t*)kfunc(freezing_slow_path);
    for (u32 i = 0; i < 0x20; i++) {
        if (freezing_slow_path_src[i] == ARM64_RET) {
            break;
        } else if ((freezing_slow_path_src[i] & MASK_LDR_64_X0) == INST_LDR_64_X0) {
            uint64_t imm12 = bits32(freezing_slow_path_src[i], 21, 10);
            task_struct_flags_offset = sign64_extend((imm12 << 0b11u), 16u);
            break;
        }
    }
    if (task_struct_flags_offset == UZERO) {
        return -11;
    }

    return 0;
}

static long inline_hook_init(const char* args, const char* event, void* __user reserved)
{
    lookup_name(do_filp_open);
    kfunc_lookup_name(__rcu_read_lock);
    kfunc_lookup_name(__rcu_read_unlock);
    kfunc_lookup_name(_binder_inner_proc_lock);
    kfunc_lookup_name(_binder_inner_proc_unlock);
    kfunc_lookup_name(get_task_pid);
    kfunc_lookup_name(pid_vnr);

    kvar_lookup_name(system_freezing_cnt);
    kfunc_lookup_name(freezing_slow_path);
    kfunc_lookup_name(__alloc_skb);
    kfunc_lookup_name(__nlmsg_put);
    kfunc_lookup_name(kfree_skb);
    kfunc_lookup_name(netlink_unicast);
    kvar_lookup_name(init_net);
    kfunc_lookup_name(__netlink_kernel_create);
    kfunc_lookup_name(netlink_kernel_release);
    kfunc_lookup_name(proc_mkdir);
    kfunc_lookup_name(proc_create_data);
    kfunc_lookup_name(proc_remove);

    // 兼容 4.9
    binder_alloc_new_buf_locked = (typeof(binder_alloc_new_buf_locked))kallsyms_lookup_name("binder_alloc_new_buf_locked");
    if (binder_alloc_new_buf_locked) {
        pr_info("kernel function %s addr: %llx\n", "binder_alloc_new_buf_locked", binder_alloc_new_buf_locked);
    } else {
        binder_alloc_new_buf_locked = (typeof(binder_alloc_new_buf_locked))kallsyms_lookup_name("binder_alloc_new_buf");
        if (binder_alloc_new_buf_locked) {
            pr_info("kernel function %s addr: %llx\n", "binder_alloc_new_buf", binder_alloc_new_buf_locked);
        } else {
            return -21;
        }
    }
    // 兼容 4.4
    binder_get_node_from_ref = (typeof(binder_get_node_from_ref))kallsyms_lookup_name("binder_get_node_from_ref");
    if (binder_get_node_from_ref) {
        pr_info("kernel function %s addr: %llx\n", "binder_get_node_from_ref", binder_get_node_from_ref);
    } else {
        security_binder_transaction = (typeof(security_binder_transaction))kallsyms_lookup_name("security_binder_transaction");
        if (security_binder_transaction) {
            pr_info("kernel function %s addr: %llx\n", "security_binder_transaction", security_binder_transaction);
        } else {
            return -21;
        }
    }

    lookup_name(binder_dec_node_tmpref);
    lookup_name(binder_transaction);
    lookup_name(do_send_sig_info);

    int rc = calculate_offsets();
    if (rc < 0) {
        return rc;
    }

    char load_file[] = "load-file";
    if (event && !memcmp(event, load_file, sizeof(load_file))) {
        return start_hook();
    } else {
        hook_func(do_filp_open, 3, 0, do_filp_open_after, 0);
    }

    return 0;
}

static long inline_hook_control0(const char* ctl_args, char* __user out_msg, int outlen)
{
    char msg[64];
    snprintf(msg, sizeof(msg), "f_p=0x%llx, b_p=0x%llx", binder_alloc_free_async_space_offset, binder_proc_binder_alloc_offset);
    compat_copy_to_user(out_msg, msg, sizeof(msg));
    return 0;
}

static long inline_hook_exit(void* __user reserved)
{
    if (rekernel_netlink) {
        netlink_kernel_release(rekernel_netlink);
    }
    if (rekernel_dir) {
        proc_remove(rekernel_dir);
    }
    unhook_func(security_binder_transaction);
    unhook_func(binder_alloc_new_buf_locked);
    unhook_func(binder_transaction);
    unhook_func(do_send_sig_info);

    return 0;
}

KPM_INIT(inline_hook_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_exit);
