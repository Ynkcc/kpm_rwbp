#include "hwbp.h"
#include "kernel_compat.h"
#include <syscall.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/err.h>

#define MY_GFP_ATOMIC 0x20U

// 默认启用方案 B（连续触发/步过模式），如果注释掉则使用方案 A（单次触发模式）
// #define CONFIG_MODIFY_HIT_NEXT_MODE 1

#ifndef PSR_MODE32_BIT
#define PSR_MODE32_BIT 0x00000010
#endif
#ifndef PSR_AA32_T_BIT
#define PSR_AA32_T_BIT 0x00000020
#endif

// ARM64 调试寄存器相关定义
#define AARCH64_DBG_REG_BVR   0
#define AARCH64_DBG_REG_BCR  16
#define AARCH64_DBG_REG_WVR  32
#define AARCH64_DBG_REG_WCR  48

// ARM64 调试寄存器访问宏
#define AARCH64_DBG_READ_WVR(N, VAL) \
    asm volatile("mrs %0, dbgwvr" #N "_el1" : "=r"(VAL))

#define AARCH64_DBG_WRITE_WVR(N, VAL) \
    asm volatile("msr dbgwvr" #N "_el1, %0" :: "r"(VAL))

#define AARCH64_DBG_READ_WCR(N, VAL) \
    asm volatile("mrs %0, dbgwcr" #N "_el1" : "=r"(VAL))

#define AARCH64_DBG_WRITE_WCR(N, VAL) \
    asm volatile("msr dbgwcr" #N "_el1, %0" :: "r"(VAL))

#define AARCH64_DBG_READ_BVR(N, VAL) \
    asm volatile("mrs %0, dbgbvr" #N "_el1" : "=r"(VAL))

#define AARCH64_DBG_WRITE_BVR(N, VAL) \
    asm volatile("msr dbgbvr" #N "_el1, %0" :: "r"(VAL))

#define AARCH64_DBG_READ_BCR(N, VAL) \
    asm volatile("mrs %0, dbgbcr" #N "_el1" : "=r"(VAL))

#define AARCH64_DBG_WRITE_BCR(N, VAL) \
    asm volatile("msr dbgbcr" #N "_el1, %0" :: "r"(VAL))

#ifndef ID_AA64DFR0_EL1
#define ID_AA64DFR0_EL1 0
#endif

#ifndef read_cpuid
#define read_cpuid(reg) 0
#endif

// 最大保存的命中记录数
#define MAX_HIT_RECORDS_PER_BP 64

// 寄存器快照结构体
struct bp_regs_snapshot {
    uint64_t regs[31];  // X0-X30
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

// 单条命中记录
struct bp_hit_record {
    uint64_t hit_time;
    uint32_t task_id;
    uint32_t _pad;
    uint64_t hit_addr;
    struct bp_regs_snapshot regs_info;
};

struct bp_hit_info {
    uint64_t addr;
    uint32_t pid;
    uint32_t hit_count;
};

struct bp_node {
    struct list_head list;
    struct perf_event *bp;
    uint32_t pid;
    uint64_t addr;
    uint32_t type;
    uint32_t len;
    uint64_t hit_count;
    struct work_struct unreg_work;
    struct perf_event_attr orig_attr;
    bool is_temp_bp;
    struct work_struct recovery_work;
    uint32_t scheme;
    struct perf_event_attr next_instruction_attr;
    // 命中记录环形缓冲区
    struct bp_hit_record hit_records[MAX_HIT_RECORDS_PER_BP];
    uint32_t hit_record_head;
    uint32_t hit_record_count;
    spinlock_t hit_records_lock;
};

struct register_work {
    struct work_struct work;
    uint32_t pid;
    uint64_t addr;
    uint32_t type;
    uint32_t len;
    uint32_t scheme;
};

static LIST_HEAD(bp_list);
static DEFINE_SPINLOCK(bp_list_lock);
volatile int in_flight = 0;
static void (*kf_on_each_cpu)(void (*func)(void *info), void *info, int wait) = NULL;

static void my_init_work(struct work_struct *work, work_func_t func) {
    work->data = 0;
    work->entry.next = (struct my_list_head *)&work->entry;
    work->entry.prev = (struct my_list_head *)&work->entry;
    work->func = func;
}

// PERF_TYPE_BREAKPOINT is 5 in Linux kernel
#ifndef PERF_TYPE_BREAKPOINT
#define PERF_TYPE_BREAKPOINT 5
#endif

// 初始化 perf_event_attr 用于硬件断点
static void init_perf_event_attr_bp(struct perf_event_attr *attr, uint32_t type) {
    memset(attr, 0, sizeof(struct perf_event_attr));
    attr->type = PERF_TYPE_BREAKPOINT;
    // 根据内核版本设置正确的 size（从内核源码确认）
    // 4.19.x: size = 112, 6.6.x: size = 136
    if (KERNEL_VERSION_MAJOR(kver) >= 6) {
        attr->size = 136;
    } else {
        attr->size = 112;
    }
    attr->bp_type = type;  // 0=execution, 1=write, 2=read, 3=access
    attr->sample_period = 1;  // 每个命中都触发回调
}

// 设置断点排除选项
static void set_perf_event_exclude(struct perf_event_attr *attr, int exclude_user, int exclude_kernel, int exclude_hv) {
    attr->exclude_user = exclude_user;
    attr->exclude_kernel = exclude_kernel;
    attr->exclude_hv = exclude_hv;
}

// 设置断点地址和长度
static void set_perf_event_bp_addr(struct perf_event_attr *attr, uint64_t addr, uint64_t len) {
    attr->bp_addr = addr;
    attr->bp_len = len;
}

static int get_cpu_num_wrps(void) {
    return ((read_cpuid(ID_AA64DFR0_EL1) >> 20) & 0xf) + 1;
}

static uint64_t read_wb_reg(int reg_idx, int n) {
    uint64_t val = 0;
    if (reg_idx == AARCH64_DBG_REG_WVR) {
        switch(n) {
            case 0: AARCH64_DBG_READ_WVR(0, val); break;
            case 1: AARCH64_DBG_READ_WVR(1, val); break;
            case 2: AARCH64_DBG_READ_WVR(2, val); break;
            case 3: AARCH64_DBG_READ_WVR(3, val); break;
            case 4: AARCH64_DBG_READ_WVR(4, val); break;
            case 5: AARCH64_DBG_READ_WVR(5, val); break;
            case 6: AARCH64_DBG_READ_WVR(6, val); break;
            case 7: AARCH64_DBG_READ_WVR(7, val); break;
            case 8: AARCH64_DBG_READ_WVR(8, val); break;
            case 9: AARCH64_DBG_READ_WVR(9, val); break;
            case 10: AARCH64_DBG_READ_WVR(10, val); break;
            case 11: AARCH64_DBG_READ_WVR(11, val); break;
            case 12: AARCH64_DBG_READ_WVR(12, val); break;
            case 13: AARCH64_DBG_READ_WVR(13, val); break;
            case 14: AARCH64_DBG_READ_WVR(14, val); break;
            case 15: AARCH64_DBG_READ_WVR(15, val); break;
        }
    } else if (reg_idx == AARCH64_DBG_REG_WCR) {
        switch(n) {
            case 0: AARCH64_DBG_READ_WCR(0, val); break;
            case 1: AARCH64_DBG_READ_WCR(1, val); break;
            case 2: AARCH64_DBG_READ_WCR(2, val); break;
            case 3: AARCH64_DBG_READ_WCR(3, val); break;
            case 4: AARCH64_DBG_READ_WCR(4, val); break;
            case 5: AARCH64_DBG_READ_WCR(5, val); break;
            case 6: AARCH64_DBG_READ_WCR(6, val); break;
            case 7: AARCH64_DBG_READ_WCR(7, val); break;
            case 8: AARCH64_DBG_READ_WCR(8, val); break;
            case 9: AARCH64_DBG_READ_WCR(9, val); break;
            case 10: AARCH64_DBG_READ_WCR(10, val); break;
            case 11: AARCH64_DBG_READ_WCR(11, val); break;
            case 12: AARCH64_DBG_READ_WCR(12, val); break;
            case 13: AARCH64_DBG_READ_WCR(13, val); break;
            case 14: AARCH64_DBG_READ_WCR(14, val); break;
            case 15: AARCH64_DBG_READ_WCR(15, val); break;
        }
    } else if (reg_idx == AARCH64_DBG_REG_BVR) {
        switch(n) {
            case 0: AARCH64_DBG_READ_BVR(0, val); break;
            case 1: AARCH64_DBG_READ_BVR(1, val); break;
            case 2: AARCH64_DBG_READ_BVR(2, val); break;
            case 3: AARCH64_DBG_READ_BVR(3, val); break;
            case 4: AARCH64_DBG_READ_BVR(4, val); break;
            case 5: AARCH64_DBG_READ_BVR(5, val); break;
            case 6: AARCH64_DBG_READ_BVR(6, val); break;
            case 7: AARCH64_DBG_READ_BVR(7, val); break;
            case 8: AARCH64_DBG_READ_BVR(8, val); break;
            case 9: AARCH64_DBG_READ_BVR(9, val); break;
            case 10: AARCH64_DBG_READ_BVR(10, val); break;
            case 11: AARCH64_DBG_READ_BVR(11, val); break;
            case 12: AARCH64_DBG_READ_BVR(12, val); break;
            case 13: AARCH64_DBG_READ_BVR(13, val); break;
            case 14: AARCH64_DBG_READ_BVR(14, val); break;
            case 15: AARCH64_DBG_READ_BVR(15, val); break;
        }
    } else if (reg_idx == AARCH64_DBG_REG_BCR) {
        switch(n) {
            case 0: AARCH64_DBG_READ_BCR(0, val); break;
            case 1: AARCH64_DBG_READ_BCR(1, val); break;
            case 2: AARCH64_DBG_READ_BCR(2, val); break;
            case 3: AARCH64_DBG_READ_BCR(3, val); break;
            case 4: AARCH64_DBG_READ_BCR(4, val); break;
            case 5: AARCH64_DBG_READ_BCR(5, val); break;
            case 6: AARCH64_DBG_READ_BCR(6, val); break;
            case 7: AARCH64_DBG_READ_BCR(7, val); break;
            case 8: AARCH64_DBG_READ_BCR(8, val); break;
            case 9: AARCH64_DBG_READ_BCR(9, val); break;
            case 10: AARCH64_DBG_READ_BCR(10, val); break;
            case 11: AARCH64_DBG_READ_BCR(11, val); break;
            case 12: AARCH64_DBG_READ_BCR(12, val); break;
            case 13: AARCH64_DBG_READ_BCR(13, val); break;
            case 14: AARCH64_DBG_READ_BCR(14, val); break;
            case 15: AARCH64_DBG_READ_BCR(15, val); break;
        }
    } else {
        pr_warn("[kpm_RWBP] read_wb_reg: unknown register idx %d, n=%d\n", reg_idx, n);
    }
    return val;
}

static void write_wb_reg(int reg_idx, int n, uint64_t val) {
    if (reg_idx == AARCH64_DBG_REG_WVR) {
        switch(n) {
            case 0: AARCH64_DBG_WRITE_WVR(0, val); break;
            case 1: AARCH64_DBG_WRITE_WVR(1, val); break;
            case 2: AARCH64_DBG_WRITE_WVR(2, val); break;
            case 3: AARCH64_DBG_WRITE_WVR(3, val); break;
            case 4: AARCH64_DBG_WRITE_WVR(4, val); break;
            case 5: AARCH64_DBG_WRITE_WVR(5, val); break;
            case 6: AARCH64_DBG_WRITE_WVR(6, val); break;
            case 7: AARCH64_DBG_WRITE_WVR(7, val); break;
            case 8: AARCH64_DBG_WRITE_WVR(8, val); break;
            case 9: AARCH64_DBG_WRITE_WVR(9, val); break;
            case 10: AARCH64_DBG_WRITE_WVR(10, val); break;
            case 11: AARCH64_DBG_WRITE_WVR(11, val); break;
            case 12: AARCH64_DBG_WRITE_WVR(12, val); break;
            case 13: AARCH64_DBG_WRITE_WVR(13, val); break;
            case 14: AARCH64_DBG_WRITE_WVR(14, val); break;
            case 15: AARCH64_DBG_WRITE_WVR(15, val); break;
        }
    } else if (reg_idx == AARCH64_DBG_REG_WCR) {
        switch(n) {
            case 0: AARCH64_DBG_WRITE_WCR(0, val); break;
            case 1: AARCH64_DBG_WRITE_WCR(1, val); break;
            case 2: AARCH64_DBG_WRITE_WCR(2, val); break;
            case 3: AARCH64_DBG_WRITE_WCR(3, val); break;
            case 4: AARCH64_DBG_WRITE_WCR(4, val); break;
            case 5: AARCH64_DBG_WRITE_WCR(5, val); break;
            case 6: AARCH64_DBG_WRITE_WCR(6, val); break;
            case 7: AARCH64_DBG_WRITE_WCR(7, val); break;
            case 8: AARCH64_DBG_WRITE_WCR(8, val); break;
            case 9: AARCH64_DBG_WRITE_WCR(9, val); break;
            case 10: AARCH64_DBG_WRITE_WCR(10, val); break;
            case 11: AARCH64_DBG_WRITE_WCR(11, val); break;
            case 12: AARCH64_DBG_WRITE_WCR(12, val); break;
            case 13: AARCH64_DBG_WRITE_WCR(13, val); break;
            case 14: AARCH64_DBG_WRITE_WCR(14, val); break;
            case 15: AARCH64_DBG_WRITE_WCR(15, val); break;
        }
    } else if (reg_idx == AARCH64_DBG_REG_BVR) {
        switch(n) {
            case 0: AARCH64_DBG_WRITE_BVR(0, val); break;
            case 1: AARCH64_DBG_WRITE_BVR(1, val); break;
            case 2: AARCH64_DBG_WRITE_BVR(2, val); break;
            case 3: AARCH64_DBG_WRITE_BVR(3, val); break;
            case 4: AARCH64_DBG_WRITE_BVR(4, val); break;
            case 5: AARCH64_DBG_WRITE_BVR(5, val); break;
            case 6: AARCH64_DBG_WRITE_BVR(6, val); break;
            case 7: AARCH64_DBG_WRITE_BVR(7, val); break;
            case 8: AARCH64_DBG_WRITE_BVR(8, val); break;
            case 9: AARCH64_DBG_WRITE_BVR(9, val); break;
            case 10: AARCH64_DBG_WRITE_BVR(10, val); break;
            case 11: AARCH64_DBG_WRITE_BVR(11, val); break;
            case 12: AARCH64_DBG_WRITE_BVR(12, val); break;
            case 13: AARCH64_DBG_WRITE_BVR(13, val); break;
            case 14: AARCH64_DBG_WRITE_BVR(14, val); break;
            case 15: AARCH64_DBG_WRITE_BVR(15, val); break;
        }
    } else if (reg_idx == AARCH64_DBG_REG_BCR) {
        switch(n) {
            case 0: AARCH64_DBG_WRITE_BCR(0, val); break;
            case 1: AARCH64_DBG_WRITE_BCR(1, val); break;
            case 2: AARCH64_DBG_WRITE_BCR(2, val); break;
            case 3: AARCH64_DBG_WRITE_BCR(3, val); break;
            case 4: AARCH64_DBG_WRITE_BCR(4, val); break;
            case 5: AARCH64_DBG_WRITE_BCR(5, val); break;
            case 6: AARCH64_DBG_WRITE_BCR(6, val); break;
            case 7: AARCH64_DBG_WRITE_BCR(7, val); break;
            case 8: AARCH64_DBG_WRITE_BCR(8, val); break;
            case 9: AARCH64_DBG_WRITE_BCR(9, val); break;
            case 10: AARCH64_DBG_WRITE_BCR(10, val); break;
            case 11: AARCH64_DBG_WRITE_BCR(11, val); break;
            case 12: AARCH64_DBG_WRITE_BCR(12, val); break;
            case 13: AARCH64_DBG_WRITE_BCR(13, val); break;
            case 14: AARCH64_DBG_WRITE_BCR(14, val); break;
            case 15: AARCH64_DBG_WRITE_BCR(15, val); break;
        }
    } else {
        pr_warn("[kpm_RWBP] write_wb_reg: unknown register idx %d, n=%d\n", reg_idx, n);
    }
    __asm__ volatile("isb" ::: "memory");
}

static uint64_t calc_hw_addr(uint64_t bp_addr, uint32_t bp_type, uint32_t bp_len) {
    uint64_t alignment_mask;
    if (bp_type == 4) {
        alignment_mask = 0x3;
    } else {
        if (bp_len == 8)
            alignment_mask = 0x7;
        else if (bp_len == 4)
            alignment_mask = 0x3;
        else
            alignment_mask = 0x7;
    }
    return bp_addr & ~alignment_mask;
}

static bool toggle_bp_registers_directly(uint64_t bp_addr, uint32_t bp_type, uint32_t bp_len, int enable) {
    int i, max_slots;
    uint64_t hw_addr = calc_hw_addr(bp_addr, bp_type, bp_len);
    uint32_t ctrl;
    int val_reg, ctrl_reg;
    
    pr_info("[kpm_RWBP] toggle_bp_registers_directly: addr=0x%llx, type=%u, len=%u, enable=%d\n",
            (unsigned long long)hw_addr, bp_type, bp_len, enable);
    
    if (bp_type == 4) { // HW_BREAKPOINT_X (execute)
        ctrl_reg = AARCH64_DBG_REG_BCR;
        val_reg = AARCH64_DBG_REG_BVR;
        max_slots = 6;
    } else {
        ctrl_reg = AARCH64_DBG_REG_WCR;
        val_reg = AARCH64_DBG_REG_WVR;
        max_slots = get_cpu_num_wrps();
    }
    
    for (i = 0; i < max_slots; i++) {
        uint64_t addr = read_wb_reg(val_reg, i);
        if (addr == hw_addr) {
            ctrl = read_wb_reg(ctrl_reg, i);
            if (enable)
                ctrl |= 0x1;
            else
                ctrl &= ~0x1;
            write_wb_reg(ctrl_reg, i, ctrl);
            pr_info("[kpm_RWBP] toggle_bp_registers_directly: found slot %d, new ctrl=0x%x\n", i, ctrl);
            return true;
        }
    }
    
    pr_warn("[kpm_RWBP] toggle_bp_registers_directly: no matching slot found for addr 0x%llx\n",
            (unsigned long long)hw_addr);
    return false;
}

static void recovery_bp_work_func(struct work_struct *work) {
    struct bp_node *node = container_of(work, struct bp_node, recovery_work);
    if (node->scheme == 4) {
        struct perf_event_attr disabled_attr = node->orig_attr;
        disabled_attr.disabled = 1;
        pr_info("[kpm_RWBP] 工作队列: 正在调用 modify_user_hw_breakpoint 禁用硬件断点 %px\n", node->bp);
        kfunc(modify_user_hw_breakpoint)(node->bp, &disabled_attr);
    } else {
        pr_info("[kpm_RWBP] 工作队列: 正在异步重新启用硬件断点 %px\n", node->bp);
        kfunc(perf_event_enable)(node->bp);
        node->is_temp_bp = false;
    }
}

static bool arm64_move_bp_to_next_instruction(struct perf_event *bp, uint64_t next_instruction_addr, struct perf_event_attr *original_attr, struct perf_event_attr *next_instruction_attr) {
    int result;
    if (!bp || !original_attr || !next_instruction_attr || !next_instruction_addr) {
        return false;
    }
    memcpy(next_instruction_attr, original_attr, sizeof(struct perf_event_attr));
    next_instruction_attr->bp_addr = next_instruction_addr;
    next_instruction_attr->bp_len = 4; // HW_BREAKPOINT_LEN_4
    next_instruction_attr->bp_type = 4; // HW_BREAKPOINT_X
    next_instruction_attr->disabled = 0;
    result = kfunc(modify_user_hw_breakpoint)(bp, next_instruction_attr);
    if (result) {
        next_instruction_attr->bp_addr = 0;
        return false;
    }
    return true;
}

static bool arm64_recovery_bp_to_original(struct perf_event *bp, struct perf_event_attr *original_attr, struct perf_event_attr *next_instruction_attr) {
    int result;
    if (!bp || !original_attr || !next_instruction_attr) {
        return false;
    }
    result = kfunc(modify_user_hw_breakpoint)(bp, original_attr);
    if (result) {
        return false;
    }
    next_instruction_attr->bp_addr = 0;
    return true;
}

#include <hook.h>
void before_watchpoint_handler(hook_fargs3_t *args, void *udata) {
    unsigned long addr = (unsigned long)args->arg0;
    struct pt_regs *regs = (struct pt_regs *)args->arg2;
    unsigned long flags;
    struct bp_node *pos;
    bool found = false;

    flags = spin_lock_irqsave(&bp_list_lock);
    list_for_each_entry(pos, &bp_list, list) {
        if (pos->scheme == 3 && pos->pid == __task_pid_nr_ns(current, PIDTYPE_TGID, 0)) {
            uint64_t hw_addr = calc_hw_addr(pos->addr, pos->type, pos->len);
            if ((addr & ~7ULL) == hw_addr) {
                pos->hit_count++;
                found = true;
                break;
            }
        }
    }
    spin_unlock_irqrestore(&bp_list_lock, flags);

    if (found) {
        pr_info("[kpm_RWBP] Scheme 3 Hooked watchpoint triggered! addr=0x%lx, PC=0x%llx\n", addr, regs ? regs->pc : 0);
        uint64_t ctrl = read_wb_reg(AARCH64_DBG_REG_WCR, 0);
        write_wb_reg(AARCH64_DBG_REG_WCR, 0, ctrl & ~1ULL);
    }
}

static bool hook_installed = false;
static hook_err_t wp_hook_err = 0;

static void install_wp_hook(void) {
    if (hook_installed) return;
    void *wp_handler_addr = (void *)kallsyms_lookup_name("watchpoint_handler");
    if (wp_handler_addr) {
        wp_hook_err = hook_wrap3(wp_handler_addr, before_watchpoint_handler, NULL, NULL);
        if (wp_hook_err == 0) {
            hook_installed = true;
            pr_info("[kpm_RWBP] watchpoint_handler hooked successfully!\n");
        } else {
            pr_err("[kpm_RWBP] Failed to hook watchpoint_handler, err=%d\n", wp_hook_err);
        }
    } else {
        pr_err("[kpm_RWBP] watchpoint_handler symbol not found!\n");
    }
}

void remove_wp_hook(void) {
    if (hook_installed) {
        void *wp_handler_addr = (void *)kallsyms_lookup_name("watchpoint_handler");
        if (wp_handler_addr) {
            hook_unwrap(wp_handler_addr, before_watchpoint_handler, NULL);
        }
        hook_installed = false;
    }
}

static void disable_wp_regs_on_cpu(void *info) {
    write_wb_reg(AARCH64_DBG_REG_WCR, 0, 0);
    write_wb_reg(AARCH64_DBG_REG_WVR, 0, 0);
}

static void unregister_bp_work_func(struct work_struct *work) {
    struct bp_node *node = container_of(work, struct bp_node, unreg_work);
    if (node->scheme == 3) {
        if (!kf_on_each_cpu) {
            kf_on_each_cpu = (void *)kallsyms_lookup_name("on_each_cpu");
        }
        if (kf_on_each_cpu) {
            kf_on_each_cpu(disable_wp_regs_on_cpu, NULL, 1);
        }
        pr_info("[kpm_RWBP] Scheme 3: 硬件断点全CPU广播注销成功\n");
    } else if (node->bp) {
        pr_info("[kpm_RWBP] 工作队列: 正在异步移除硬件断点 %px\n", node->bp);
        kfunc(unregister_hw_breakpoint)(node->bp);
    }
    kfunc(kfree)(node);
    __sync_fetch_and_sub(&in_flight, 1);
}

static void hwbp_triggered(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
    unsigned long flags;
    struct bp_node *pos, *found_node = NULL;
    
    pr_info("[kpm_RWBP] hwbp_triggered called! bp=%px\n", bp);
    
    flags = spin_lock_irqsave(&bp_list_lock);
    list_for_each_entry(pos, &bp_list, list) {
        if (pos->bp == bp) {
            found_node = pos;
            break;
        }
    }
    spin_unlock_irqrestore(&bp_list_lock, flags);
    
    if (!found_node) {
        pr_warn("[kpm_RWBP] hwbp_triggered: node not found for bp=%px\n", bp);
        return;
    }

    // 去重逻辑：若非方案2且断点已处于临时禁用状态，直接忽略重复触发
    if (found_node->scheme != 2 && found_node->is_temp_bp) {
        return;
    }

    found_node->hit_count++;

      // 保存命中记录到环形缓冲区
      if (regs) {
          unsigned long rec_flags = spin_lock_irqsave(&found_node->hit_records_lock);
          struct bp_hit_record *rec = &found_node->hit_records[found_node->hit_record_head];
          rec->hit_time = (uint64_t)kfunc(ktime_get_real_seconds)() * 1000000000LL;
          rec->task_id = (uint32_t)kfunc(__task_pid_nr_ns)(current, PIDTYPE_TGID, 0);
          rec->hit_addr = found_node->addr;
          // 保存寄存器快照
          rec->regs_info.pc = regs->pc;
          rec->regs_info.sp = regs->sp;
          rec->regs_info.pstate = regs->pstate;
          // regs->regs[0..30] are saved differently depending on arch
          // For ARM64 pt_regs, regs[0] is at offset 0, regs[1] at 8, etc.
          // On ARM64: struct pt_regs has regs[0]..regs[30] at offset 0..240
          uint64_t *reg_ptr = (uint64_t *)regs;
          for (int i = 0; i < 31; i++) {
              rec->regs_info.regs[i] = reg_ptr[i];
          }
          found_node->hit_record_head = (found_node->hit_record_head + 1) % MAX_HIT_RECORDS_PER_BP;
          if (found_node->hit_record_count < MAX_HIT_RECORDS_PER_BP) {
              found_node->hit_record_count++;
          }
          spin_unlock_irqrestore(&found_node->hit_records_lock, rec_flags);
      }

      pr_info("[kpm_RWBP] === Hardware Breakpoint Hit ===\n");
    pr_info("[kpm_RWBP] PID: %u, Addr: 0x%llx, Hit Count: %llu\n",
            found_node->pid, found_node->addr, found_node->hit_count);
    pr_info("[kpm_RWBP] PC: 0x%llx\n", regs ? regs->pc : 0);
    pr_info("[kpm_RWBP] Stack trace:\n");
    kfunc(dump_stack)();

    if (found_node->scheme == 1) {
        pr_info("[kpm_RWBP] Scheme 1 triggered! PC=0x%llx\n", regs ? regs->pc : 0);
        toggle_bp_registers_directly(found_node->addr, found_node->type, found_node->len, 0);
        kfunc(perf_event_disable_inatomic)(bp);
        found_node->is_temp_bp = true;
        kfunc(queue_work_on)(0, (struct workqueue_struct *)kf_system_wq, &found_node->recovery_work);
    } 
    else if (found_node->scheme == 2) {
        if (!found_node->is_temp_bp) {
            // First hit (watchpoint)
            pr_info("[kpm_RWBP] Scheme 2 triggered (First Hit)! PC=0x%llx\n", regs ? regs->pc : 0);
            toggle_bp_registers_directly(found_node->addr, found_node->type, found_node->len, 0);
            if (regs && arm64_move_bp_to_next_instruction(bp, regs->pc + 4, &found_node->orig_attr, &found_node->next_instruction_attr)) {
                found_node->is_temp_bp = true;
            } else {
                pr_err("[kpm_RWBP] Scheme 2: Failed to move bp to next instruction!\n");
                kfunc(perf_event_disable_inatomic)(bp);
            }
        } else {
            // Second hit (execution breakpoint step-over)
            pr_info("[kpm_RWBP] Scheme 2 triggered (Second Hit)! PC=0x%llx\n", regs ? regs->pc : 0);
            if (arm64_recovery_bp_to_original(bp, &found_node->orig_attr, &found_node->next_instruction_attr)) {
                found_node->is_temp_bp = false;
                toggle_bp_registers_directly(found_node->addr, found_node->type, found_node->len, 1);
            } else {
                pr_err("[kpm_RWBP] Scheme 2: Failed to restore original bp!\n");
                toggle_bp_registers_directly(found_node->next_instruction_attr.bp_addr, 4, 4, 0);
                kfunc(perf_event_disable_inatomic)(bp);
            }
        }
    }
    else if (found_node->scheme == 4) {
        pr_info("[kpm_RWBP] Scheme 4 triggered! PC=0x%llx\n", regs ? regs->pc : 0);
        toggle_bp_registers_directly(found_node->addr, found_node->type, found_node->len, 0);
        kfunc(perf_event_disable_inatomic)(bp);
        kfunc(queue_work_on)(0, (struct workqueue_struct *)kf_system_wq, &found_node->recovery_work);
    }
    else {
        toggle_bp_registers_directly(found_node->addr, found_node->type, found_node->len, 0);
        kfunc(perf_event_disable_inatomic)(bp);
    }
}

static void write_wp_regs_on_cpu(void *info) {
    struct bp_node *node = (struct bp_node *)info;
    uint64_t hw_addr = calc_hw_addr(node->addr, node->type, node->len);
    write_wb_reg(AARCH64_DBG_REG_WVR, 0, hw_addr);
    uint32_t ctrl = 1 | (3 << 1) | (3 << 3) | (0xff << 5);
    write_wb_reg(AARCH64_DBG_REG_WCR, 0, ctrl);

    // Enable MDSCR_EL1.MDE
    uint64_t mdscr;
    asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
    mdscr |= (1ULL << 15);
    asm volatile("msr mdscr_el1, %0" :: "r"(mdscr));
    asm volatile("isb" ::: "memory");
}

static void register_bp_work_func(struct work_struct *work) {
    struct register_work *reg_work = container_of(work, struct register_work, work);
    unsigned long flags;
    
    pr_info("[kpm_RWBP] register_bp_work_func: PID=%u, addr=0x%llx, type=%u, len=%u, scheme=%u\n",
            reg_work->pid, (unsigned long long)reg_work->addr, reg_work->type, reg_work->len, reg_work->scheme);
    
    if (reg_work->scheme == 3) {
          install_wp_hook();
          struct bp_node *node = kfunc(__kmalloc)(sizeof(struct bp_node), MY_GFP_ATOMIC);
          if (node) {
              node->bp = NULL;
              node->pid = reg_work->pid;
              node->addr = reg_work->addr;
              node->type = reg_work->type;
              node->len = reg_work->len;
              node->scheme = 3;
              node->hit_count = 0;
              node->is_temp_bp = false;
              node->hit_record_head = 0;
              node->hit_record_count = 0;
              spin_lock_init(&node->hit_records_lock);
            
            flags = spin_lock_irqsave(&bp_list_lock);
            list_add(&node->list, &bp_list);
            spin_unlock_irqrestore(&bp_list_lock, flags);
            
            if (!kf_on_each_cpu) {
                kf_on_each_cpu = (void *)kallsyms_lookup_name("on_each_cpu");
            }
            if (kf_on_each_cpu) {
                kf_on_each_cpu(write_wp_regs_on_cpu, node, 1);
            }
            pr_info("[kpm_RWBP] Scheme 3: 硬件断点全CPU广播使能成功\n");
        }
    } else {
        void *task = kfunc(find_task_by_vpid)(reg_work->pid);
        if (!task) {
            pr_err("[kpm_RWBP] 异步注册工作线程: 未找到 PID %u 对应的进程\n", reg_work->pid);
            kfunc(kfree)(reg_work);
            __sync_fetch_and_sub(&in_flight, 1);
            return;
        }

        struct perf_event_attr attr;
        init_perf_event_attr_bp(&attr, reg_work->type);
        attr.disabled = 0;  // 启用断点
        set_perf_event_exclude(&attr, 0, 1, 1);  // exclude_kernel=1, exclude_hv=1
        set_perf_event_bp_addr(&attr, reg_work->addr, reg_work->len);

        struct perf_event *bp = kfunc(register_user_hw_breakpoint)(&attr, hwbp_triggered, NULL, task);
        if (IS_ERR(bp)) {
            long err = PTR_ERR(bp);
            pr_err("[kpm_RWBP] 注册失败，错误码: %ld\n", err);
        } else {
            struct bp_node *node = kfunc(__kmalloc)(sizeof(struct bp_node), MY_GFP_ATOMIC);
            if (node) {
                  node->bp = bp;
                  node->pid = reg_work->pid;
                  node->addr = reg_work->addr;
                  node->type = reg_work->type;
                  node->len = reg_work->len;
                  node->scheme = reg_work->scheme;
                  node->hit_count = 0;
                  node->orig_attr = attr;
                  node->is_temp_bp = false;
                  node->hit_record_head = 0;
                  node->hit_record_count = 0;
                  spin_lock_init(&node->hit_records_lock);
                  my_init_work(&node->recovery_work, recovery_bp_work_func);
                
                flags = spin_lock_irqsave(&bp_list_lock);
                list_add(&node->list, &bp_list);
                spin_unlock_irqrestore(&bp_list_lock, flags);
                
                kfunc(perf_event_enable)(bp);
                pr_info("[kpm_RWBP] 硬件断点注册成功，内核指针: %px, 方案: %u\n", bp, reg_work->scheme);
            } else {
                kfunc(unregister_hw_breakpoint)(bp);
            }
        }
    }

    kfunc(kfree)(reg_work);
    __sync_fetch_and_sub(&in_flight, 1);
}

long register_hwbp(uint32_t pid, uint64_t addr, uint32_t type, uint32_t len, uint32_t scheme) {
    unsigned long flags;
    struct bp_node *pos;
    
    pr_info("[kpm_RWBP] register_hwbp: PID=%u, addr=0x%llx, type=%u, len=%u, scheme=%u\n",
            pid, (unsigned long long)addr, type, len, scheme);
    
    flags = spin_lock_irqsave(&bp_list_lock);
    list_for_each_entry(pos, &bp_list, list) {
        if (pos->pid == pid && pos->addr == addr) {
            spin_unlock_irqrestore(&bp_list_lock, flags);
            return -EEXIST;
        }
    }
    spin_unlock_irqrestore(&bp_list_lock, flags);

    if (scheme == 3) {
          install_wp_hook();
          struct bp_node *node = kfunc(__kmalloc)(sizeof(struct bp_node), MY_GFP_ATOMIC);
          if (node) {
              node->bp = NULL;
              node->pid = pid;
              node->addr = addr;
              node->type = type;
              node->len = len;
              node->scheme = 3;
              node->hit_count = 0;
              node->is_temp_bp = false;
              node->hit_record_head = 0;
              node->hit_record_count = 0;
              spin_lock_init(&node->hit_records_lock);
            
            flags = spin_lock_irqsave(&bp_list_lock);
            list_add(&node->list, &bp_list);
            spin_unlock_irqrestore(&bp_list_lock, flags);
            
            if (!kf_on_each_cpu) {
                kf_on_each_cpu = (void *)kallsyms_lookup_name("on_each_cpu");
            }
            if (kf_on_each_cpu) {
                kf_on_each_cpu(write_wp_regs_on_cpu, node, 1);
            }
            pr_info("[kpm_RWBP] register_hwbp Scheme 3: 硬件断点全CPU广播使能成功\n");
        } else {
            return -ENOMEM;
        }
        return 0;
    }

    void *task = kfunc(find_task_by_vpid)(pid);
    if (!task) {
        pr_err("[kpm_RWBP] register_hwbp: 未找到 PID %u 对应的进程\n", pid);
        return -ESRCH;
    }

    struct perf_event_attr attr;
    init_perf_event_attr_bp(&attr, type);
    attr.disabled = 0;  // 启用断点
    set_perf_event_exclude(&attr, 0, 1, 1);  // exclude_kernel=1, exclude_hv=1
    set_perf_event_bp_addr(&attr, addr, len);

    struct perf_event *bp = kfunc(register_user_hw_breakpoint)(&attr, hwbp_triggered, NULL, task);
    if (IS_ERR(bp)) {
        long err = PTR_ERR(bp);
        pr_err("[kpm_RWBP] register_hwbp: 注册失败，错误码: %ld\n", err);
        return err;
    }
    
    struct bp_node *node = kfunc(__kmalloc)(sizeof(struct bp_node), MY_GFP_ATOMIC);
      if (node) {
          node->bp = bp;
          node->pid = pid;
          node->addr = addr;
          node->type = type;
          node->len = len;
          node->scheme = scheme;
          node->hit_count = 0;
          node->orig_attr = attr;
          node->is_temp_bp = false;
          node->hit_record_head = 0;
          node->hit_record_count = 0;
          spin_lock_init(&node->hit_records_lock);
          my_init_work(&node->recovery_work, recovery_bp_work_func);
        
        flags = spin_lock_irqsave(&bp_list_lock);
        list_add(&node->list, &bp_list);
        spin_unlock_irqrestore(&bp_list_lock, flags);
        
        kfunc(perf_event_enable)(bp);
        pr_info("[kpm_RWBP] register_hwbp: 硬件断点注册成功，内核指针: %px, 方案: %u\n", bp, scheme);
    } else {
        kfunc(unregister_hw_breakpoint)(bp);
        return -ENOMEM;
    }
    
    return 0;
}

long unregister_hwbp(uint32_t pid, uint64_t addr) {
    unsigned long flags;
    struct bp_node *pos, *n;
    struct bp_node *target_node = NULL;

    flags = spin_lock_irqsave(&bp_list_lock);
    list_for_each_entry_safe(pos, n, &bp_list, list) {
        if (pos->pid == pid && pos->addr == addr) {
            list_del(&pos->list);
            target_node = pos;
            break;
        }
    }
    spin_unlock_irqrestore(&bp_list_lock, flags);

    if (!target_node) {
        return -ENOENT;
    }

    __sync_fetch_and_add(&in_flight, 1);
    my_init_work(&target_node->unreg_work, unregister_bp_work_func);
    kfunc(queue_work_on)(0, (struct workqueue_struct *)kf_system_wq, &target_node->unreg_work);
    return 0;
}

long unregister_all_hwbp(void) {
    unsigned long flags;
    struct bp_node *pos, *n;

    flags = spin_lock_irqsave(&bp_list_lock);
    list_for_each_entry_safe(pos, n, &bp_list, list) {
        list_del(&pos->list);
        __sync_fetch_and_add(&in_flight, 1);
        my_init_work(&pos->unreg_work, unregister_bp_work_func);
        kfunc(queue_work_on)(0, (struct workqueue_struct *)kf_system_wq, &pos->unreg_work);
    }
    spin_unlock_irqrestore(&bp_list_lock, flags);
    return 0;
}

long query_hwbp_hit(uint32_t pid, uint64_t addr) {
    unsigned long flags;
    struct bp_node *pos;
    
    flags = spin_lock_irqsave(&bp_list_lock);
    list_for_each_entry(pos, &bp_list, list) {
        if (pos->pid == pid && pos->addr == addr) {
            spin_unlock_irqrestore(&bp_list_lock, flags);
            return pos->hit_count;
        }
    }
    spin_unlock_irqrestore(&bp_list_lock, flags);
    return -ENOENT;
}

long read_hwbp_info(uint32_t pid, uint64_t max_count, void __user *user_buf, uint64_t *actual_count) {
    unsigned long flags;
    struct bp_node *pos;
    uint64_t total_copied = 0;

    if (max_count == 0 || user_buf == NULL) {
        return -EINVAL;
    }

    flags = spin_lock_irqsave(&bp_list_lock);
    list_for_each_entry(pos, &bp_list, list) {
        if (pos->pid == pid) {
            // 遍历该 PID 的所有断点节点
            unsigned long rec_flags = spin_lock_irqsave(&pos->hit_records_lock);
            
            uint32_t count = pos->hit_record_count;
            uint32_t head = pos->hit_record_head;
            
            for (uint32_t i = 0; i < count && total_copied < max_count; i++) {
                uint32_t idx = (head + MAX_HIT_RECORDS_PER_BP - count + i) % MAX_HIT_RECORDS_PER_BP;
                struct bp_hit_record *rec = &pos->hit_records[idx];
                
                if (kfunc(copy_to_user_nofault)(user_buf + total_copied * sizeof(struct bp_hit_record), rec, sizeof(struct bp_hit_record)) != 0) {
                    spin_unlock_irqrestore(&pos->hit_records_lock, rec_flags);
                    spin_unlock_irqrestore(&bp_list_lock, flags);
                    return -EFAULT;
                }
                total_copied++;
            }
            
            // 消费掉已经读取的记录，重置计数和头部指针
            pos->hit_record_count = 0;
            pos->hit_record_head = 0;
            
            spin_unlock_irqrestore(&pos->hit_records_lock, rec_flags);
            break;  // 只处理第一个匹配的PID
        }
    }
    spin_unlock_irqrestore(&bp_list_lock, flags);

    *actual_count = total_copied;
    return 0;
}