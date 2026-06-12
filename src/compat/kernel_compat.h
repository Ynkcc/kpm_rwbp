#ifndef __KERNEL_COMPAT_H__
#define __KERNEL_COMPAT_H__
#include <compiler.h>
#include <kpmodule.h>
#include <ksyms.h>
#undef kfunc_lookup_name
#define kfunc_lookup_name(func) \
    kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func ".cfi_jt"); \
    if (!kf_##func) kf_##func = (typeof(kf_##func))kallsyms_lookup_name(#func)
#include <common.h>
#include <linux/printk.h>
#include <linux/spinlock.h>

// 前置结构体声明
struct task_struct;
struct perf_event;
struct workqueue_struct;
struct pt_regs;

// 链表节点结构体
struct my_list_head {
    struct my_list_head *next, *prev;
};

// 自定义 work_struct
struct work_struct;
typedef void (*work_func_t)(struct work_struct *work);
struct work_struct {
    unsigned long data;
    struct my_list_head entry;
    work_func_t func;
};

// 内联汇编读取 sp_el0 获取当前任务的 task_struct 指针
static inline struct task_struct *get_current(void) {
    unsigned long sp_el0;
    __asm__ __volatile__("mrs %0, sp_el0" : "=r"(sp_el0));
    return (struct task_struct *)sp_el0;
}
#ifndef current
#define current get_current()
#endif

// 完美与标准 Linux 内核对齐的 perf_event_attr 结构体
struct perf_event_attr {
    uint32_t type;               // 0
    uint32_t size;               // 4
    uint64_t config;             // 8
    uint64_t sample_period;      // 16
    uint64_t sample_type;        // 24
    uint64_t read_format;        // 32
    
    // 与标准小端位域排布完全一致的标志位域
    uint64_t disabled       :  1, /* off by default        */
             inherit        :  1, /* children inherit it   */
             pinned         :  1, /* must always be on PMU */
             exclusive      :  1, /* only group on PMU     */
             exclude_user   :  1, /* don't count user      */
             exclude_kernel :  1, /* dont count kernel     */
             exclude_hv     :  1, /* don't count hypervisor*/
             exclude_idle   :  1, /* don't count idle      */
             mmap           :  1, /* include mmap data     */
             comm           :  1, /* include comm data     */
             freq           :  1, /* use freq, not period  */
             inherit_stat   :  1, /* per task counts       */
             enable_on_exec :  1, /* next exec enables it  */
             task           :  1, /* trace fork/exit       */
             watermark      :  1, /* wakeup_watermark      */
             precise_ip     :  2, /* skid constraint       */
             mmap_data      :  1, /* non-exec mmap data    */
             sample_id_all  :  1, /* sample_type all events */
             exclude_host   :  1, /* double guestos exclusion */
             exclude_guest  :  1, /* double hostos exclusion */
             exclude_callchain_kernel : 1, /* exclude kernel callchains */
             exclude_callchain_user   : 1, /* exclude user callchains */
             mmap2          :  1, /* include mmap with inode data */
             comm_exec      :  1, /* flag comm events that are due to an exec */
             use_clockid    :  1, /* use @clockid for time fields */
             context_switch :  1, /* context flow data */
             write_backward :  1, /* write ring buffer from end */
             namespaces     :  1, /* include namespaces data */
             ksymbol        :  1, /* include ksymbol events */
             bpf_event      :  1, /* include bpf events */
             aux_output     :  1, /* generate AUX records instead of events */
             cgroup         :  1, /* include cgroup events */
             text_poke      :  1, /* include text poke events */
             build_id       :  1, /* use build id in mmap2 events */
             inherit_thread :  1, /* children only inherit if cloned with CLONE_THREAD */
             remove_on_exec :  1, /* event is removed from task on exec */
             sigtrap        :  1, /* send synchronous SIGTRAP on event */
             __reserved_1   : 26;

    uint32_t wakeup_events;      // 48
    uint32_t bp_type;            // 52
    uint64_t bp_addr;            // 56
    uint64_t bp_len;             // 64
    
    // 4.14/4.19: branch_sample_type 和 sample_regs_user 是分开的字段
    // 6.x+: branch_sample_type 被移除，新增 ksymbol, bpf_event 等标志位
    // 以下结构体布局兼容 4.14/4.19 (size=112)
    uint64_t branch_sample_type;     // 72 (4.14/4.19)
    uint64_t sample_regs_user;       // 80 (4.14/4.19)
    uint32_t sample_stack_user;  // 80
    int32_t  clockid;            // 84
    uint64_t sample_regs_intr;   // 88
    uint32_t aux_watermark;      // 96
    uint16_t sample_max_stack;   // 100
    uint16_t __reserved_2;       // 102
    uint32_t __reserved_3;       // 104
    uint64_t __reserved_4[2];    // 108
};

struct perf_sample_data;

// 硬件断点命中回调类型
typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

// 利用框架 kfunc_def 宏声明函数指针（自动生成 kf_xxx 变量）
extern int kfunc_def(sscanf)(const char *buf, const char *fmt, ...);
// find_task_by_vpid 已在 KernelPatch/sched.h 中定义，无需在此处重复定义以规避类型冲突
extern uint64_t kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, uint64_t n);
extern int kfunc_def(sprint_symbol)(char *buffer, unsigned long address);
extern int kfunc_def(access_process_vm)(void *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags);
extern long kfunc_def(copy_from_user_nofault)(void *dst, const void __user *src, size_t size);
extern long kfunc_def(copy_to_user_nofault)(void __user *to, const void *from, size_t size);

// 硬件断点与内存管理函数指针
extern struct perf_event *kfunc_def(register_user_hw_breakpoint)(struct perf_event_attr *attr,
                                                                 perf_overflow_handler_t triggered,
                                                                 void *context,
                                                                 struct task_struct *tsk);
extern void kfunc_def(unregister_hw_breakpoint)(struct perf_event *bp);
extern int kfunc_def(modify_user_hw_breakpoint)(struct perf_event *bp, struct perf_event_attr *attr);
extern void kfunc_def(perf_event_disable_inatomic)(struct perf_event *event);
extern void kfunc_def(perf_event_enable)(struct perf_event *event);
extern void *kfunc_def(__kmalloc)(size_t size, unsigned int flags);
extern void kfunc_def(kfree)(const void *objp);
extern struct workqueue_struct *kfunc_def(system_wq);
extern bool kfunc_def(queue_work_on)(int cpu, struct workqueue_struct *wq, struct work_struct *work);

// 新增内存与页表管理符号
struct mm_struct;
extern void kfunc_def(mmput)(struct mm_struct *mm);
extern struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task);
extern int kfunc_def(pfn_valid)(unsigned long pfn);
extern int kfunc_def(valid_phys_addr_range)(unsigned long addr, unsigned long size);
extern int64_t kfunc_def(ktime_get_real_seconds)(void);
extern void kfunc_def(msleep)(unsigned int msecs);



// 兼容层运行时版本与状态变量


// KernelPatch 版本宏（与标准 Linux kernel_version 编码兼容）
// VERSION(major, minor, patch) = (major << 16) + (minor << 8) + patch
#ifndef KERNEL_VERSION_CODE
#define KERNEL_VERSION_CODE(major, minor, patch) (((major) << 16) + ((minor) << 8) + (patch))
#endif
#ifndef KERNEL_VERSION_MAJOR
#define KERNEL_VERSION_MAJOR(version) (((version) >> 16) & 0xFF)
#endif
#ifndef KERNEL_VERSION_MINOR
#define KERNEL_VERSION_MINOR(version) (((version) >> 8) & 0xFF)
#endif
#ifndef KERNEL_VERSION_PATCH
#define KERNEL_VERSION_PATCH(version) ((version) & 0xFF)
#endif

// 运行时保存的物理地址偏移与虚拟地址基址
extern uint64_t memstart_addr_val;
extern uint64_t page_offset_val;

// 运行时内核版本
extern uint32_t kp_kernel_version;

// 兼容层拷贝数据至用户态
long compat_copy_to_user(void __user *to, const void *from, size_t size);
long compat_copy_from_user(void *to, const void __user *from, size_t size);

// 声明 raw spinlock 兼容接口指针
extern unsigned long (*kf__raw_spin_lock_irqsave)(raw_spinlock_t *lock);
extern void (*kf__raw_spin_unlock_irqrestore)(raw_spinlock_t *lock, unsigned long flags);

// 声明 NMI 安全的高精度单调时间戳获取函数
extern uint64_t (*kf_ktime_get_mono_fast_ns)(void);

// 兼容层初始化，执行符号查找与动态偏移计算
long compat_init(void);

#endif // __KERNEL_COMPAT_H__

