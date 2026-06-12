#include "kernel_compat.h"
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

// 运行时内核版本（由 compat_init 设置）
uint32_t kp_kernel_version = 0;

// 本地页大小变量（pgtable.h 中声明的 extern，此处提供实体定义）
int64_t page_size = 4096;
int64_t page_shift = 12;
// 线性区偏移量，由 memstart_addr 与 va_bits 动态计算
uint64_t linear_voffset = 0;
uint64_t memstart_addr_val = 0;
uint64_t page_offset_val = 0;

// 实例化 spinlock.h 中声明的 kfunc 自旋锁指针
unsigned long (*kf__raw_spin_lock_irqsave)(raw_spinlock_t *lock) = NULL;
void (*kf__raw_spin_unlock_irqrestore)(raw_spinlock_t *lock, unsigned long flags) = NULL;

// 函数指针定义（kfunc_def 展开为 (*kf_xxx)，这里提供存储）
int kfunc_def(sscanf)(const char *buf, const char *fmt, ...) = NULL;
struct task_struct *kfunc_def(find_task_by_vpid)(pid_t nr) = NULL;
pid_t (*kf___task_pid_nr_ns)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns) = NULL;
uint64_t kfunc_def(__arch_copy_to_user)(void __user *to, const void *from, uint64_t n) = NULL;
int kfunc_def(sprint_symbol)(char *buffer, unsigned long address) = NULL;
void kfunc_def(dump_stack)(void) = NULL;
int kfunc_def(access_process_vm)(void *tsk, unsigned long addr, void *buf, int len, unsigned int gup_flags) = NULL;
long kfunc_def(copy_from_user_nofault)(void *dst, const void __user *src, size_t size) = NULL;
long kfunc_def(copy_to_user_nofault)(void *dst, const void *from, size_t size) = NULL;
void *kfunc_def(memset)(void *s, int c, size_t n) = NULL;

struct perf_event *kfunc_def(register_user_hw_breakpoint)(struct perf_event_attr *attr,
                                                         perf_overflow_handler_t triggered,
                                                         void *context,
                                                         struct task_struct *tsk) = NULL;
void kfunc_def(unregister_hw_breakpoint)(struct perf_event *bp) = NULL;
int kfunc_def(modify_user_hw_breakpoint)(struct perf_event *bp, struct perf_event_attr *attr) = NULL;
void kfunc_def(perf_event_disable_inatomic)(struct perf_event *event) = NULL;
void kfunc_def(perf_event_enable)(struct perf_event *event) = NULL;
void *kfunc_def(__kmalloc)(size_t size, unsigned int flags) = NULL;
void kfunc_def(kfree)(const void *objp) = NULL;
struct workqueue_struct *kfunc_def(system_wq) = NULL;
bool kfunc_def(queue_work_on)(int cpu, struct workqueue_struct *wq, struct work_struct *work) = NULL;

// 内存与页表管理符号定义
void kfunc_def(mmput)(struct mm_struct *mm) = NULL;
struct mm_struct *kfunc_def(get_task_mm)(struct task_struct *task) = NULL;
int kfunc_def(pfn_valid)(unsigned long pfn) = NULL;
int kfunc_def(valid_phys_addr_range)(unsigned long addr, unsigned long size) = NULL;
int64_t kfunc_def(ktime_get_real_seconds)(void) = NULL;
void kfunc_def(msleep)(unsigned int msecs) = NULL;

// 匿名描述符与文件管理符号定义
struct file *kfunc_def(anon_inode_getfile)(const char *name, const struct file_operations *fops, void *priv, int flags) = NULL;
int kfunc_def(get_unused_fd_flags)(unsigned int flags) = NULL;
void kfunc_def(put_unused_fd)(unsigned int fd) = NULL;
void kfunc_def(fd_install)(unsigned int fd, struct file *file) = NULL;

// 从 UTS_RELEASE 字符串解析内核版本
static uint32_t parse_kernel_version(const char *release) {
    int major = 0, minor = 0, patch = 0;
    const char *p = release;
    
    // 解析主版本号
    while (*p && *p >= '0' && *p <= '9') {
        major = major * 10 + (*p - '0');
        p++;
    }
    if (*p == '.') p++;
    
    // 解析次版本号
    while (*p && *p >= '0' && *p <= '9') {
        minor = minor * 10 + (*p - '0');
        p++;
    }
    if (*p == '.') p++;
    
    // 解析补丁版本号（可能带有其他后缀如 -rc1, -generic 等）
    while (*p && *p >= '0' && *p <= '9') {
        patch = patch * 10 + (*p - '0');
        p++;
    }
    
    return KERNEL_VERSION_CODE(major, minor, patch);
}

long compat_init(void)
{
    // 直接使用 KernelPatch 框架提供的 kver 变量
    kp_kernel_version = kver;
    pr_info("[kpm_RWBP] 检测到内核版本: %d.%d.%d (0x%08x)\n",
            KERNEL_VERSION_MAJOR(kp_kernel_version),
            KERNEL_VERSION_MINOR(kp_kernel_version),
            KERNEL_VERSION_PATCH(kp_kernel_version),
            kp_kernel_version);
    
    // 动态查找所有核心函数 and 变量
    kfunc_lookup_name(sscanf);
    kfunc_lookup_name(find_task_by_vpid);
    kfunc_lookup_name(__arch_copy_to_user);
    kfunc_lookup_name(sprint_symbol);
    kfunc_lookup_name(dump_stack);
    kfunc_lookup_name(memset);
    kfunc_lookup_name(access_process_vm);
    kfunc_lookup_name(copy_from_user_nofault);
    kfunc_lookup_name(copy_to_user_nofault);
    kfunc_lookup_name(register_user_hw_breakpoint);
    kfunc_lookup_name(unregister_hw_breakpoint);
    kfunc_lookup_name(modify_user_hw_breakpoint);
    kfunc_lookup_name(perf_event_disable_inatomic);
    kfunc_lookup_name(perf_event_enable);
    kfunc_lookup_name(__kmalloc);
    kfunc_lookup_name(kfree);
    kfunc_lookup_name(queue_work_on);

    // 动态查找新增符号
    kfunc_lookup_name(mmput);
    kfunc_lookup_name(get_task_mm);
    kfunc_lookup_name(pfn_valid);
    kfunc_lookup_name(valid_phys_addr_range);
    kfunc_lookup_name(ktime_get_real_seconds);
    kfunc_lookup_name(msleep);
    kfunc_lookup_name(anon_inode_getfile);
    kfunc_lookup_name(get_unused_fd_flags);
    kfunc_lookup_name(put_unused_fd);
    kfunc_lookup_name(fd_install);
    kfunc_lookup_name(_raw_spin_lock_irqsave);
    kfunc_lookup_name(_raw_spin_unlock_irqrestore);
    kfunc_lookup_name(__task_pid_nr_ns);

    // system_wq 在内核中是一个全局指针变量，通过 kallsyms_lookup_name 查找到它的符号地址并进行解引用
    void *system_wq_sym = (void *)kallsyms_lookup_name("system_wq");
    if (system_wq_sym) {
        *(void **)&kf_system_wq = *(void **)system_wq_sym;
    }

    // 动态查找真实页大小和页偏移（内核符号，非 KP 符号）
    int64_t *page_size_ptr = (int64_t *)kallsyms_lookup_name("page_size");
    if (page_size_ptr) page_size = *page_size_ptr;
    int64_t *page_shift_ptr = (int64_t *)kallsyms_lookup_name("page_shift");
    if (page_shift_ptr) page_shift = *page_shift_ptr;

    // 动态计算线性区偏移量 linear_voffset、page_offset_val 和 memstart_addr_val
    uint64_t *memstart_addr_ptr = (uint64_t *)kallsyms_lookup_name("memstart_addr");
    if (memstart_addr_ptr) {
        memstart_addr_val = *memstart_addr_ptr;
        uint64_t tcr_el1;
        __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
        uint64_t va_bits_local = 64 - ((tcr_el1 >> 16) & 0x1F);
        
        // 5.4.0 之前的内核与 5.4.0 之后的内核在 PAGE_OFFSET 的计算底数上相差 1 位 (VA_BITS - 1 vs VA_BITS)
        if (kp_kernel_version < KERNEL_VERSION_CODE(5, 4, 0)) {
            page_offset_val = (-1ULL << (va_bits_local - 1));
        } else {
            page_offset_val = (-1ULL << va_bits_local);
        }
        
        linear_voffset = page_offset_val - memstart_addr_val;
        pr_info("[kpm_RWBP] va_bits=%llu, page_offset=%llx, memstart_addr=%llx, linear_voffset=%llx\n",
                (unsigned long long)va_bits_local,
                (unsigned long long)page_offset_val,
                (unsigned long long)memstart_addr_val,
                (unsigned long long)linear_voffset);
    } else {
        pr_err("[kpm_RWBP] 未找到 memstart_addr，无法计算线性偏移！\n");
        return -ENOENT;
    }

    // 验证必需的内核符号
    if (!kfunc(sscanf) || !kfunc(find_task_by_vpid) || !kfunc(__arch_copy_to_user) || 
        !kfunc(sprint_symbol) || !kfunc(copy_from_user_nofault) || !kfunc(copy_to_user_nofault) ||
        !kfunc(register_user_hw_breakpoint) || !kfunc(unregister_hw_breakpoint) || !kfunc(modify_user_hw_breakpoint) ||
        !kfunc(perf_event_disable_inatomic) || !kfunc(perf_event_enable) || !kfunc(__kmalloc) || !kfunc(kfree) || 
        !kfunc(queue_work_on) || !kf_system_wq ||
        !kfunc(mmput) || !kfunc(get_task_mm) || !kfunc(pfn_valid) || !kfunc(valid_phys_addr_range) ||
        !kfunc(ktime_get_real_seconds) || !kfunc(msleep) ||
        !kfunc(anon_inode_getfile) || !kfunc(get_unused_fd_flags) || 
        !kfunc(put_unused_fd) || !kfunc(fd_install) ||
        !kfunc(_raw_spin_lock_irqsave) || !kfunc(_raw_spin_unlock_irqrestore) ||
        !kfunc(__task_pid_nr_ns)) {
        pr_err("[kpm_RWBP] 动态查找核心内核符号失败！\n");
        return -ENOENT;
    }
    
    pr_info("[kpm_RWBP] 内核兼容适配动态初始化完成 (版本: %d.%d.%d)\n",
            KERNEL_VERSION_MAJOR(kp_kernel_version),
            KERNEL_VERSION_MINOR(kp_kernel_version),
            KERNEL_VERSION_PATCH(kp_kernel_version));

    return 0;
}
