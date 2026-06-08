#ifndef __KERNEL_COMPAT_H__
#define __KERNEL_COMPAT_H__
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>

// 系统页表及内存参数
extern uint64_t my_page_shift;
extern uint64_t my_va_bits;
extern uint64_t my_pa_bits;
extern uint64_t pgd_offset;

// 内核符号和变量地址
extern uint64_t kv_memstart_addr;
extern uint64_t kv_kimage_voffset;

// 内核导出的函数指针声明
extern int (*kf_sscanf)(const char *buf, const char *fmt, ...);
extern void *(*kf_find_task_by_vpid)(uint32_t pid);
extern void *(*kf_get_task_mm)(void *task);
extern void (*kf_mmput)(void *mm);
extern int (*kf_pfn_valid)(uint64_t pfn);
extern int (*kf_valid_phys_addr_range)(uint64_t addr, uint64_t size);
extern uint64_t (*kf___arch_copy_to_user)(void __user *to, const void *from, uint64_t n);

// 物理地址转换为内核虚拟地址（线性映射区）
static inline uint64_t phys_to_virt_compat(uint64_t phys_addr)
{
    // 在不同内核大版本上，物理地址到虚拟地址的映射转换可以通过系统的 memstart_addr 与 va_bits 计算
    // 映射公式: kva = phys_addr - memstart_addr + (-1ULL << va_bits)
    return (phys_addr & (-1ULL << my_page_shift))
           - *(uint64_t *)kv_memstart_addr
           + (-1ULL << my_va_bits)
           + (phys_addr & ~(-1ULL << my_page_shift));
}

// 兼容层初始化，执行符号查找与内核结构偏移扫描
long compat_init(void);

#endif // __KERNEL_COMPAT_H__
