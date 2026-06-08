#include "kernel_compat.h"
#include <linux/printk.h>
#include <common.h>

// 全局变量定义
uint64_t my_page_shift = 12;
uint64_t my_va_bits = 48;
uint64_t my_pa_bits = 48;
uint64_t pgd_offset = 0;

uint64_t kv_memstart_addr = 0;
uint64_t kv_kimage_voffset = 0;

// 内核导出的函数指针定义
int (*kf_sscanf)(const char *buf, const char *fmt, ...) = NULL;
void *(*kf_find_task_by_vpid)(uint32_t pid) = NULL;
void *(*kf_get_task_mm)(void *task) = NULL;
void (*kf_mmput)(void *mm) = NULL;
int (*kf_pfn_valid)(uint64_t pfn) = NULL;
int (*kf_valid_phys_addr_range)(uint64_t addr, uint64_t size) = NULL;
uint64_t (*kf___arch_copy_to_user)(void __user *to, const void *from, uint64_t n) = NULL;

static const uint64_t pa_bits_table[] = { 32, 36, 40, 42, 44, 48, 52 };

#define LOOKUP_SYM(var, name) \
    var = (typeof(var))kallsyms_lookup_name(name);

// 动态获取系统页表各项参数与布局
static void pgtable_detect(void)
{
    uint64_t tcr_el1;
    __asm__ volatile("mrs %0, tcr_el1" : "=r"(tcr_el1));
    uint64_t tg1 = (tcr_el1 >> 30) & 0x3;
    my_va_bits = 64 - ((tcr_el1 >> 16) & 0x1F);
    if (tg1 == 1) {
        my_page_shift = 14; // 16KB 页面
    } else if (tg1 == 3) {
        my_page_shift = 16; // 64KB 页面
    } else {
        my_page_shift = 12; // 4KB 页面
    }

    uint64_t mmfr0;
    __asm__ volatile("mrs %0, id_aa64mmfr0_el1" : "=r"(mmfr0));
    uint64_t parange = mmfr0 & 0xF;
    if (parange > 6) {
        my_pa_bits = 48;
    } else {
        my_pa_bits = pa_bits_table[parange];
    }

    uint64_t ttbr1;
    __asm__ volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));

    uint64_t init_mm_addr = (uint64_t)kallsyms_lookup_name("init_mm");
    if (init_mm_addr && kv_kimage_voffset) {
        uint64_t expected_pgd = *(uint64_t *)kv_kimage_voffset
                              + (ttbr1 & (-1ULL << my_page_shift) & 0xFFFFFFFFFFFEULL);
        uint64_t off;
        // 在 init_mm 结构体前 256 字节中动态探测 pgd 的成员变量偏移量
        // 该偏移在不同内核编译选项中可能由于其他成员的大小和布局而改变，自动探测能增强多版本兼容性
        for (off = 0; off < 256; off += 4) {
            if (*(uint64_t *)(init_mm_addr + off) == expected_pgd) {
                pgd_offset = off;
                break;
            }
        }
    }
}

long compat_init(void)
{
    // 获取内核关键符号的指针，若找不到将在卸载和载入时引起明确反馈
    LOOKUP_SYM(kv_memstart_addr, "memstart_addr");
    LOOKUP_SYM(kv_kimage_voffset, "kimage_voffset");
    LOOKUP_SYM(kf_sscanf, "sscanf");
    LOOKUP_SYM(kf_find_task_by_vpid, "find_task_by_vpid");
    LOOKUP_SYM(kf_get_task_mm, "get_task_mm");
    LOOKUP_SYM(kf_mmput, "mmput");
    LOOKUP_SYM(kf_pfn_valid, "pfn_valid");
    LOOKUP_SYM(kf_valid_phys_addr_range, "valid_phys_addr_range");
    LOOKUP_SYM(kf___arch_copy_to_user, "__arch_copy_to_user");

    // 动态探测当前系统内核的页表和布局配置
    pgtable_detect();

    pr_info("[kpm_RWBP] 内核兼容适配初始化完成: page_shift=%lld, va_bits=%lld, pgd_offset=%lld\n",
            my_page_shift, my_va_bits, pgd_offset);

    return 0;
}
