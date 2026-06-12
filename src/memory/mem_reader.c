#include "mem_reader.h"
#include "kernel_compat.h"
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/errno.h>

// pgtable_entry 已由 KP 通过 KP_EXPORT_SYMBOL 导出，可正常链接
extern uint64_t *pgtable_entry(uint64_t pgd, uint64_t va);

// page_size/page_shift/linear_voffset 由 kernel_compat.c 本地定义（非 KP 导出，不走 relocation）
extern int64_t page_size;
extern int64_t page_shift;
extern uint64_t linear_voffset;
extern uint64_t memstart_addr_val;
extern uint64_t page_offset_val;

// 使用本地 memstart_addr_val 和 page_offset_val 结合按位或，避免依赖 pgtable.h 中未导出的 phys_to_virt，并防止加法进位导致的高位错误偏离
#define local_phys_to_virt(pa) (((uint64_t)(pa) - memstart_addr_val) | page_offset_val)
// 页掩码
#define page_mask (~(page_size - 1))

// 虚拟地址转物理地址，使用 KP 导出的 pgtable_entry + 手算物理地址
static uint64_t pid_virt_to_phys(void *task, uint64_t vaddr)
{
    pr_info("[kpm_RWBP] pid_virt_to_phys entry: task=%p, vaddr=%llx\n", task, (unsigned long long)vaddr);
    kfunc(msleep)(50);

    if (mm_struct_offset.pgd_offset < 0) {
        pr_err("[kpm_RWBP] pgd_offset is negative: %d\n", mm_struct_offset.pgd_offset);
        kfunc(msleep)(50);
        return 0;
    }

    struct mm_struct *mm = kfunc(get_task_mm)(task);
    if (!mm) {
        pr_err("[kpm_RWBP] get_task_mm failed for task %p\n", task);
        kfunc(msleep)(50);
        return 0;
    }
    pr_info("[kpm_RWBP] mm_struct obtained: %p, pgd_offset: %d\n", mm, mm_struct_offset.pgd_offset);
    kfunc(msleep)(50);

    // 获取页表基址 PGD
    uintptr_t pgd_addr = (uintptr_t)mm + mm_struct_offset.pgd_offset;
    uint64_t pgd_base = *(uint64_t *)pgd_addr;
    pr_info("[kpm_RWBP] pgd_base value: %llx\n", (unsigned long long)pgd_base);
    kfunc(msleep)(50);

    if (!pgd_base) {
        pr_warn("[kpm_RWBP] pgd_base is null!\n");
        kfunc(msleep)(50);
        kfunc(mmput)(mm);
        return 0;
    }

    // 调用 KP 导出的 pgtable_entry 查找 PTE 条目
    uint64_t *pte_ptr = pgtable_entry(pgd_base, vaddr);
    pr_info("[kpm_RWBP] pgtable_entry returned: %p\n", pte_ptr);
    kfunc(msleep)(50);

    if (!pte_ptr) {
        kfunc(mmput)(mm);
        return 0;
    }

    uint64_t pte_val = *pte_ptr;
    pr_info("[kpm_RWBP] pte_val: %llx\n", (unsigned long long)pte_val);
    kfunc(msleep)(50);

    if (!pte_val || !(pte_val & 1)) {
        pr_warn("[kpm_RWBP] pte not present: %llx\n", (unsigned long long)pte_val);
        kfunc(msleep)(50);
        kfunc(mmput)(mm);
        return 0;
    }

    // 从 PTE 提取物理帧地址（支持 48 位物理地址）
    uint64_t phys_mask = 0x0000FFFFFFFFF000ULL & page_mask;
    uint64_t phys_addr = (pte_val & phys_mask) + (vaddr & (page_size - 1));
    pr_info("[kpm_RWBP] phys_addr: %llx\n", (unsigned long long)phys_addr);
    kfunc(msleep)(50);

    kfunc(mmput)(mm);
    return phys_addr;
}

// 读取物理地址 - 使用线性偏移直接物理映射
static size_t read_physical_address(uint64_t pa, void __user *buffer, size_t size)
{
    uint64_t page_pa = pa & page_mask;
    unsigned long offset = pa & (page_size - 1);

    // 确保读取操作不跨越页边界
    if (offset + size > page_size) {
        size = page_size - offset;
    }

    pr_info("[kpm_RWBP] read_physical_address: pa=%llx, size=%zu\n", (unsigned long long)pa, size);
    kfunc(msleep)(50);

    // 验证物理页帧与物理地址范围是否合法
    int is_pfn_valid = kfunc(pfn_valid)(page_pa >> page_shift);
    int is_range_valid = kfunc(valid_phys_addr_range)(page_pa, page_size);

    pr_info("[kpm_RWBP] pfn_valid: %d, range_valid: %d\n", is_pfn_valid, is_range_valid);
    kfunc(msleep)(50);

    if (!is_pfn_valid || !is_range_valid) {
        pr_warn("[kpm_RWBP] pfn or range check failed for page_pa=%llx\n", (unsigned long long)page_pa);
        kfunc(msleep)(50);
        return 0;
    }

    // 物理地址转内核虚拟地址（使用本地 linear_voffset，不依赖 pgtable.h 导出）
    uint64_t kva = local_phys_to_virt(pa);
    pr_info("[kpm_RWBP] kva=%llx, linear_voffset=%llx\n", 
            (unsigned long long)kva, (unsigned long long)linear_voffset);
    kfunc(msleep)(50);

    if (kva < 0xffff000000000000ULL) {
        pr_err("[kpm_RWBP] Dangerous kva detected: %llx, skipping copy!\n", (unsigned long long)kva);
        kfunc(msleep)(50);
        return 0;
    }

    pr_info("[kpm_RWBP] Invoking copy_to_user_nofault(to=%p, from=%llx, size=%zu)...\n", 
            buffer, (unsigned long long)kva, size);
    kfunc(msleep)(50);

    // 安全拷贝 data 至用户空间 (使用 copy_to_user_nofault 避免缺页引起的内核崩溃)
    long copy_err = kfunc(copy_to_user_nofault)(buffer, (const void *)kva, size);
    
    pr_info("[kpm_RWBP] copy_to_user_nofault returned: %ld\n", copy_err);
    kfunc(msleep)(50);

    if (copy_err < 0) {
        copy_err = size;
    }

    return size - copy_err;
}

// 核心读取函数 - 分页读取，避免跨页问题
long read_process_memory(uint32_t pid, uint64_t vaddr, uint64_t size, char *__user out_msg)
{
    pr_info("[kpm_RWBP] read_process_memory request: pid=%u, vaddr=%llx, size=%llu\n", 
            pid, (unsigned long long)vaddr, (unsigned long long)size);
    kfunc(msleep)(50);

    void *task = kfunc(find_task_by_vpid)(pid);
    if (!task) {
        pr_err("[kpm_RWBP] find_task_by_vpid failed for pid %u\n", pid);
        kfunc(msleep)(50);
        return -ESRCH;
    }

    uint64_t remaining = size;
    uint64_t cur_vaddr = vaddr;
    uint64_t cur_outbuf = (uint64_t)out_msg;
    long total_copied = 0;

    while (remaining > 0) {
        // 计算当前页最多能读取多少字节
        uint64_t offset = cur_vaddr & (page_size - 1);
        uint64_t chunk = page_size - offset;
        if (chunk > remaining) {
            chunk = remaining;
        }

        // 虚拟地址转物理地址
        uint64_t pa = pid_virt_to_phys(task, cur_vaddr);
        if (!pa) {
            pr_warn("[kpm_RWBP] pid_virt_to_phys returned 0 for vaddr=%llx\n", (unsigned long long)cur_vaddr);
            kfunc(msleep)(50);
            break;
        }

        // 读取该物理页中的数据片段
        size_t bytes_read = read_physical_address(pa, (void __user *)cur_outbuf, chunk);
        if (bytes_read <= 0) {
            pr_warn("[kpm_RWBP] read_physical_address read 0 bytes for pa=%llx\n", (unsigned long long)pa);
            kfunc(msleep)(50);
            break;
        }

        total_copied += bytes_read;
        remaining -= bytes_read;
        cur_vaddr += bytes_read;
        cur_outbuf += bytes_read;
    }

    pr_info("[kpm_RWBP] read_process_memory finish: total_copied=%ld\n", total_copied);
    kfunc(msleep)(50);

    return total_copied;
}
