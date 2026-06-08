#include "mem_reader.h"
#include "kernel_compat.h"
#include <linux/errno.h>

// 页表转换逻辑：将用户态虚拟地址转换为内核物理地址
static uint64_t get_phys_addr(void *mm, uint64_t vaddr)
{
    uint64_t ps = my_page_shift;
    uint64_t vb = my_va_bits;
    uint64_t es = ps - 3;
    int64_t levels = (int64_t)((vb - 4) / es);
    uint64_t phys_addr = 0;

    if (levels < 1) return 0;

    int64_t level = 4 - levels;
    uint64_t tbl = *(uint64_t *)((uint64_t)mm + pgd_offset);
    uint64_t pmask = ~(-1ULL << (48 - (uint8_t)ps)) << ps;
    uint64_t imask = (1U << es) - 1;
    int found = 0;

    while (!found) {
        uint64_t shift = (4 - (uint8_t)level) * es + 3;
        uint64_t idx = (vaddr >> shift) & imask;
        uint64_t entry = *(uint64_t *)(tbl + idx * 8);
        uint64_t dt = entry & 3;

        if (dt == 3) {
            tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
            level++;
            if (level >= 3) {
                found = 1;
                break;
            }
        } else if (dt == 1) {
            if (level == 0) {
                pmask = ~(-1ULL << (48 - ((uint8_t)ps + 3 * es))) << ((uint8_t)ps + 3 * es);
                tbl = (pmask & entry) + (-1ULL << vb) - *(uint64_t *)kv_memstart_addr;
                level++;
                if (level >= 3) {
                    found = 1;
                    break;
                }
                continue;
            }
            found = 1;
            break;
        } else {
            break;
        }
    }

    if (found) {
        uint64_t shift = (4 - (uint8_t)level) * es + 3;
        uint64_t idx = (vaddr >> shift) & imask;
        uint64_t entry = *(uint64_t *)(tbl + idx * 8);
        if ((~(uint16_t)entry & 0x401) == 0) {
            uint64_t pa_frame = 0;
            if (my_pa_bits == 52) {
                pa_frame = (entry << 36) & 0xF000000000000ULL;
            }
            phys_addr = (pa_frame + (entry & pmask)) & (-1ULL << ps);
            phys_addr |= vaddr & ~(-1ULL << ps);
        }
    }

    return phys_addr;
}

long read_process_memory(uint32_t pid, uint64_t vaddr, uint64_t size, char *__user out_msg)
{
    void *task = kf_find_task_by_vpid(pid);
    if (!task) return -ESRCH;

    void *mm = kf_get_task_mm(task);
    if (!mm) return -EINVAL;

    uint64_t remaining = size;
    uint64_t cur_vaddr = vaddr;
    uint64_t cur_outbuf = (uint64_t)out_msg;
    long total_copied = 0;

    // 分块拷贝逻辑：按页的大小截断处理，避免跨页引起的缺页和地址越界问题
    while (remaining > 0) {
        uint64_t pgsz = 1ULL << my_page_shift;
        uint64_t pgoff = cur_vaddr & (pgsz - 1);
        uint64_t chunk = pgsz - pgoff;
        if (chunk > remaining) chunk = remaining;

        uint64_t phys_addr = get_phys_addr(mm, cur_vaddr);
        if (phys_addr) {
            if (kf_pfn_valid(phys_addr >> my_page_shift) &&
                kf_valid_phys_addr_range(phys_addr, chunk)) {
                
                // 将物理地址转换为内核虚拟地址（线性映射区）
                uint64_t kva = phys_to_virt_compat(phys_addr);
                
                uint64_t uncopied = kf___arch_copy_to_user((void __user *)cur_outbuf, (void *)kva, chunk);
                total_copied += (chunk - uncopied);
            }
        }

        remaining -= chunk;
        cur_vaddr += chunk;
        cur_outbuf += chunk;
    }

    kf_mmput(mm);
    return total_copied;
}
