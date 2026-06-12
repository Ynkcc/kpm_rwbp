#include "mem_reader.h"
#include "kernel_compat.h"
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/errno.h>

// 核心读取函数 - 基于 access_process_vm 的稳健读取方案
long read_process_memory(uint32_t pid, uint64_t vaddr, uint64_t size, char *__user out_msg)
{
    pr_info("[kpm_RWBP] read_process_memory request: pid=%u, vaddr=%llx, size=%llu\n", 
            pid, (unsigned long long)vaddr, (unsigned long long)size);

    void *task = kfunc(find_task_by_vpid)(pid);
    if (!task) {
        pr_err("[kpm_RWBP] find_task_by_vpid failed for pid %u\n", pid);
        return -ESRCH;
    }

    uint64_t remaining = size;
    uint64_t cur_vaddr = vaddr;
    uint64_t cur_outbuf = (uint64_t)out_msg;
    long total_copied = 0;
    
    // 使用本地栈空间作为临时拷贝缓存，免去 kmalloc 与 GFP 兼容性风险
    char kbuf[1024];

    while (remaining > 0) {
        uint64_t chunk = (remaining > sizeof(kbuf)) ? sizeof(kbuf) : remaining;

        // 调用 access_process_vm 从目标进程中读取到栈缓存
        int read_bytes = kfunc(access_process_vm)(task, cur_vaddr, kbuf, chunk, 0);
        if (read_bytes <= 0) {
            pr_warn("[kpm_RWBP] access_process_vm failed for vaddr=%llx\n", (unsigned long long)cur_vaddr);
            break;
        }

        // 安全拷贝到控制进程用户空间
        long copy_err = compat_copy_to_user((void __user *)cur_outbuf, kbuf, read_bytes);
        if (copy_err < 0) {
            copy_err = read_bytes;
        }

        int copied = read_bytes - copy_err;
        total_copied += copied;

        if (copied < chunk) {
            break;
        }

        remaining -= copied;
        cur_vaddr += copied;
        cur_outbuf += copied;
    }

    return total_copied;
}
