#include "mem_reader.h"
#include "kernel_compat.h"
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/errno.h>
#include <linux/string.h>

// FOLL_WRITE flag for access_process_vm
#ifndef FOLL_WRITE
#define FOLL_WRITE 0x01
#endif
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

        // 安全拷贝到控制进程用户空间或内核共享内存
        long copy_err;
        if (cur_outbuf >= 0xffff000000000000ULL) {
            memcpy((void *)cur_outbuf, kbuf, read_bytes);
            copy_err = 0;
        } else {
            copy_err = compat_copy_to_user((void __user *)cur_outbuf, kbuf, read_bytes);
            if (copy_err < 0) {
                copy_err = read_bytes;
            }
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

// ============================================================================
// 内存写入函数 - 使用 access_process_vm + FOLL_WRITE
// ============================================================================
long write_process_memory(uint32_t pid, uint64_t vaddr, const char *src, uint64_t size)
{
    pr_info("[kpm_RWBP] write_process_memory request: pid=%u, vaddr=%llx, size=%llu\n",
            pid, (unsigned long long)vaddr, (unsigned long long)size);

    void *task = kfunc(find_task_by_vpid)(pid);
    if (!task) {
        pr_err("[kpm_RWBP] write: find_task_by_vpid failed for pid %u\n", pid);
        return -ESRCH;
    }

    uint64_t remaining = size;
    uint64_t cur_vaddr = vaddr;
    uint64_t cur_src = (uint64_t)src;
    long total_written = 0;

    // 使用本地栈空间作为临时拷贝缓存
    char kbuf[1024];

    while (remaining > 0) {
        uint64_t chunk = (remaining > sizeof(kbuf)) ? sizeof(kbuf) : remaining;

        // 从用户态源地址读取数据到内核栈缓冲区
        long copy_err;
        if (cur_src >= 0xffff000000000000ULL) {
            // 源也是内核地址，直接 memcpy
            memcpy(kbuf, (void *)cur_src, chunk);
            copy_err = 0;
        } else {
            copy_err = compat_copy_from_user(kbuf, (void __user *)cur_src, chunk);
            if (copy_err < 0) {
                copy_err = chunk;
            }
        }

        int to_write = chunk - copy_err;
        if (to_write <= 0) {
            break;
        }

        // 使用 access_process_vm 写入目标进程内存，加上 FOLL_WRITE flag
        int written = kfunc(access_process_vm)(task, cur_vaddr, kbuf, to_write, FOLL_WRITE);
        if (written <= 0) {
            pr_warn("[kpm_RWBP] write: access_process_vm failed at vaddr=%llx\n",
                    (unsigned long long)cur_vaddr);
            break;
        }

        total_written += written;

        if (written < to_write) {
            break;
        }

        remaining -= written;
        cur_vaddr += written;
        cur_src += written;
    }

    pr_info("[kpm_RWBP] write_process_memory total_written: %ld\n", total_written);
    return total_written;
}
