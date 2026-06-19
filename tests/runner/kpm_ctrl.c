#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "kpm_ctrl.h"
#include "dispatcher.h"
#include "../include/supercall.h"

int kpm_load(const char *key, const char *path)
{
    long ret = sc_kpm_load(key, path, "");
    if (ret != 0) {
        printf("[-] sc_kpm_load 失败: %ld, errno: %d (%s)\n", ret, errno, strerror(errno));
        return -1;
    }
    return 0;
}

void kpm_unload(const char *key, const char *name)
{
    long ret = sc_kpm_unload(key, name);
    if (ret != 0) {
        printf("[-] kpm_unload 失败: %ld, errno: %d (%s)\n", ret, errno, strerror(errno));
    } else {
        printf("[+] kpm_unload 成功\n");
    }
}

int get_anon_fd(void)
{
    // 返回 999 作为虚拟句柄指示成功，当前为无状态系统调用，不需要共享内存绑定。
    return 999;
}

long kpm_ipc_cmd(int fd, unsigned int cmd, void *arg)
{
    // 直接发起无状态系统调用进行指令 RPC 交互
    long retval = syscall(44, (unsigned long)arg, (void *)0xDEADC0DEULL, (unsigned long)cmd);

    if (retval < 0) {
        return -1;
    }
    return retval;
}

// ============================================================================
// 便捷封装函数
// ============================================================================

// 内存写入
long kpm_write_mem(uint32_t pid, uint64_t vaddr, const void *buffer, uint64_t size)
{
    write_memory_t wcmd = {
        .pid = pid,
        ._pad0 = 0,
        .addr = vaddr,
        .buffer = (uint64_t)buffer,
        .size = size
    };
    return kpm_ipc_cmd(-1, OP_WRITE_MEM, &wcmd);
}

// 内存读取
long kpm_read_mem(uint32_t pid, uint64_t vaddr, void *dest, uint64_t size)
{
    copy_memory_t rcmd = {
        .pid = pid,
        ._pad0 = 0,
        .addr = vaddr,
        .buffer = (uint64_t)dest,
        .size = size
    };
    return kpm_ipc_cmd(-1, OP_READ_MEM, &rcmd);
}

// 内存链表读取
long kpm_read_mem_list(uint32_t pid, uint64_t base_addr, const uint64_t *addrs, uint64_t count,
                       void *dest, uint64_t size)
{
    uint64_t current_base = base_addr;
    long total_read = 0;

    for (uint64_t i = 0; i < count; i++) {
        uint64_t offset = addrs[i];

        if (offset == (uint64_t)-1) {
            break;
        }

        if (i + 1 >= count) {
            // 最后一项：读取实际数据
            long ret = kpm_read_mem(pid, current_base + offset, dest, size);
            if (ret <= 0) {
                break;
            }
            total_read += ret;
            break;
        } else {
            // 中间项：读取指针
            uint64_t next_ptr = 0;
            long ret = kpm_read_mem(pid, current_base + offset, &next_ptr, sizeof(next_ptr));
            if (ret != sizeof(next_ptr)) {
                break;
            }
            // 考虑 40 位虚拟地址掩码
            current_base = next_ptr & 0xFFFFFFFFFFULL;
            if (!current_base || current_base == 0xFFFFFFFFFFULL) {
                break;
            }
        }
    }
    return total_read > 0 ? total_read : -1;
}

// 内存数组读取
long kpm_read_mem_array(uint32_t pid, uint64_t array_vaddr, uint64_t count,
                        void *dest, uint64_t item_size)
{
    // 在用户态，数组是连续分布的，仅需一次读取即可
    return kpm_read_mem(pid, array_vaddr, dest, count * item_size);
}
