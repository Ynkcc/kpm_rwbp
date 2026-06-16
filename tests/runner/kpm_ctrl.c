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

// 全局共享内存通道指针
static shm_channel_t *g_shm = NULL;

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
    printf("[*] kpm_unload 返回: %ld, errno: %d (%s)\n", ret, errno, strerror(errno));
    if (g_shm) {
        munmap(g_shm, 4096);
        g_shm = NULL;
    }
}

int get_anon_fd(void)
{
    if (g_shm == NULL) {
        // 分配一页共享内存
        g_shm = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (g_shm == MAP_FAILED) {
            perror("[-] mmap 共享内存失败");
            g_shm = NULL;
            return -1;
        }
        memset(g_shm, 0, 4096);
        g_shm->magic = SHM_MAGIC;
    }

    printf("[*] 正在触发 fstatfs 引导绑定共享内存: %p\n", g_shm);
    // ARM64: 44 = __NR_fstatfs，传递共享内存虚拟地址进行内核绑定
    int ret = (int)syscall(44, (unsigned long)g_shm, (void *)0xDEADC0DEULL);
    if (ret != 0) {
        perror("[-] fstatfs 共享内存通道绑定失败");
        munmap(g_shm, 4096);
        g_shm = NULL;
        return -1;
    }
    // 返回虚拟的非负句柄 (999) 代表绑定成功
    return 999;
}

long kpm_ipc_cmd(int fd, unsigned int cmd, void *arg)
{
    if (!g_shm) {
        errno = ENOTCONN;
        return -1;
    }

    // 1. 将参数拷入共享内存 payload
    if (cmd == OP_READ_MEM) {
        copy_memory_t *rcmd = (copy_memory_t *)arg;
        memcpy(g_shm->payload, rcmd, sizeof(copy_memory_t));
    }
    else if (cmd == OP_WRITE_MEM) {
        write_memory_t *wcmd = (write_memory_t *)arg;
        memcpy(g_shm->payload, wcmd, sizeof(write_memory_t));
    }
    else if (cmd == OP_SET_HW_BREAKPOINT || cmd == OP_REMOVE_HW_BREAKPOINT) {
        hw_breakpoint_cmd_t *bcmd = (hw_breakpoint_cmd_t *)arg;
        memcpy(g_shm->payload, bcmd, sizeof(hw_breakpoint_cmd_t));
    }
    else if (cmd == OP_READ_HW_BP_INFO) {
        hwbp_info_cmd_t *icmd = (hwbp_info_cmd_t *)arg;
        memcpy(g_shm->payload, icmd, sizeof(hwbp_info_cmd_t));
    }

    g_shm->cmd = cmd;
    g_shm->status = 1; // 标记请求就绪

    // 2. 触发系统调用敲门通知内核
    syscall(44, 0, (void *)0xDEADC0DEULL);

    // 3. 同步读取结果返回值
    long retval = g_shm->retval;

    // 4. 如果是读取数据的命令，需要将共享内存中的结果写回原用户态缓冲区
    if (retval >= 0) {
        if (cmd == OP_READ_MEM) {
            copy_memory_t *rcmd = (copy_memory_t *)arg;
            memcpy((void *)rcmd->buffer, g_shm->payload, g_shm->data_size);
        }
        else if (cmd == OP_READ_HW_BP_INFO) {
            hwbp_info_cmd_t *icmd = (hwbp_info_cmd_t *)arg;
            memcpy((void *)icmd->user_buf, g_shm->payload, g_shm->data_size);
            icmd->actual_count = g_shm->data_size / 296; // 296 = sizeof(hwbp_hit_item_t)
        }
    } else {
        // 出错时设置 errno
        errno = -retval;
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
