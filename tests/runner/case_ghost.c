#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "case_ghost.h"
#include "dispatcher.h"
#include "kpm_ctrl.h"

// 检查 maps 中是否存在给定的地址
static bool is_addr_in_maps(uint64_t vaddr)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        printf("[-] [ghost] 无法打开 /proc/self/maps\n");
        return false;
    }

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        uint64_t start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (vaddr >= start && vaddr < end) {
                found = true;
                printf("[!] [ghost] 警告：发现地址 0x%lx 落在 maps 映射中: %s", vaddr, line);
                break;
            }
        }
    }
    fclose(fp);
    return found;
}

bool run_case_ghost(int anon_fd)
{
    bool all_pass = true;

    printf("[*] [ghost] 启动 Ghost 内存(VMA-less 物理强插) 测试...\n");

    // 1. 发起分配命令 (OP_GHOST_ALLOC)
    ghost_alloc_cmd_t alloc_cmd;
    alloc_cmd.pid = (uint32_t)getpid();
    alloc_cmd.num_pages = 1;
    alloc_cmd.near_addr = 0x7000000000UL; // 设定一个合理的用户空间大地址附近
    alloc_cmd.range = 0x100000000UL;
    alloc_cmd.pte_template = 0x00E8000000000F53UL; // 典型的 RWX 用户页 PTE 模板属性

    long ret = kpm_ipc_cmd(anon_fd, OP_GHOST_ALLOC, &alloc_cmd);
    if (ret <= 0) {
        printf("[-] [ghost] OP_GHOST_ALLOC 失败, ret=%ld, errno=%d\n", ret, errno);
        return false;
    }

    uint64_t ghost_vaddr = (uint64_t)ret;
    printf("[+] [ghost] 成功分配 Ghost 内存虚拟地址: 0x%lx\n", ghost_vaddr);

    // 2. 验证隐形属性 (不在 maps 里)
    bool in_maps = is_addr_in_maps(ghost_vaddr);
    if (in_maps) {
        printf("[-] [ghost] 失败：Ghost 内存地址在 /proc/self/maps 中可见！\n");
        all_pass = false;
    } else {
        printf("[+] [ghost] 成功：Ghost 内存地址在 /proc/self/maps 中完全隐形 (VMA-less)！\n");
    }

    // 3. 写入 Shellcode 测试 (OP_GHOST_WRITE)
    // Shellcode 逻辑：mov w0, #2026; ret (直接向用户态返回特定常量 2026)
    uint32_t shellcode[] = {
        0x5280FD40, // mov w0, #2026
        0xD65F03C0  // ret
    };

    ghost_write_cmd_t write_cmd;
    write_cmd.vaddr = ghost_vaddr;
    write_cmd.offset = 0;
    write_cmd.size = sizeof(shellcode);
    write_cmd.buffer = (uint64_t)shellcode;

    ret = kpm_ipc_cmd(anon_fd, OP_GHOST_WRITE, &write_cmd);
    if (ret < 0) {
        printf("[-] [ghost] OP_GHOST_WRITE 失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        printf("[+] [ghost] 成功写入 Shellcode 并同步指令缓存 (I-Cache Sync)\n");

        // 4. 执行 Shellcode 验证
        // 将地址强制转换为函数指针并调用它
        typedef int (*shellcode_fn)(void);
        shellcode_fn run_code = (shellcode_fn)ghost_vaddr;

        printf("[*] [ghost] 准备执行 Ghost 内存中的 Shellcode...\n");
        fflush(stdout);

        int result = run_code();
        if (result == 2026) {
            printf("[+] [ghost] 成功：Shellcode 执行正常且返回正确的值 %d！\n", result);
        } else {
            printf("[-] [ghost] 失败：Shellcode 执行返回值不匹配: %d (期望 2026)\n", result);
            all_pass = false;
        }
    }

    // 5. 释放 Ghost 内存 (OP_GHOST_FREE)
    ghost_free_cmd_t free_cmd;
    free_cmd.vaddr = ghost_vaddr;

    ret = kpm_ipc_cmd(anon_fd, OP_GHOST_FREE, &free_cmd);
    if (ret < 0) {
        printf("[-] [ghost] OP_GHOST_FREE 失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        printf("[+] [ghost] 成功释放 Ghost 内存\n");
    }

    fflush(stdout);
    return all_pass;
}
