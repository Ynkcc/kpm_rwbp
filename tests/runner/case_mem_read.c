#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include "case_mem_read.h"
#include "dispatcher.h"

static void print_hex(const unsigned char *buf, size_t len)
{
    printf("  HEX: ");
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", buf[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len)
            printf("\n       ");
    }
    printf("\n");
}

bool run_case_mem_read(int anon_fd)
{
    bool all_pass = true;

    // --- 子测试 1: 单个 int 读取 ---
    int test_value = 556677;
    printf("[*] [mem_read] 读取本地 int 变量 %p，当前值: %d\n", &test_value, test_value);
    fflush(stdout);

    copy_memory_t rcmd;
    rcmd.pid    = (uint32_t)getpid();
    rcmd.addr   = (uint64_t)&test_value;
    rcmd.buffer = (uint64_t)malloc(sizeof(test_value));
    rcmd.size   = sizeof(test_value);

    long ret = kpm_ipc_cmd(anon_fd, OP_READ_MEM, &rcmd);
    if (ret < 0) {
        printf("[-] [mem_read] int 读取 ioctl 失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        int read_val = *(int *)rcmd.buffer;
        bool pass = (read_val == test_value);
        printf("%s [mem_read] int 读取: 期望 %d, 实际 %d\n",
               pass ? "[+]" : "[-]", test_value, read_val);
        print_hex((const unsigned char *)rcmd.buffer, sizeof(test_value));
        if (!pass) all_pass = false;
    }
    free((void *)rcmd.buffer);

    // --- 子测试 2: 批量读取 ---
    char test_pattern[64];
    snprintf(test_pattern, sizeof(test_pattern), "RWBP_TEST_PATTERN_0x%08X", 0xDEADBEEF);

    copy_memory_t bulk;
    bulk.pid    = (uint32_t)getpid();
    bulk.addr   = (uint64_t)test_pattern;
    bulk.buffer = (uint64_t)malloc(sizeof(test_pattern));
    bulk.size   = sizeof(test_pattern);

    printf("[*] [mem_read] 批量读取 %zu 字节: \"%s\"\n", sizeof(test_pattern), test_pattern);
    fflush(stdout);

    ret = kpm_ipc_cmd(anon_fd, OP_READ_MEM, &bulk);
    if (ret < 0) {
        printf("[-] [mem_read] 批量 ioctl 失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (memcmp((void *)bulk.buffer, test_pattern, sizeof(test_pattern)) == 0);
        printf("%s [mem_read] 批量读取: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        print_hex((const unsigned char *)bulk.buffer, sizeof(test_pattern));
        if (!pass) all_pass = false;
    }
    free((void *)bulk.buffer);

    fflush(stdout);
    return all_pass;
}
