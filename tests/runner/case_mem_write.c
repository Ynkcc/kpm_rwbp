#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "case_mem_write.h"
#include "kpm_ctrl.h"
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

// 简单的链表节点结构（用于测试链表读取）
struct test_list_node {
    uint64_t value;
    struct test_list_node *next;
};

bool run_case_mem_write(int anon_fd)
{
    bool all_pass = true;
    uint32_t pid = (uint32_t)getpid();

    printf("[*] ===== 内存写入测试 =====\n");

    // --- 子测试 1: 写入并读取 int ---
    int test_value = 0;
    int new_value = 0x12345678;
    printf("[*] [mem_write] 测试写入 int: 地址=%p, 新值=0x%08X\n", &test_value, new_value);
    fflush(stdout);

    long ret = kpm_write_mem(pid, (uint64_t)&test_value, &new_value, sizeof(new_value));
    if (ret < 0) {
        printf("[-] [mem_write] int 写入失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        // 验证写入成功
        bool pass = (test_value == new_value);
        printf("%s [mem_write] int 写入: 期望 0x%08X, 实际 0x%08X\n",
               pass ? "[+]" : "[-]", new_value, test_value);
        if (!pass) all_pass = false;
    }

    // --- 子测试 2: 写入字符串 ---
    char test_str_src[64] = "RWBP_WRITE_TEST_STRING_0xDEADBEEF";
    char test_str_dst[64] = {0};
    printf("[*] [mem_write] 测试写入字符串: src=\"%s\"\n", test_str_src);
    fflush(stdout);

    ret = kpm_write_mem(pid, (uint64_t)test_str_dst, test_str_src, sizeof(test_str_src));
    if (ret < 0) {
        printf("[-] [mem_write] 字符串写入失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (strcmp(test_str_dst, test_str_src) == 0);
        printf("%s [mem_write] 字符串写入: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        if (!pass) all_pass = false;
    }

    // --- 子测试 3: 写入数组 ---
    int src_array[8] = {0x11111111, 0x22222222, 0x33333333, 0x44444444,
                        0x55555555, 0x66666666, 0x77777777, 0x88888888};
    int dst_array[8] = {0};
    printf("[*] [mem_write] 测试写入 int 数组: 8 个元素\n");
    fflush(stdout);

    ret = kpm_write_mem(pid, (uint64_t)dst_array, src_array, sizeof(src_array));
    if (ret < 0) {
        printf("[-] [mem_write] 数组写入失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = true;
        for (int i = 0; i < 8; i++) {
            if (dst_array[i] != src_array[i]) {
                pass = false;
                break;
            }
        }
        printf("%s [mem_write] 数组写入: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        print_hex((const unsigned char *)dst_array, sizeof(dst_array));
        if (!pass) all_pass = false;
    }

    // --- 子测试 4: 跨页边界写入 ---
    char page_boundary_buf[8192];  // 2 pages
    memset(page_boundary_buf, 0xAA, sizeof(page_boundary_buf));
    char page_verify[8192] = {0};
    printf("[*] [mem_write] 测试跨页边界写入: 大小=%zu 字节\n", sizeof(page_boundary_buf));
    fflush(stdout);

    ret = kpm_write_mem(pid, (uint64_t)page_verify, page_boundary_buf, sizeof(page_boundary_buf));
    if (ret < 0) {
        printf("[-] [mem_write] 跨页写入失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (memcmp(page_verify, page_boundary_buf, sizeof(page_boundary_buf)) == 0);
        printf("%s [mem_write] 跨页写入: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        if (!pass) all_pass = false;
    }

    printf("[*] ===== 内存写入测试完成: %s =====\n\n",
           all_pass ? "全部通过" : "存在失败");
    fflush(stdout);
    return all_pass;
}