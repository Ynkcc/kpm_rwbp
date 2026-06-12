#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "case_mem_array.h"
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

bool run_case_mem_array(int anon_fd)
{
    bool all_pass = true;
    uint32_t pid = (uint32_t)getpid();

    printf("[*] ===== 内存数组读取测试 =====\n");

    // --- 子测试 1: 读取指针数组 ---
    uint64_t ptr_array[5] = {
        0x1111111111111111ULL,
        0x2222222222222222ULL,
        0x3333333333333333ULL,
        0x4444444444444444ULL,
        0x5555555555555555ULL
    };

    printf("[*] [mem_array] 读取指针数组: 5 个元素\n");
    fflush(stdout);

    uint64_t read_ptrs[5] = {0};
    long ret = kpm_read_mem_array(pid, (uint64_t)ptr_array, 5, read_ptrs, 8);
    if (ret < 0) {
        printf("[-] [mem_array] 指针数组读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = true;
        for (int i = 0; i < 5; i++) {
            if (read_ptrs[i] != ptr_array[i]) {
                pass = false;
                break;
            }
        }
        printf("%s [mem_array] 指针数组读取: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        print_hex((const unsigned char *)read_ptrs, sizeof(read_ptrs));
        if (!pass) all_pass = false;
    }

    // --- 子测试 2: 读取 int 数组 ---
    int int_array[6] = {0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555, 0x66666666};

    printf("[*] [mem_array] 读取 int 数组: 6 个元素 (连续数组, item_size > 8)\n");
    fflush(stdout);

    int read_ints[6] = {0};
    ret = kpm_read_mem_array(pid, (uint64_t)int_array, 6, read_ints, sizeof(int));
    if (ret < 0) {
        printf("[-] [mem_array] int 数组读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = true;
        for (int i = 0; i < 6; i++) {
            if (read_ints[i] != int_array[i]) {
                pass = false;
                break;
            }
        }
        printf("%s [mem_array] int 数组读取: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        print_hex((const unsigned char *)read_ints, sizeof(read_ints));
        if (!pass) all_pass = false;
    }

    // --- 子测试 3: 读取 char 数组 (字符串) ---
    char str_array[] = "ARRAY_READ_TEST_STRING_0xDEADBEEF";
    size_t str_len = sizeof(str_array);

    printf("[*] [mem_array] 读取字符串数组: \"%s\"\n", str_array);
    fflush(stdout);

    char read_str[64] = {0};
    ret = kpm_read_mem_array(pid, (uint64_t)str_array, str_len, read_str, 1);
    if (ret < 0) {
        printf("[-] [mem_array] 字符串数组读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (strcmp(read_str, str_array) == 0);
        printf("%s [mem_array] 字符串数组读取: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        printf("    读取内容: \"%s\"\n", read_str);
        if (!pass) all_pass = false;
    }

    // --- 子测试 4: 读取结构体数组 ---
    struct point {
        int x;
        int y;
        int z;
    };

    struct point points[3] = {
        {100, 200, 300},
        {111, 222, 333},
        {999, 888, 777}
    };

    printf("[*] [mem_array] 读取结构体数组: 3 个 point 结构\n");
    fflush(stdout);

    struct point read_points[3] = {0};
    ret = kpm_read_mem_array(pid, (uint64_t)points, 3, read_points, sizeof(struct point));
    if (ret < 0) {
        printf("[-] [mem_array] 结构体数组读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = true;
        for (int i = 0; i < 3; i++) {
            if (read_points[i].x != points[i].x ||
                read_points[i].y != points[i].y ||
                read_points[i].z != points[i].z) {
                pass = false;
                break;
            }
        }
        printf("%s [mem_array] 结构体数组读取: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        for (int i = 0; i < 3; i++) {
            printf("    [%d] 期望 (%d,%d,%d), 实际 (%d,%d,%d)\n",
                   i, points[i].x, points[i].y, points[i].z,
                   read_points[i].x, read_points[i].y, read_points[i].z);
        }
        if (!pass) all_pass = false;
    }

    // --- 子测试 5: 读取部分数组 (只读前3个) ---
    printf("[*] [mem_array] 读取指针数组前3个元素\n");
    fflush(stdout);

    uint64_t partial_ptrs[3] = {0};
    ret = kpm_read_mem_array(pid, (uint64_t)ptr_array, 3, partial_ptrs, 8);
    if (ret < 0) {
        printf("[-] [mem_array] 部分数组读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = true;
        for (int i = 0; i < 3; i++) {
            if (partial_ptrs[i] != ptr_array[i]) {
                pass = false;
                break;
            }
        }
        printf("%s [mem_array] 部分数组读取: %s\n",
               pass ? "[+]" : "[-]", pass ? "内容一致" : "内容不符");
        print_hex((const unsigned char *)partial_ptrs, sizeof(partial_ptrs));
        if (!pass) all_pass = false;
    }

    printf("[*] ===== 内存数组读取测试完成: %s =====\n\n",
           all_pass ? "全部通过" : "存在失败");
    fflush(stdout);
    return all_pass;
}