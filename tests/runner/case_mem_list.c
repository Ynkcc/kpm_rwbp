#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <errno.h>
#include "case_mem_list.h"
#include "kpm_ctrl.h"
#include "dispatcher.h"

// 模拟内核链表节点结构
struct list_node {
    uint64_t data;           // 节点数据
    struct list_node *next; // 指向下一个节点
};

// 模拟 struct list_head 节点结构 (next 在偏移 0, data 在偏移 16)
struct list_head_dummy {
    struct list_head_dummy *next;
    struct list_head_dummy *prev;
    uint64_t data;
};

bool run_case_mem_list(int anon_fd)
{
    bool all_pass = true;
    uint32_t pid = (uint32_t)getpid();

    printf("[*] ===== 内存链表读取测试 =====\n");

    // --- 子测试 1: 简单的链表节点读取 ---
    // 创建一个简单的链表结构
    struct list_node node3 = {.data = 0x3333333333333333ULL, .next = NULL};
    struct list_node node2 = {.data = 0x2222222222222222ULL, .next = &node3};
    struct list_node node1 = {.data = 0x1111111111111111ULL, .next = &node2};
    struct list_node head  = {.data = 0x0000000000000000ULL, .next = &node1};

    printf("[*] [mem_list] 创建测试链表: head -> node1 -> node2 -> node3\n");
    printf("    节点地址: head=%p, node1=%p, node2=%p, node3=%p\n",
           (void *)&head, (void *)&node1, (void *)&node2, (void *)&node3);
    fflush(stdout);

    // 读取链表: head -> next (node1) -> next (node2) -> next (node3) -> data
    // 偏移计算 (假设是64位系统):
    //   next 在 data 之后，即 offset = sizeof(uint64_t) = 8
    //   data 偏移 = 0
    uint64_t offsets[] = {
        8,   // head.next 偏移 -> node1
        8,   // node1.next 偏移 -> node2
        8,   // node2.next 偏移 -> node3
        0    // node3.data 偏移 -> 读取数据
    };

    uint64_t read_data = 0;
    long ret = kpm_read_mem_list(pid, (uint64_t)&head, offsets, 4, &read_data, sizeof(read_data));
    if (ret < 0) {
        printf("[-] [mem_list] 链表读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (read_data == 0x3333333333333333ULL);
        printf("%s [mem_list] 链表遍历读取: 期望 0x3333333333333333, 实际 0x%llx\n",
               pass ? "[+]" : "[-]", (unsigned long long)read_data);
        if (!pass) all_pass = false;
    }

    // --- 子测试 2: 读取链表头的 data (无遍历) ---
    // head.data 在偏移 0 处
    uint64_t single_offset[] = {0};
    uint64_t head_data = 0;

    ret = kpm_read_mem_list(pid, (uint64_t)&head, single_offset, 1, &head_data, sizeof(head_data));
    if (ret < 0) {
        printf("[-] [mem_list] 单节点读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (head_data == 0x0000000000000000ULL);
        printf("%s [mem_list] 单节点读取: 期望 0, 实际 0x%llx\n",
               pass ? "[+]" : "[-]", (unsigned long long)head_data);
        if (!pass) all_pass = false;
    }

    // --- 子测试 3: 读取 node2 的数据 ---
    // head.next (node1) -> next (node2) -> data
    uint64_t offsets2[] = {
        8,   // head.next -> node1
        8,   // node1.next -> node2
        0    // node2.data
    };
    uint64_t node2_data = 0;

    ret = kpm_read_mem_list(pid, (uint64_t)&head, offsets2, 3, &node2_data, sizeof(node2_data));
    if (ret < 0) {
        printf("[-] [mem_list] node2 读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (node2_data == 0x2222222222222222ULL);
        printf("%s [mem_list] node2 读取: 期望 0x2222222222222222, 实际 0x%llx\n",
               pass ? "[+]" : "[-]", (unsigned long long)node2_data);
        if (!pass) all_pass = false;
    }

    // --- 子测试 4: 模拟读取 struct list_head 链表 ---
    // 每一个 lh_node 的 next 均在偏移 0 处，data 在偏移 16 处
    struct list_head_dummy lh_node3 = {.next = NULL, .prev = NULL, .data = 0x3333333333333333ULL};
    struct list_head_dummy lh_node2 = {.next = &lh_node3, .prev = NULL, .data = 0x2222222222222222ULL};
    struct list_head_dummy lh_node1 = {.next = &lh_node2, .prev = NULL, .data = 0x1111111111111111ULL};
    struct list_head_dummy lh_head  = {.next = &lh_node1, .prev = NULL, .data = 0x0000000000000000ULL};

    printf("[*] [mem_list] 模拟 struct list_head 链表读取\n");
    fflush(stdout);

    // list_head 结构 (next 在偏移 0，prev 在偏移 8，data 在偏移 16)
    // 读取 lh_head.next->next->next->data (跳过3个节点后读取数据)
    uint64_t list_offsets[] = {
        0,   // lh_head.next
        0,   // lh_node1.next
        0,   // lh_node2.next
        16   // lh_node3.data
    };

    uint64_t third_node_data = 0;
    ret = kpm_read_mem_list(pid, (uint64_t)&lh_head, list_offsets, 4, &third_node_data, sizeof(third_node_data));
    if (ret < 0) {
        printf("[-] [mem_list] list_head 链表读取失败, errno=%d\n", errno);
        all_pass = false;
    } else {
        bool pass = (third_node_data == 0x3333333333333333ULL);
        printf("%s [mem_list] list_head 遍历读取: 期望 0x3333333333333333, 实际 0x%llx\n",
               pass ? "[+]" : "[-]", (unsigned long long)third_node_data);
        if (!pass) all_pass = false;
    }

    printf("[*] ===== 内存链表读取测试完成: %s =====\n\n",
           all_pass ? "全部通过" : "存在失败");
    fflush(stdout);
    return all_pass;
}