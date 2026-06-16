#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include "kpm_ctrl.h"
#include "case_mem_read.h"
#include "case_mem_write.h"
#include "case_mem_list.h"
#include "case_mem_array.h"
#include "case_hwbp_self.h"
#include "../include/supercall.h"

#define MAX_RESULTS  16

// 测试结果条目
typedef struct {
    const char *name;
    bool        passed;
} test_result_t;

static void print_usage(const char *prog)
{
    printf("用法: %s [OPTIONS]\n", prog);
    printf("  --case <name>     all | mem | mem-write | mem-list | mem-array | hwbp-self | hwbp-target  (默认: all)\n");
    printf("  --scheme <n>      HWBP 方案 1-4，0=全部运行  (默认: 0)\n");
    printf("  --timeout <ms>    单个断点方案超时时间 ms  (默认: 3000)\n");
    printf("  --help\n");
}

static void print_summary(test_result_t *results, int count)
{
    int pass = 0;
    for (int i = 0; i < count; i++)
        if (results[i].passed) pass++;

    printf("\n========================================\n");
    printf("           测试结果汇总\n");
    printf("========================================\n");
    for (int i = 0; i < count; i++) {
        printf("  %s  %s\n",
               results[i].passed ? "\033[32m[PASS]\033[0m" : "\033[31m[FAIL]\033[0m",
               results[i].name);
    }
    printf("----------------------------------------\n");
    printf("  通过: %d / %d   失败: %d / %d\n", pass, count, count - pass, count);
    printf("========================================\n\n");
}

int main(int argc, char *argv[])
{
    // --- 解析命令行参数 ---
    const char *run_case = "all";
    int scheme    = 0;    // 0 = 全部方案
    int timeout   = 3000; // ms

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--case")     == 0 && i + 1 < argc) run_case  = argv[++i];
        else if (strcmp(argv[i], "--scheme")   == 0 && i + 1 < argc) scheme    = atoi(argv[++i]);
        else if (strcmp(argv[i], "--timeout")  == 0 && i + 1 < argc) timeout   = atoi(argv[++i]);
        else if (strcmp(argv[i], "--help")     == 0) { print_usage(argv[0]); return 0; }
    }

    printf("[*] test_rwbp 启动  case=%s  scheme=%d  timeout=%dms\n",
           run_case, scheme, timeout);
    fflush(stdout);

// 统一清理退出宏
#define CLEANUP_EXIT(code) \
    do { \
        return (code); \
    } while (0)

    // --- 预卸载、加载 KPM ---
    printf("[*] 卸载旧 kpm_alt_pstore 模块 (如有)...\n");
    sc_kpm_unload(KPM_KEY, "kpm_alt_pstore");
    usleep(200000);

    printf("[*] 加载 kpm_alt_pstore KPM: /data/local/tmp/kpm_alt_pstore.kpm\n");
    if (kpm_load(KPM_KEY, "/data/local/tmp/kpm_alt_pstore.kpm") != 0) {
        printf("[-] 加载 kpm_alt_pstore 失败，但尝试继续...\n");
    } else {
        printf("[+] kpm_alt_pstore 加载成功\n");
    }
    usleep(200000);

    printf("[*] 卸载旧模块 (如有)...\n");
    sc_kpm_unload(KPM_KEY, KPM_NAME);
    usleep(200000);

    printf("[*] 加载 KPM: %s\n", KPM_PATH);
    if (kpm_load(KPM_KEY, KPM_PATH) != 0)
        CLEANUP_EXIT(1);
    printf("[+] KPM 加载成功\n");
    usleep(200000);

    // --- 获取匿名控制 FD ---
    int anon_fd = get_anon_fd();
    if (anon_fd < 0) {
        kpm_unload(KPM_KEY, KPM_NAME);
        CLEANUP_EXIT(1);
    }
    printf("[+] 匿名控制 FD: %d\n\n", anon_fd);
    usleep(200000);

    // --- 运行测试用例，收集结果 ---
    test_result_t results[MAX_RESULTS];
    int result_count = 0;

    bool do_mem      = (strcmp(run_case, "all") == 0 || strcmp(run_case, "mem") == 0);
    bool do_mem_write = (strcmp(run_case, "all") == 0 || strcmp(run_case, "mem-write") == 0);
    bool do_mem_list  = (strcmp(run_case, "all") == 0 || strcmp(run_case, "mem-list") == 0);
    bool do_mem_array = (strcmp(run_case, "all") == 0 || strcmp(run_case, "mem-array") == 0);
    bool do_self      = (strcmp(run_case, "all") == 0 || strcmp(run_case, "hwbp-self") == 0);
    bool do_target    = (strcmp(run_case, "all") == 0 || strcmp(run_case, "hwbp-target") == 0);

    // case: mem_read
    if (do_mem) {
        printf("[*] ========== 运行 case: mem_read ==========\n");
        bool ok = run_case_mem_read(anon_fd);
        results[result_count++] = (test_result_t){ "mem_read", ok };
        printf("\n");
    }

    // case: mem_write
    if (do_mem_write) {
        printf("[*] ========== 运行 case: mem_write ==========\n");
        bool ok = run_case_mem_write(anon_fd);
        results[result_count++] = (test_result_t){ "mem_write", ok };
        printf("\n");
    }

    // case: mem_list
    if (do_mem_list) {
        printf("[*] ========== 运行 case: mem_list ==========\n");
        bool ok = run_case_mem_list(anon_fd);
        results[result_count++] = (test_result_t){ "mem_list", ok };
        printf("\n");
    }

    // case: mem_array
    if (do_mem_array) {
        printf("[*] ========== 运行 case: mem_array ==========\n");
        bool ok = run_case_mem_array(anon_fd);
        results[result_count++] = (test_result_t){ "mem_array", ok };
        printf("\n");
    }

    // case: hwbp_self（所有/指定方案全量运行）
    if (do_self) {
        printf("[*] ========== 运行 case: hwbp_self ==========\n");

        hwbp_scheme_result_t scheme_results[4] = {0};
        run_case_hwbp_self(anon_fd, scheme, scheme_results, timeout);

        // 将每个方案作为独立条目加入汇总
        int start = (scheme == 0) ? 1 : scheme;
        int end   = (scheme == 0) ? 4 : scheme;
        for (int s = start, i = 0; s <= end; s++, i++) {
            char *name = malloc(32);
            snprintf(name, 32, "hwbp_self (方案 %d)", scheme_results[i].scheme);
            results[result_count++] = (test_result_t){ name, scheme_results[i].passed };
        }
        printf("\n");
    }

    // case: hwbp_target
    if (do_target) {
        printf("[*] ========== 运行 case: hwbp_target ==========\n");
        int use_scheme = (scheme == 0) ? 1 : scheme; // target 默认用方案 1
        bool ok = run_case_hwbp_target(anon_fd, use_scheme);
        results[result_count++] = (test_result_t){ "hwbp_target", ok };
        printf("\n");
    }

    // --- 打印汇总结果 ---
    print_summary(results, result_count);

    // --- 清理 ---
    close(anon_fd);
    kpm_unload(KPM_KEY, KPM_NAME);
    kpm_unload(KPM_KEY, "kpm_alt_pstore");

    CLEANUP_EXIT(0);
}
