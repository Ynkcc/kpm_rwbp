#ifndef CASE_HWBP_SELF_H
#define CASE_HWBP_SELF_H

#include <stdbool.h>

// 单个方案的测试结果
typedef struct {
    int  scheme;
    bool passed;
} hwbp_scheme_result_t;

/**
 * 运行自触发硬件断点测试
 *
 * @param anon_fd    匿名控制 FD
 * @param scheme     要测试的方案：0=全部运行(1-4)，1-4=仅运行指定方案
 * @param results    输出结果数组，调用方需保证至少 4 个元素
 * @param timeout_ms 单方案超时时间（毫秒）
 * @return           通过的方案数量
 */
int run_case_hwbp_self(int anon_fd, int scheme, hwbp_scheme_result_t *results, int timeout_ms);

#endif // CASE_HWBP_SELF_H
