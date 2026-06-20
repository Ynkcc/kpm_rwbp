#ifndef CASE_HWBP_EXTRA_H
#define CASE_HWBP_EXTRA_H

#include <stdbool.h>

/**
 * 运行大规模断点注册与注销测试（测试超过 64 个断点的注销与内存清理）
 *
 * @param anon_fd    匿名控制 FD
 * @return           成功返回 true，失败返回 false
 */
bool run_case_hwbp_scale(int anon_fd);

/**
 * 运行并发多线程断点命中与读取测试（测试无锁环形缓冲区的并发正确性与死锁风险消除）
 *
 * @param anon_fd    匿名控制 FD
 * @return           成功返回 true，失败返回 false
 */
bool run_case_hwbp_concurrency(int anon_fd);

#endif // CASE_HWBP_EXTRA_H
