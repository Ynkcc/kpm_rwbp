#ifndef CASE_HWBP_TARGET_H
#define CASE_HWBP_TARGET_H

#include <stdbool.h>

/**
 * 向外部目标进程设置硬件断点并等待触发
 *
 * @param anon_fd     匿名控制 FD
 * @param scheme      HWBP 方案 (1-4)
 * @param target_path 目标进程可执行文件路径
 * @return            检测到断点命中返回 true，否则返回 false
 */
bool run_case_hwbp_target(int anon_fd, int scheme, const char *target_path);

#endif // CASE_HWBP_TARGET_H
