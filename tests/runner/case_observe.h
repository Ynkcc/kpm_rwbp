#ifndef CASE_OBSERVE_H
#define CASE_OBSERVE_H

#include <stdbool.h>

// case: observe-perf（perf_event_open 拦截 + attr 回读比对）
bool run_case_observe_perf(int anon_fd);

// case: observe-ptrace（PTRACE_SETREGSET/NT_ARM_HW_BREAK 拦截 + 槽位回读比对）
bool run_case_observe_ptrace(int anon_fd);

// case: observe-resolve（find_vma -> d_path 路径解析链路）
bool run_case_observe_resolve(int anon_fd);

#endif // CASE_OBSERVE_H
