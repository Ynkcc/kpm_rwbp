#ifndef __HWBP_H__
#define __HWBP_H__

#include "kernel_compat.h"

// 全局在途任务计数器，用于安全退出屏障
extern volatile int in_flight;

// 注册硬件断点外部接口
long register_hwbp(uint32_t pid, uint64_t addr, uint32_t type, uint32_t len, uint32_t scheme);

// 注销指定硬件断点外部接口
long unregister_hwbp(uint32_t pid, uint64_t addr);

// 注销所有硬件断点外部接口
long unregister_all_hwbp(void);

// 移除 watchpoint_handler inline hook 接口
void remove_wp_hook(void);

// 读取断点命中信息
long read_hwbp_info(uint32_t pid, uint64_t max_count, void __user *user_buf, uint64_t *actual_count);

#endif // __HWBP_H__
