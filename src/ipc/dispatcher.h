#ifndef __DISPATCHER_H__
#define __DISPATCHER_H__

#ifdef __KERNEL__
#include <common.h>
#else
#include <stdint.h>
#endif

// Ioctl 命令定义，使用简单整数值以避免头文件冲突
#define OP_READ_MEM                  8001
#define OP_SET_HW_BREAKPOINT         8011
#define OP_REMOVE_HW_BREAKPOINT      8013
#define OP_REMOVE_ALL_HW_BREAKPOINT  8014

// 内存读取命令参数结构体
typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t addr;
    uint64_t buffer;
    uint64_t size;
} copy_memory_t;

// 硬件断点命令参数结构体
typedef struct {
    uint32_t pid;
    uint32_t type;
    uint64_t addr;
    uint32_t len;
    uint32_t scheme; // 1: 方案1, 2: 方案2, 3: 方案3, 4: 方案4
} hw_breakpoint_cmd_t;

// 核心分发入口定义
long rwbp_dispatch(unsigned int cmd, unsigned long arg);

#endif // __DISPATCHER_H__
