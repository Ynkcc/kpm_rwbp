#ifndef __DISPATCHER_H__
#define __DISPATCHER_H__

#ifdef __KERNEL__
#include <common.h>
#else
#include <stdint.h>
#include <stdbool.h>
#endif

#ifdef __USER_SPACE__
// 用户态通信接口
long kpm_ipc_cmd(int fd, unsigned int cmd, void *arg);
#endif

// Ioctl 命令定义，使用简单整数值以避免头文件冲突
#define OP_READ_MEM                  8001
#define OP_WRITE_MEM                 8002
#define OP_SET_HW_BREAKPOINT         8011
#define OP_REMOVE_HW_BREAKPOINT      8013
#define OP_REMOVE_ALL_HW_BREAKPOINT  8014
#define OP_READ_HW_BP_INFO           8015  // 新增：读取断点命中信息
#define OP_GET_HW_BREAKPOINT_CAPS    8016
#define OP_ENABLE_HW_BREAKPOINT     8017
#define OP_DISABLE_HW_BREAKPOINT    8018
#define OP_QUERY_HW_BREAKPOINT_STATUS 8019
#define OP_GHOST_ALLOC               8021
#define OP_GHOST_FREE                8022
#define OP_GHOST_WRITE               8023
#define OP_READ_OBSERVE_RECORDS      8031  // 新增：读取 OBSERVE 观测记录

typedef struct {
    uint32_t pid;
    uint32_t num_pages;
    uint64_t near_addr;
    uint64_t range;
    uint64_t pte_template;
} ghost_alloc_cmd_t;

typedef struct {
    uint64_t vaddr;
} ghost_free_cmd_t;

typedef struct {
    uint64_t vaddr;
    uint32_t offset;
    uint32_t size;
    uint64_t buffer;
} ghost_write_cmd_t;

// 内存读取命令参数结构体
typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t addr;
    uint64_t buffer;
    uint64_t size;
} copy_memory_t;

// 内存写入命令参数结构体
typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t addr;       // 目标进程虚拟地址
    uint64_t buffer;     // 源数据用户态地址
    uint64_t size;       // 写入大小
} write_memory_t;

// 硬件断点命令参数结构体
typedef struct {
    uint32_t pid;
    uint32_t type;
    uint64_t addr;
    uint32_t len;
    uint32_t scheme; // 1: 方案1, 2: 方案2, 3: 方案3, 4: 方案4
} hw_breakpoint_cmd_t;

// 寄存器快照结构体 (ARM64)
typedef struct {
    uint64_t regs[31];  // X0-X30 (LR)
    uint64_t sp;       // 栈指针
    uint64_t pc;       // 程序计数器
    uint64_t pstate;   // 处理器状态
} hwbp_regs_snapshot_t;

// 单条命中记录结构体
typedef struct {
    uint64_t hit_time;         // 命中时间戳
    uint32_t task_id;         // 触发线程 ID
    uint32_t _pad;
    uint64_t hit_addr;        // 触发地址
    hwbp_regs_snapshot_t regs_info;  // 寄存器快照
} hwbp_hit_item_t;

// 命中信息读取结构体
typedef struct {
    uint32_t pid;             // 目标进程 PID
    uint32_t _pad;
    uint64_t max_count;       // 输入：最大返回条数
    uint64_t user_buf;        // 输出：hwbp_hit_item_t 数组指针
    uint64_t actual_count;    // 输出：实际返回条数
} hwbp_info_cmd_t;

#define SHM_MAGIC 0x53484d43 // 'SHMC'

typedef struct {
    uint32_t magic;         // SHM_MAGIC
    uint32_t cmd;           // OP_READ_MEM 等
    int32_t  status;        // 0: 空闲/完成, 1: 有请求
    int32_t  retval;        // 返回码
    uint32_t data_size;     // 数据载荷大小
    uint32_t _pad;
    uint8_t  payload[3500]; // 共享缓冲区 (用于读写数据载荷)
} shm_channel_t;

// 核心分发入口定义
long rwbp_dispatch(shm_channel_t *shm);

// 硬件调试能力结构体
typedef struct {
    uint32_t max_breakpoints;
    uint32_t max_watchpoints;
} hwbp_caps_t;

// 硬件调试状态查询命令结构体
typedef struct {
    uint32_t pid;
    uint32_t _pad0;
    uint64_t addr;
    uint32_t active;
    uint32_t bp_type;
    uint32_t len;
    uint32_t scheme;
    uint64_t hit_count;
} hwbp_query_cmd_t;

// OBSERVE 观测记录事件类型
#define OBSERVE_EVENT_PERF           0
#define OBSERVE_EVENT_PTRACE         1

// 单条 OBSERVE 观测记录（与 src/ipc/protocol.rs 的 ObserveRecord 保持一致）
typedef struct {
    uint32_t event_type;   // OBSERVE_EVENT_*
    uint32_t _pad0;
    uint32_t pid;          // 发起者 PID
    uint32_t tid;          // 发起者 TID
    uint64_t bp_addr;      // perf: attr.bp_addr / ptrace: 槽位地址
    uint64_t bp_type;      // perf: attr.bp_type / ptrace: NT 类型
    uint64_t bp_len;       // perf: attr.bp_len
    uint64_t caller_pc;    // 发起者用户态 pc
    uint64_t caller_lr;    // 发起者用户态 lr
    uint64_t path_offset;  // bp_addr - vma.vm_start（so 内偏移）
    uint32_t path_len;     // path 有效长度（0 表示无法解析）
    uint32_t _pad1;
    char     path[64];     // d_path 结果
} observe_record_t;

// OBSERVE 观测记录读取结构体
typedef struct {
    uint32_t pid;             // 目标进程 PID
    uint32_t _pad;
    uint64_t max_count;       // 输入：最大返回条数
    uint64_t user_buf;        // 输出：observe_record_t 数组指针
    uint64_t actual_count;    // 输出：实际返回条数
} observe_info_cmd_t;

#endif // __DISPATCHER_H__
