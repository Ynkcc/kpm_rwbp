#ifndef KPM_CTRL_H
#define KPM_CTRL_H

#include "dispatcher.h"

// 默认配置（与 src/core/main.c 中 KPM_NAME 保持一致）
#define KPM_KEY  "QWERTY1234"
#define KPM_NAME "kpm_RWBP"
#define KPM_PATH "/data/local/tmp/kpm_RWBP.kpm"

// 加载 KPM，成功返回 0，失败返回 -1
int kpm_load(const char *key, const char *path);

// 卸载 KPM
void kpm_unload(const char *key, const char *name);

// 触发 Hook 获取匿名控制 FD，失败返回 -1
int get_anon_fd(void);

// IPC 命令发送
long kpm_ipc_cmd(int fd, unsigned int cmd, void *arg);

// 内存读取
long kpm_read_mem(uint32_t pid, uint64_t vaddr, void *dest, uint64_t size);

// 内存写入
long kpm_write_mem(uint32_t pid, uint64_t vaddr, const void *buffer, uint64_t size);

// 内存链表读取
long kpm_read_mem_list(uint32_t pid, uint64_t base_addr, const uint64_t *addrs, uint64_t count,
                       void *dest, uint64_t size);

// 内存数组读取
long kpm_read_mem_array(uint32_t pid, uint64_t array_vaddr, uint64_t count,
                        void *dest, uint64_t item_size);

#endif // KPM_CTRL_H
