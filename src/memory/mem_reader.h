#ifndef __MEM_READER_H__
#define __MEM_READER_H__

#include <common.h>

// 读取指定进程的虚拟内存
long read_process_memory(uint32_t pid, uint64_t vaddr, uint64_t size, char *out_msg);

// 写入数据到指定进程的虚拟内存 (使用 access_process_vm + FOLL_WRITE)
long write_process_memory(uint32_t pid, uint64_t vaddr, const char *src, uint64_t size);

#endif // __MEM_READER_H__
