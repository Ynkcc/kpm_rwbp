#ifndef __MEM_READER_H__
#define __MEM_READER_H__

#include <common.h>

// 读取指定进程 of 虚拟内存
long read_process_memory(uint32_t pid, uint64_t vaddr, uint64_t size, char *out_msg);

#endif // __MEM_READER_H__
