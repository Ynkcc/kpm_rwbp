#ifndef __MEM_READER_H__
#define __MEM_READER_H__
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>

/**
 * 读取目标进程的内存数据到用户态输出缓冲区
 * @pid 目标进程 PID
 * @vaddr 目标虚拟地址
 * @size 读取数据长度
 * @out_msg 用户空间输出缓冲区指针
 * @return 实际读取字节数，失败返回错误码
 */
long read_process_memory(uint32_t pid, uint64_t vaddr, uint64_t size, char *__user out_msg);

#endif // __MEM_READER_H__
