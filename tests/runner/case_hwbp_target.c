#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <dirent.h>
#include <elf.h>
#include <time.h>
#include <fcntl.h>
#include "case_hwbp_target.h"
#include "dispatcher.h"

#define MAX_HIT_RECORDS 64
#define MAX_MAPS_ENTRIES 256

typedef struct {
    uint64_t baseaddress;
    uint64_t size;
    char name[256];
} driver_region_info_t;

// 获取进程的所有 Task ID
static int get_process_task(int pid, int *tasks, int max_tasks) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *dir = opendir(path);
    if (!dir) return 0;
    
    int count = 0;
    struct dirent *ptr;
    while ((ptr = readdir(dir)) && count < max_tasks) {
        if (ptr->d_type == DT_DIR) {
            int tid = atoi(ptr->d_name);
            if (tid > 0) {
                tasks[count++] = tid;
            }
        }
    }
    closedir(dir);
    return count;
}

// 获取进程的内存映射信息
static int get_process_maps(int pid, driver_region_info_t *maps, int max_maps) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    
    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp) && count < max_maps) {
        uint64_t start, end;
        char perms[5];
        char name[256] = "";
        
        if (sscanf(line, "%lx-%lx %4s %*x %*x:%*x %*d %255[^\n]", 
                   &start, &end, perms, name) >= 3) {
            maps[count].baseaddress = start;
            maps[count].size = end - start;
            strncpy(maps[count].name, name, sizeof(maps[count].name) - 1);
            maps[count].name[sizeof(maps[count].name) - 1] = '\0';
            count++;
        }
    }
    fclose(fp);
    return count;
}

// 解析地址对应的模块和偏移量
static const char* resolve_address(uint64_t pc, driver_region_info_t *maps, int map_count) {
    static char buf[512];
    for (int i = 0; i < map_count; i++) {
        if (pc >= maps[i].baseaddress && pc < maps[i].baseaddress + maps[i].size) {
            if (maps[i].name[0]) {
                snprintf(buf, sizeof(buf), "%s + 0x%lx", maps[i].name, pc - maps[i].baseaddress);
            } else {
                snprintf(buf, sizeof(buf), "%lx + 0x%lx", maps[i].baseaddress, pc - maps[i].baseaddress);
            }
            return buf;
        }
    }
    snprintf(buf, sizeof(buf), "%lx", pc);
    return buf;
}

// 打印调用栈回溯 (使用 /proc/pid/mem 读取目标进程栈)
static void print_backtrace(pid_t target_pid, uint64_t fp, uint64_t sp, uint64_t pc, uint64_t lr,
                            driver_region_info_t *maps, int map_count) {
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        printf("  [警告] 无法打开 %s\n", mem_path);
        return;
    }
    
    int frame_idx = 0;
    
    printf("  === 调用栈回溯 (Backtrace) ===\n");
    
    // Frame 0: 当前 PC
    printf("  #%-2d PC: %p (%s) FP: %p SP: %p\n", 
           frame_idx++, (void*)pc, resolve_address(pc, maps, map_count), (void*)fp, (void*)sp);
    
    // Frame 1: LR (返回地址)
    if (lr) {
        printf("  #%-2d LR: %p (%s) [来自 FP]\n", 
               frame_idx++, (void*)lr, resolve_address(lr, maps, map_count));
    }
    
    // 循环回溯栈帧
    while (frame_idx < 30) {
        if (fp == 0 || (fp & 7) != 0) break;
        
        uint64_t next_fp = 0;
        uint64_t next_lr = 0;
        
        // 使用 pread 读取目标进程的栈
        ssize_t bytes_read = pread(mem_fd, &next_fp, sizeof(next_fp), (off_t)fp);
        if (bytes_read != sizeof(next_fp)) break;
        
        // 读取上一层栈帧的返回地址 LR (X30) - 位于 fp + 8
        bytes_read = pread(mem_fd, &next_lr, sizeof(next_lr), (off_t)(fp + 8));
        if (bytes_read != sizeof(next_lr)) break;
        
        // 安全检查：上一级 FP 必须大于当前 FP（栈往低地址增长）
        if (next_fp <= fp) break;
        
        // 对齐检查
        if ((next_fp & 7) != 0) break;
        
        printf("  #%-2d LR: %p (%s) FP: %p\n", 
               frame_idx++, (void*)next_lr, resolve_address(next_lr, maps, map_count), (void*)next_fp);
        
        fp = next_fp;
    }
    printf("  === Backtrace 结束 ===\n");
    close(mem_fd);
}

// 时间戳转字符串
static const char* timestamp_to_datetime(uint64_t timestamp_ns) {
    static char buf[64];
    time_t t = timestamp_ns / 1000000000;
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        snprintf(buf, sizeof(buf), "%lu", (unsigned long)t);
    }
    return buf;
}

bool run_case_hwbp_target(int anon_fd, int scheme, const char *target_path)
{
    // 启动目标进程
    pid_t target_pid = fork();
    if (target_pid == 0) {
        execl(target_path, "target", NULL);
        perror("[-] [hwbp_target] execl 失败");
        _exit(1);
    } else if (target_pid < 0) {
        perror("[-] [hwbp_target] fork 失败");
        return false;
    }

    printf("[+] [hwbp_target] target PID: %d, 等待 1s 完成内存映射...\n", target_pid);
    fflush(stdout);
    sleep(1);

    // 获取目标进程的内存映射
    driver_region_info_t maps[MAX_MAPS_ENTRIES];
    int map_count = get_process_maps(target_pid, maps, MAX_MAPS_ENTRIES);
    printf("[*] [hwbp_target] 获取到 %d 个内存区域\n", map_count);

    // 在目标进程的固定地址注册硬件断点
    hw_breakpoint_cmd_t bcmd;
    memset(&bcmd, 0, sizeof(bcmd));
    bcmd.pid    = (uint32_t)target_pid;
    bcmd.addr   = 0x2000000000ULL; // 与 target.cpp 中 FIXED_ADDRESS 对应
    bcmd.type   = 3;               // rw
    bcmd.len    = 8;
    bcmd.scheme = scheme;

    printf("[*] [hwbp_target] 注册 HWBP (方案 %d, 地址 0x%llx)...\n",
           scheme, (unsigned long long)bcmd.addr);
    fflush(stdout);

    long ret = ioctl(anon_fd, OP_SET_HW_BREAKPOINT, &bcmd);
    printf("%s [hwbp_target] HWBP 注册返回: %ld\n", ret == 0 ? "[+]" : "[-]", ret);
    fflush(stdout);

    if (ret != 0) {
        kill(target_pid, SIGKILL);
        waitpid(target_pid, NULL, 0);
        return false;
    }

    // 轮询读取断点命中信息
    printf("[*] [hwbp_target] 开始监听断点命中事件...\n");
    fflush(stdout);
    
    hwbp_hit_item_t hits[MAX_HIT_RECORDS];
    int poll_count = 0;
    bool has_hits = false;
    
    while (poll_count < 50) {  // 最多轮询 5 秒
        hwbp_info_cmd_t icmd;
        memset(&icmd, 0, sizeof(icmd));
        icmd.pid = (uint32_t)target_pid;
        icmd.max_count = MAX_HIT_RECORDS;
        icmd.user_buf = (uint64_t)hits;
        
        ret = ioctl(anon_fd, OP_READ_HW_BP_INFO, &icmd);
        if (ret == 0 && icmd.actual_count > 0) {
            has_hits = true;
            printf("\n==========================================================================\n");
            printf("[hwbp_target] 第 %d 次轮询检测到 %lu 条命中记录:\n", poll_count + 1, icmd.actual_count);
            
            for (uint64_t i = 0; i < icmd.actual_count; i++) {
                hwbp_hit_item_t *hit = &hits[i];
                printf("--------------------------------------------------------------------------\n");
                printf("命中时间: %s\n", timestamp_to_datetime(hit->hit_time));
                printf("触发线程: %u (TaskID)\n", hit->task_id);
                printf("触发地址: %p\n", (void*)hit->hit_addr);
                printf("寄存器快照:\n");
                printf("  PC: %p, SP: %p, LR: %p, FP: %p\n", 
                       (void*)hit->regs_info.pc, 
                       (void*)hit->regs_info.sp, 
                       (void*)hit->regs_info.regs[30],  // LR = X30
                       (void*)hit->regs_info.regs[29]); // FP = X29
                
                // 打印调用栈
                print_backtrace(
                    target_pid,
                    hit->regs_info.regs[29],  // FP
                    hit->regs_info.sp,         // SP
                    hit->regs_info.pc,         // PC
                    hit->regs_info.regs[30],   // LR
                    maps, map_count
                );
            }
            printf("==========================================================================\n");
            fflush(stdout);
        }
        
        usleep(100000);  // 100ms 轮询一次
        poll_count++;
        
        // 检查目标进程是否还在运行
        if (kill(target_pid, 0) != 0) {
            printf("[*] [hwbp_target] 目标进程已终止\n");
            break;
        }
    }
    
    if (!has_hits) {
        printf("[-] [hwbp_target] 未检测到任何断点命中!\n");
    }

    kill(target_pid, SIGKILL);
    waitpid(target_pid, NULL, 0);
    printf("[*] [hwbp_target] target 进程已终止\n");
    fflush(stdout);

    return has_hits;
}
