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
#include <sys/mman.h>
#include <dirent.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include "case_hwbp_self.h"
#include "dispatcher.h"

#define MAX_HIT_RECORDS 64
#define MAX_MAPS_ENTRIES 256
#define FIXED_ADDRESS 0x2000000000ULL
#define XOR_KEY 0x55AA55AAFF00FF00ULL

typedef struct {
    uint64_t baseaddress;
    uint64_t size;
    char name[256];
} driver_region_info_t;

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
    uint64_t stripped_pc = pc & 0x0000ffffffffffffULL;
    bool found = false;
    
    for (int i = 0; i < map_count; i++) {
        if (stripped_pc >= maps[i].baseaddress && stripped_pc < maps[i].baseaddress + maps[i].size) {
            found = true;
            break;
        }
    }
    if (!found) {
        stripped_pc = pc & 0x0000007fffffffffULL;
    }
    
    for (int i = 0; i < map_count; i++) {
        if (stripped_pc >= maps[i].baseaddress && stripped_pc < maps[i].baseaddress + maps[i].size) {
            uint64_t image_base = maps[i].baseaddress;
            if (maps[i].name[0]) {
                // 寻找同名段的最小映射基地址作为该模块的 Image Base
                for (int k = 0; k < map_count; k++) {
                    if (strcmp(maps[k].name, maps[i].name) == 0) {
                        if (maps[k].baseaddress < image_base) {
                            image_base = maps[k].baseaddress;
                        }
                    }
                }
            }
            uint64_t file_offset = stripped_pc - image_base;
            if (maps[i].name[0]) {
                snprintf(buf, sizeof(buf), "%s + 0x%lx", maps[i].name, file_offset);
            } else {
                snprintf(buf, sizeof(buf), "%lx + 0x%lx", maps[i].baseaddress, file_offset);
            }
            return buf;
        }
    }
    snprintf(buf, sizeof(buf), "%lx", pc);
    return buf;
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
        uint64_t stripped_lr = lr & 0x0000ffffffffffffULL;
        bool lr_found = false;
        for (int k = 0; k < map_count; k++) {
            if (stripped_lr >= maps[k].baseaddress && stripped_lr < maps[k].baseaddress + maps[k].size) {
                lr_found = true;
                break;
            }
        }
        if (!lr_found) {
            stripped_lr = lr & 0x0000007fffffffffULL;
        }
        printf("  #%-2d LR: %p (%s) [来自 FP]\n", 
               frame_idx++, (void*)stripped_lr, resolve_address(stripped_lr, maps, map_count));
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
        
        uint64_t stripped_next_lr = next_lr & 0x0000ffffffffffffULL;
        bool lr_found = false;
        for (int k = 0; k < map_count; k++) {
            if (stripped_next_lr >= maps[k].baseaddress && stripped_next_lr < maps[k].baseaddress + maps[k].size) {
                lr_found = true;
                break;
            }
        }
        if (!lr_found) {
            stripped_next_lr = next_lr & 0x0000007fffffffffULL;
        }
        
        // 安全检查：上一级 FP 必须大于当前 FP（栈往低地址增长）
        if (next_fp <= fp) break;
        
        // 对齐检查
        if ((next_fp & 7) != 0) break;
        
        printf("  #%-2d LR: %p (%s) FP: %p\n", 
               frame_idx++, (void*)stripped_next_lr, resolve_address(stripped_next_lr, maps, map_count), (void*)next_fp);
        
        fp = next_fp;
    }
    printf("  === Backtrace 结束 ===\n");
    close(mem_fd);
}

// 目标进程自循环代码，模拟原先 target.cpp 的逻辑
void __attribute__((noinline)) target_loop_func(void) {
    size_t page_size = 4096;
    void* mapped_mem = mmap((void*)FIXED_ADDRESS, page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (mapped_mem == MAP_FAILED) {
        perror("mmap 失败");
        _exit(1);
    }

    volatile int var1 = 100;
    volatile int var2 = 200;
    volatile int var3 = 300;

    volatile uintptr_t* encrypted_array = (volatile uintptr_t*)mapped_mem;

    encrypted_array[0] = (uintptr_t)&var1 ^ XOR_KEY;
    encrypted_array[1] = (uintptr_t)&var2 ^ XOR_KEY;
    encrypted_array[2] = (uintptr_t)&var3 ^ XOR_KEY;

    while (true) {
        usleep(200000); // 200ms

        uintptr_t enc1 = encrypted_array[0];
        uintptr_t enc2 = encrypted_array[1];
        uintptr_t enc3 = encrypted_array[2];

        volatile int* p1 = (volatile int*)(enc1 ^ XOR_KEY);
        volatile int* p2 = (volatile int*)(enc2 ^ XOR_KEY);
        volatile int* p3 = (volatile int*)(enc3 ^ XOR_KEY);

        *p1 += 1;
        *p2 += 10;
        *p3 += 100;
    }

    munmap(mapped_mem, page_size);
    _exit(0);
}

// 自动校验命中记录的合法性 (基于函数指针范围)
static bool validate_hit_record(hwbp_hit_item_t *hit) {
    if (hit->hit_addr != FIXED_ADDRESS) {
        printf("  [自动判定失败] 触发地址错误: %p (期望: 0x%llx)\n", (void*)hit->hit_addr, (unsigned long long)FIXED_ADDRESS);
        return false;
    }

    if (hit->regs_info.pc == hit->regs_info.sp) {
        printf("  [自动判定失败] 寄存器快照错乱: PC 和 SP 的值相同 (%p)\n", (void*)hit->regs_info.pc);
        return false;
    }

    // 校验 PC 是否在 target_loop_func 函数指针范围 (假定编译后长度不超过 1024 字节)
    uint64_t pc = hit->regs_info.pc & 0x0000ffffffffffffULL;
    uint64_t start_addr = ((uint64_t)target_loop_func) & 0x0000ffffffffffffULL;
    uint64_t end_addr = start_addr + 1024;

    if (pc < start_addr || pc >= end_addr) {
        printf("  [自动判定失败] 触发的 PC %p 不在 target_loop_func 代码区 [%p, %p)\n", 
               (void*)hit->regs_info.pc, (void*)start_addr, (void*)end_addr);
        return false;
    }

    printf("  [自动判定成功] 该条命中记录校验通过 (PC: %p, 地址: 0x%llx)\n", (void*)hit->regs_info.pc, (unsigned long long)FIXED_ADDRESS);
    return true;
}

bool run_case_hwbp_target(int anon_fd, int scheme)
{
    // 启动目标进程
    pid_t target_pid = fork();
    if (target_pid == 0) {
        target_loop_func();
        _exit(0);
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
    bcmd.addr   = FIXED_ADDRESS;
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
    bool test_passed = true;
    
    while (poll_count < 50) {  // 最多轮询 5 秒
        hwbp_info_cmd_t icmd;
        memset(&icmd, 0, sizeof(icmd));
        icmd.pid = (uint32_t)target_pid;
        icmd.max_count = MAX_HIT_RECORDS;
        icmd.user_buf = (uint64_t)hits;
        
        ret = ioctl(anon_fd, OP_READ_HW_BP_INFO, &icmd);
        if (ret != 0) {
            printf("[-] [hwbp_target] OP_READ_HW_BP_INFO ioctl 失败, ret=%ld, errno=%d\n", ret, errno);
            fflush(stdout);
        }
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
                
                // 自动判定命中记录是否合法
                if (!validate_hit_record(hit)) {
                    test_passed = false;
                }
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
        test_passed = false;
    }

    kill(target_pid, SIGKILL);
    waitpid(target_pid, NULL, 0);
    printf("[*] [hwbp_target] target 进程已终止\n");
    fflush(stdout);

    return has_hits && test_passed;
}

// 运行单一方案的子进程测试，成功返回 true
static bool _run_scheme(int anon_fd, int scheme, int timeout_ms)
{
    pid_t pid = fork();
    if (pid == 0) {
        volatile uint64_t bp_val __attribute__((aligned(8))) = 88888888ULL;

        hw_breakpoint_cmd_t bcmd;
        bcmd.pid    = (uint32_t)getpid();
        bcmd.addr   = (uint64_t)&bp_val;
        bcmd.type   = 3; // rw
        bcmd.len    = 8;
        bcmd.scheme = scheme;

        long ret = ioctl(anon_fd, OP_SET_HW_BREAKPOINT, &bcmd);
        if (ret != 0) {
            printf("[-] [hwbp_self] 方案 %d: 断点注册失败, ret=%ld\n", scheme, ret);
            _exit(1);
        }

        // 等待注册生效
        usleep(200000);

        printf("[*] [hwbp_self] 方案 %d: 触发写入...\n", scheme);
        fflush(stdout);

        volatile uint64_t *ptr = &bp_val;
        *ptr = 99999999ULL;

        printf("[+] [hwbp_self] 方案 %d: 写入完成, 新值=%llu\n",
               scheme, (unsigned long long)(*ptr));
        fflush(stdout);

        ioctl(anon_fd, OP_REMOVE_HW_BREAKPOINT, &bcmd);
        _exit(0);
    }

    // 父进程轮询子进程，最多等待 timeout_ms
    int status;
    int check_interval_ms = 100;
    int loops = timeout_ms / check_interval_ms;

    for (int i = 0; i < loops; i++) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid)
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        usleep(check_interval_ms * 1000);
    }

    printf("[-] [hwbp_self] 方案 %d: 超时 (%d ms)\n", scheme, timeout_ms);
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return false;
}

int run_case_hwbp_self(int anon_fd, int scheme, hwbp_scheme_result_t *results, int timeout_ms)
{
    int start = (scheme == 0) ? 1 : scheme;
    int end   = (scheme == 0) ? 4 : scheme;
    int pass_count = 0;
    int idx = 0;

    for (int s = start; s <= end; s++, idx++) {
        printf("\n[*] ---------------------------------------------------\n");
        printf("[*] [hwbp_self] 测试方案 %d...\n", s);
        fflush(stdout);

        bool ok = _run_scheme(anon_fd, s, timeout_ms);

        printf("%s [hwbp_self] 方案 %d: %s\n",
               ok ? "[+]" : "[-]", s, ok ? "通过" : "失败");
        fflush(stdout);

        results[idx].scheme = s;
        results[idx].passed = ok;
        if (ok) pass_count++;
    }

    return pass_count;
}
