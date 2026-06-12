#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include "case_hwbp_target.h"
#include "dispatcher.h"

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

    // 等待 target 循环触发断点，结果通过 dmesg 确认
    printf("[*] [hwbp_target] 等待 5s 观察断点触发...\n");
    fflush(stdout);
    sleep(5);

    kill(target_pid, SIGKILL);
    waitpid(target_pid, NULL, 0);
    printf("[*] [hwbp_target] target 进程已终止\n");
    fflush(stdout);

    // 注册成功即认为 case 通过，实际触发情况见 dmesg
    return true;
}
