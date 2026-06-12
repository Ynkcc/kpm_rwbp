#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include "case_hwbp_self.h"
#include "dispatcher.h"

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
