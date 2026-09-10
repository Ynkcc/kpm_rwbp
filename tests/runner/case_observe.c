#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include "case_observe.h"
#include "dispatcher.h"

#ifndef PERF_TYPE_BREAKPOINT
#define PERF_TYPE_BREAKPOINT 5
#endif

#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif

#ifndef NT_ARM_HW_WATCH
#define NT_ARM_HW_WATCH 0x403
#endif

#ifndef PTRACE_SETREGSET
#define PTRACE_SETREGSET 0x4205
#endif

// user_hwdebug_state / user_hwdebug_bp 由 sysroot 的 asm/ptrace.h 提供

struct perf_event_attr_uapi {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events;
    uint32_t bp_type;
    uint64_t bp_addr;
    uint64_t bp_len;
    uint64_t __reserved[6];
};

static void observe_marker_func(void)
{
    volatile int x = 1;
    (void)x;
}

static int perf_open_bp(uint64_t bp_addr, uint32_t bp_type)
{
    struct perf_event_attr_uapi attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_addr = bp_addr;
    attr.bp_type = bp_type;
    attr.bp_len = sizeof(long);
    attr.sample_period = 1;
    return (int)syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
}

// 按内核约定，pid 记为 bp_addr 归属进程；此处用 /proc/<pid>/maps 补全 path/path_offset
static void fill_paths_from_maps(uint32_t pid, observe_record_t *records, int count)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%u/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) {
        printf("[-] [observe] 打开 %s 失败 errno=%d\n", maps_path, errno);
        return;
    }

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end;
        char path[256];
        path[0] = '\0';
        // 格式: start-end perms offset dev inode pathname
        if (sscanf(line, "%lx-%lx %*4s %*x %*x:%*x %*lu %255[^\n]",
                   &start, &end, path) < 3)
            continue;
        // 去掉 pathname 前导空白
        char *p = path;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') continue;

        for (int i = 0; i < count; i++) {
            observe_record_t *r = &records[i];
            if (r->path_len != 0 || r->bp_addr < start || r->bp_addr >= end)
                continue;
            r->path_offset = r->bp_addr - start;
            size_t plen = strlen(p);
            if (plen > 64) plen = 64;
            memcpy(r->path, p, plen);
            r->path_len = (uint32_t)plen;
        }
    }
    fclose(f);
}

// 拉取观测记录，返回实际条数；<0 表示内核侧未实现/命令失败
static int fetch_observe_records(int anon_fd, uint32_t pid,
                                 observe_record_t *records, uint32_t max_count)
{
    memset(records, 0, sizeof(observe_record_t) * max_count);
    observe_info_cmd_t cmd;
    cmd.pid = pid;
    cmd._pad = 0;
    cmd.max_count = max_count;
    cmd.user_buf = (uint64_t)records;
    cmd.actual_count = 0;

    long ret = kpm_ipc_cmd(anon_fd, OP_READ_OBSERVE_RECORDS, &cmd);
    if (ret < 0) {
        printf("[-] [observe] OP_READ_OBSERVE_RECORDS 失败, ret=%ld errno=%d"
               " (内核侧 observe hook 未实现?)\n", ret, errno);
        return -1;
    }
    return (int)cmd.actual_count;
}

// case: observe-perf
bool run_case_observe_perf(int anon_fd)
{
    bool all_pass = true;
    uint32_t self_pid = (uint32_t)getpid();

    // --- 子测试 1: 数据断点(RW) 下在本进程自有地址 ---
    volatile int watch_var = 0;
    int fd = perf_open_bp((uint64_t)&watch_var, 0x3 /*HW_BREAKPOINT_RW*/);
    printf("[*] [observe_perf] perf_event_open(bp_addr=%p) -> fd=%d\n",
           (void *)&watch_var, fd);
    if (fd < 0) {
        printf("[-] [observe_perf] perf_event_open 自身失败 errno=%d\n", errno);
        all_pass = false;
    } else {
        close(fd);
    }
    fflush(stdout);

    observe_record_t records[8];
    int n = fetch_observe_records(anon_fd, self_pid, records, 8);
    if (n < 0) {
        return false;
    }
    bool pass = false;
    for (int i = 0; i < n; i++) {
        if (records[i].event_type == OBSERVE_EVENT_PERF &&
            records[i].bp_addr == (uint64_t)&watch_var) {
            pass = true;
            printf("[+] [observe_perf] 记录 #%d: bp_addr=%#lx bp_type=%lu bp_len=%lu"
                   " caller_pc=%#lx lr=%#lx\n",
                   i, (unsigned long)records[i].bp_addr,
                   (unsigned long)records[i].bp_type,
                   (unsigned long)records[i].bp_len,
                   (unsigned long)records[i].caller_pc,
                   (unsigned long)records[i].caller_lr);
            break;
        }
    }
    if (!pass) {
        printf("[-] [observe_perf] 未找到 bp_addr=%p 的 PERF 记录 (共 %d 条)\n",
               (void *)&watch_var, n);
    }
    all_pass &= pass;

    // --- 子测试 2: 执行断点(X) 下在自有函数 ---
    fd = perf_open_bp((uint64_t)&observe_marker_func, 0x1 /*HW_BREAKPOINT_X*/);
    printf("[*] [observe_perf] perf_event_open(bp_addr=%p, X) -> fd=%d\n",
           (void *)&observe_marker_func, fd);
    if (fd >= 0) close(fd);
    fflush(stdout);

    n = fetch_observe_records(anon_fd, self_pid, records, 8);
    if (n < 0) return false;
    pass = false;
    for (int i = 0; i < n; i++) {
        if (records[i].event_type == OBSERVE_EVENT_PERF &&
            records[i].bp_addr == (uint64_t)&observe_marker_func) {
            pass = true;
            break;
        }
    }
    printf("%s [observe_perf] 执行断点记录: bp_addr=%p %s\n",
           pass ? "[+]" : "[-]", (void *)&observe_marker_func,
           pass ? "已捕获" : "未捕获");
    if (!pass) all_pass = false;

    fflush(stdout);
    return all_pass;
}

// case: observe-ptrace
bool run_case_observe_ptrace(int anon_fd)
{
    uint64_t watch_addr = (uint64_t)&observe_marker_func;

    pid_t child = fork();
    if (child < 0) {
        printf("[-] [observe_ptrace] fork 失败 errno=%d\n", errno);
        return false;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
            _exit(127);
        raise(SIGSTOP);
        _exit(0);
    }

    int status;
    bool all_pass = true;
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
        printf("[-] [observe_ptrace] 子进程未按预期停止\n");
        kill(child, SIGKILL);
        waitpid(child, &status, 0);
        return false;
    }

    struct user_hwdebug_state bp_state;
    memset(&bp_state, 0, sizeof(bp_state));
    bp_state.dbg_regs[0].addr = watch_addr;
    // bit0=1 使能, bits5-12 BAS=0xF（执行断点合法长度）; 其余保留位清零
    bp_state.dbg_regs[0].ctrl = 0x1 | (0xFu << 5);

    // 内核按 iov_len 推算写入槽位数，多写会导致逐槽注册断点直至 -ENOSPC；
    // 真实调试器（GDB）按可用槽位回写，这里只写 1 个槽位: hdr(8) + addr(8)+ctrl(4)+pad(4)
    struct iovec iov = { .iov_base = &bp_state, .iov_len = 8 + 16 };
    long ret = ptrace(PTRACE_SETREGSET, child, (void *)NT_ARM_HW_BREAK, &iov);
    printf("[*] [observe_ptrace] PTRACE_SETREGSET(NT_ARM_HW_BREAK, addr=%#lx) -> %ld\n",
           (unsigned long)watch_addr, ret);
    if (ret < 0) {
        printf("[-] [observe_ptrace] SETREGSET 失败 errno=%d\n", errno);
        all_pass = false;
    }
    fflush(stdout);

    observe_record_t records[8];
    int n = fetch_observe_records(anon_fd, (uint32_t)child, records, 8);
    if (n < 0) {
        ptrace(PTRACE_KILL, child, NULL, NULL);
        waitpid(child, &status, 0);
        return false;
    }
    bool pass = false;
    for (int i = 0; i < n; i++) {
        if (records[i].event_type == OBSERVE_EVENT_PTRACE &&
            records[i].bp_addr == watch_addr) {
            pass = true;
            printf("[+] [observe_ptrace] 记录 #%d: tid=%u bp_addr=%#lx\n",
                   i, records[i].tid, (unsigned long)records[i].bp_addr);
            break;
        }
    }
    if (!pass) {
        printf("[-] [observe_ptrace] 未找到 addr=%#lx 的 PTRACE 记录 (共 %d 条)\n",
               (unsigned long)watch_addr, n);
        all_pass = false;
    }

    ptrace(PTRACE_KILL, child, NULL, NULL);
    waitpid(child, &status, 0);
    fflush(stdout);
    return all_pass;
}

// case: observe-resolve
bool run_case_observe_resolve(int anon_fd)
{
    uint32_t self_pid = (uint32_t)getpid();

    int fd = perf_open_bp((uint64_t)&observe_marker_func, 0x1);
    if (fd >= 0) close(fd);
    printf("[*] [observe_resolve] 已下执行断点 bp_addr=%p\n",
           (void *)&observe_marker_func);
    fflush(stdout);

    observe_record_t records[8];
    int n = fetch_observe_records(anon_fd, self_pid, records, 8);
    if (n < 0) return false;
    fill_paths_from_maps(self_pid, records, n);

    bool all_pass = false;
    for (int i = 0; i < n; i++) {
        observe_record_t *r = &records[i];
        if (r->event_type != OBSERVE_EVENT_PERF ||
            r->bp_addr != (uint64_t)&observe_marker_func)
            continue;

        if (r->path_len == 0) {
            printf("[-] [observe_resolve] 记录 #%d path 为空（d_path 未解析）\n", i);
            break;
        }
        char path_buf[65];
        memcpy(path_buf, r->path, r->path_len < 64 ? r->path_len : 64);
        path_buf[r->path_len < 64 ? r->path_len : 64] = '\0';

        // vma 起始 = bp_addr - path_offset，应页对齐；且 path 应指向 runner 自身
        uint64_t vma_start = r->bp_addr - r->path_offset;
        bool page_aligned = (vma_start & 0xFFFULL) == 0;
        bool self_named = strstr(path_buf, "test_rwbp") != NULL;
        printf("[%s] [observe_resolve] 记录 #%d: path=\"%s\" offset=%#lx vma_start=%#lx(%s)\n",
               (page_aligned && self_named) ? "+" : "-",
               i, path_buf, (unsigned long)r->path_offset,
               (unsigned long)vma_start,
               page_aligned ? "页对齐" : "未对齐");
        if (page_aligned && self_named)
            all_pass = true;
        break;
    }
    if (!all_pass && n == 0) {
        printf("[-] [observe_resolve] 无任何记录可校验\n");
    }
    fflush(stdout);
    return all_pass;
}
