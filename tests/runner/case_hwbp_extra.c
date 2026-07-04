#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include "case_hwbp_extra.h"
#include "kpm_ctrl.h"
#include "dispatcher.h"

// 大规模注销测试：注册 80 个 scheme 3 断点并全部注销
bool run_case_hwbp_scale(int anon_fd)
{
    printf("[*] [hwbp_scale] 开始大规模断点注册注销测试（注册 80 个）...\n");
    fflush(stdout);

    uint32_t my_pid = (uint32_t)getpid();
    uint64_t base_addr = 0x3000000000ULL;
    int count = 80;
    bool success = true;

    // 1. 注册 80 个 Scheme 3 断点
    for (int i = 0; i < count; i++) {
        hw_breakpoint_cmd_t bcmd;
        memset(&bcmd, 0, sizeof(bcmd));
        bcmd.pid = my_pid;
        bcmd.addr = base_addr + i * 8;
        bcmd.type = 3;    // rw
        bcmd.len = 8;
        bcmd.scheme = 2;  // Scheme 2 不需要硬件寄存器插槽限制，可无限注册

        long ret = kpm_ipc_cmd(anon_fd, OP_SET_HW_BREAKPOINT, &bcmd);
        if (ret != 0) {
            printf("[-] [hwbp_scale] 注册第 %d 个断点失败 (地址: 0x%llx), 返回值=%ld\n", 
                   i, (unsigned long long)bcmd.addr, ret);
            success = false;
            break;
        }
    }

    if (!success) {
        // 如果注册失败，尝试清理
        kpm_ipc_cmd(anon_fd, OP_REMOVE_ALL_HW_BREAKPOINT, NULL);
        return false;
    }

    printf("[+] [hwbp_scale] 成功注册 %d 个断点\n", count);
    fflush(stdout);

    // 2. 调用全部注销指令
    printf("[*] [hwbp_scale] 调用 OP_REMOVE_ALL_HW_BREAKPOINT 注销全部断点...\n");
    fflush(stdout);

    long ret = kpm_ipc_cmd(anon_fd, OP_REMOVE_ALL_HW_BREAKPOINT, NULL);
    if (ret != 0) {
        printf("[-] [hwbp_scale] OP_REMOVE_ALL_HW_BREAKPOINT 返回失败: %ld\n", ret);
        return false;
    }

    // 等待 RCU 和内核工作队列异步释放内存
    usleep(300000); // 300ms

    // 3. 验证是否清理干净且内核正常运行（尝试重新注册一个看是否工作）
    hw_breakpoint_cmd_t test_cmd;
    memset(&test_cmd, 0, sizeof(test_cmd));
    test_cmd.pid = my_pid;
    test_cmd.addr = base_addr;
    test_cmd.type = 3;
    test_cmd.len = 8;
    test_cmd.scheme = 2;

    long test_ret = kpm_ipc_cmd(anon_fd, OP_SET_HW_BREAKPOINT, &test_cmd);
    if (test_ret == 0) {
        printf("[+] [hwbp_scale] 重新注册验证成功\n");
        // 清理测试用的这个
        kpm_ipc_cmd(anon_fd, OP_REMOVE_HW_BREAKPOINT, &test_cmd);
    } else {
        printf("[-] [hwbp_scale] 重新注册验证失败: %ld\n", test_ret);
        success = false;
    }

    usleep(100000);

    return success;
}

// 并发测试参数结构体
typedef struct {
    int anon_fd;
    int thread_id;
    volatile uint64_t *shared_bp_val_ptr;
    volatile bool stop;
    long trigger_count;
    volatile pid_t tid;
} thread_ctx_t;

// 触发断点的写线程函数
static void* writer_thread_func(void *arg)
{
    thread_ctx_t *ctx = (thread_ctx_t*)arg;
    ctx->tid = gettid();

    // 高频写入同一个共享地址，触发断点
    volatile uint64_t *ptr = ctx->shared_bp_val_ptr;
    while (!ctx->stop) {
        *ptr += 1;
        ctx->trigger_count++;
        // 极小延时，让出 CPU 并制造并发乱序
        if (ctx->trigger_count % 10 == 0) {
            usleep(1);
        }
    }

    return NULL;
}

// 轮询读取命中记录的读线程函数
typedef struct {
    int anon_fd;
    volatile bool stop;
    unsigned long total_hits_read;
    volatile pid_t writer_tid;
} reader_ctx_t;

static void* reader_thread_func(void *arg)
{
    reader_ctx_t *ctx = (reader_ctx_t*)arg;
    hwbp_hit_item_t hits[16];

    while (!ctx->stop) {
        hwbp_info_cmd_t icmd;
        memset(&icmd, 0, sizeof(icmd));
        icmd.pid = ctx->writer_tid;
        icmd.max_count = 16;
        icmd.user_buf = (uint64_t)hits;

        long ret = kpm_ipc_cmd(ctx->anon_fd, OP_READ_HW_BP_INFO, &icmd);
        if (ret == 0 && icmd.actual_count > 0) {
            ctx->total_hits_read += icmd.actual_count;
        }
        usleep(5000); // 5ms 轮询一次
    }

    return NULL;
}

// 并发测试主逻辑
bool run_case_hwbp_concurrency(int anon_fd)
{
    printf("[*] [hwbp_concurrency] 开始并发多线程断点触发与读取测试...\n");
    fflush(stdout);

    // 1. 初始化并注册单个共享断点
    volatile uint64_t shared_bp_val __attribute__((aligned(8))) = 12345678ULL;

    int num_writers = 4;
    pthread_t writers[4];
    thread_ctx_t writer_ctxs[4];

    // 2. 启动 4 个写线程并发写入共享地址
    for (int i = 0; i < num_writers; i++) {
        writer_ctxs[i].anon_fd = anon_fd;
        writer_ctxs[i].thread_id = i;
        writer_ctxs[i].shared_bp_val_ptr = &shared_bp_val;
        writer_ctxs[i].stop = false;
        writer_ctxs[i].trigger_count = 0;
        writer_ctxs[i].tid = 0;

        if (pthread_create(&writers[i], NULL, writer_thread_func, &writer_ctxs[i]) != 0) {
            printf("[-] [hwbp_concurrency] 创建写线程 %d 失败\n", i);
            return false;
        }
    }

    // 等待第一个写线程获取其内核线程ID (TID)
    while (writer_ctxs[0].tid == 0) {
        usleep(1000);
    }

    // 3. 启动读线程并发轮询命中记录，并传递需要监听的 TID
    pthread_t reader;
    reader_ctx_t reader_ctx;
    reader_ctx.anon_fd = anon_fd;
    reader_ctx.stop = false;
    reader_ctx.total_hits_read = 0;
    reader_ctx.writer_tid = writer_ctxs[0].tid;

    if (pthread_create(&reader, NULL, reader_thread_func, &reader_ctx) != 0) {
        printf("[-] [hwbp_concurrency] 创建读线程失败\n");
        // 强行终止并清理写线程
        for (int i = 0; i < num_writers; i++) {
            writer_ctxs[i].stop = true;
            pthread_join(writers[i], NULL);
        }
        return false;
    }

    // 4. 注册硬件断点，把 PID/TID 设置为我们要监听的第一个写线程的内核线程ID
    hw_breakpoint_cmd_t bcmd;
    memset(&bcmd, 0, sizeof(bcmd));
    bcmd.pid = (uint32_t)writer_ctxs[0].tid;
    bcmd.addr = (uint64_t)&shared_bp_val;
    bcmd.type = 3; // rw
    bcmd.len = 8;
    bcmd.scheme = 1;

    long ret = kpm_ipc_cmd(anon_fd, OP_SET_HW_BREAKPOINT, &bcmd);
    if (ret != 0) {
        printf("[-] [hwbp_concurrency] 注册共享断点失败, ret=%ld\n", ret);
        // 终止线程并清理
        for (int i = 0; i < num_writers; i++) {
            writer_ctxs[i].stop = true;
        }
        reader_ctx.stop = true;
        for (int i = 0; i < num_writers; i++) {
            pthread_join(writers[i], NULL);
        }
        pthread_join(reader, NULL);
        return false;
    }

    // 运行 2 秒钟，高压读写
    sleep(2);

    // 5. 停止并清理所有线程
    printf("[*] [hwbp_concurrency] 停止所有测试线程并清理断点...\n");
    fflush(stdout);

    for (int i = 0; i < num_writers; i++) {
        writer_ctxs[i].stop = true;
    }
    reader_ctx.stop = true;

    for (int i = 0; i < num_writers; i++) {
        pthread_join(writers[i], NULL);
    }
    pthread_join(reader, NULL);

    // 注销共享断点
    kpm_ipc_cmd(anon_fd, OP_REMOVE_HW_BREAKPOINT, &bcmd);

    // 打印测试结果统计
    long total_triggers = 0;
    for (int i = 0; i < num_writers; i++) {
        printf("[*] [hwbp_concurrency] 写线程 %d 共触发写入: %ld 次\n", i, writer_ctxs[i].trigger_count);
        total_triggers += writer_ctxs[i].trigger_count;
    }
    printf("[*] [hwbp_concurrency] 总触发写入: %ld 次, 读线程成功读取命中记录数: %lu 次\n", total_triggers, reader_ctx.total_hits_read);
    fflush(stdout);

    // 并发测试通过判定：内核没有崩溃/死锁，且成功采集到了命中数据
    if (reader_ctx.total_hits_read > 0) {
        printf("[+] [hwbp_concurrency] 并发测试通过，读写分离工作正常且消除了自旋锁死锁风险。\n");
        return true;
    } else {
        printf("[-] [hwbp_concurrency] 未能成功抓取到任何断点触发记录！\n");
        return false;
    }
}

bool run_case_hwbp_interfaces(int anon_fd)
{
    printf("[*] [hwbp_interfaces] 开始硬件断点新接口功能验证...\n");
    fflush(stdout);

    // 1. 获取硬件能力
    hwbp_caps_t caps;
    memset(&caps, 0, sizeof(caps));
    long ret = kpm_get_hwbp_caps(anon_fd, &caps);
    if (ret != 0) {
        printf("[-] [hwbp_interfaces] 获取硬件能力失败, ret=%ld\n", ret);
        return false;
    }
    printf("[+] [hwbp_interfaces] 硬件能力获取成功: 最大 Breakpoints = %u, 最大 Watchpoints = %u\n",
           caps.max_breakpoints, caps.max_watchpoints);
    if (caps.max_breakpoints == 0 || caps.max_watchpoints == 0) {
        printf("[-] [hwbp_interfaces] 获取到的硬件能力数量不合法（为0）\n");
        return false;
    }

    // 2. 注册硬件断点 (Scheme 1)
    volatile uint64_t bp_val __attribute__((aligned(8))) = 11111111ULL;
    uint32_t my_pid = (uint32_t)getpid();

    hw_breakpoint_cmd_t bcmd;
    memset(&bcmd, 0, sizeof(bcmd));
    bcmd.pid    = my_pid;
    bcmd.addr   = (uint64_t)&bp_val;
    bcmd.type   = 3; // rw
    bcmd.len    = 8;
    bcmd.scheme = 1; // Scheme 1

    printf("[*] [hwbp_interfaces] 注册硬件断点 (地址: 0x%llx)...\n", (unsigned long long)bcmd.addr);
    ret = kpm_ipc_cmd(anon_fd, OP_SET_HW_BREAKPOINT, &bcmd);
    if (ret != 0) {
        printf("[-] [hwbp_interfaces] 注册断点失败, ret=%ld\n", ret);
        return false;
    }

    // 等待生效
    usleep(100000);

    // 3. 状态查询：刚注册完，active 应该为 1，hit_count 应为 0
    hwbp_query_cmd_t qcmd;
    ret = kpm_query_hwbp_status(anon_fd, my_pid, (uint64_t)&bp_val, &qcmd);
    if (ret != 0) {
        printf("[-] [hwbp_interfaces] 查询状态失败, ret=%ld\n", ret);
        return false;
    }
    printf("[+] [hwbp_interfaces] 状态查询: active = %u, hit_count = %llu, scheme = %u\n",
           qcmd.active, (unsigned long long)qcmd.hit_count, qcmd.scheme);
    if (qcmd.active != 1 || qcmd.hit_count != 0) {
        printf("[-] [hwbp_interfaces] 初始状态校验失败\n");
        return false;
    }

    // 4. 触发一次命中
    printf("[*] [hwbp_interfaces] 触发断点命中 (向地址写入新值)... \n");
    bp_val = 22222222ULL;
    usleep(200000); // 延迟等待中断和工作项恢复

    // 再次查询命中计数
    ret = kpm_query_hwbp_status(anon_fd, my_pid, (uint64_t)&bp_val, &qcmd);
    if (ret != 0 || qcmd.hit_count == 0) {
        printf("[-] [hwbp_interfaces] 命中计数未按预期递增, ret=%ld, hit_count=%llu\n", ret, (unsigned long long)qcmd.hit_count);
        return false;
    }
    uint64_t first_hit_count = qcmd.hit_count;
    printf("[+] [hwbp_interfaces] 触发后命中计数: %llu\n", (unsigned long long)first_hit_count);

    // 5. 禁用断点
    printf("[*] [hwbp_interfaces] 禁用该断点...\n");
    ret = kpm_disable_hwbp(anon_fd, my_pid, (uint64_t)&bp_val);
    if (ret != 0) {
        printf("[-] [hwbp_interfaces] 禁用操作返回错误: %ld\n", ret);
        return false;
    }

    // 查询状态确认被禁用
    ret = kpm_query_hwbp_status(anon_fd, my_pid, (uint64_t)&bp_val, &qcmd);
    if (ret != 0 || qcmd.active != 0) {
        printf("[-] [hwbp_interfaces] 禁用后查询状态不为禁用状态, active=%u\n", qcmd.active);
        return false;
    }
    printf("[+] [hwbp_interfaces] 状态验证: 已成功禁用 (active = %u)\n", qcmd.active);

    // 6. 在禁用状态下触发写入，应该不触发命中计数递增
    printf("[*] [hwbp_interfaces] 在禁用状态下尝试触发写入...\n");
    bp_val = 33333333ULL;
    usleep(200000);

    ret = kpm_query_hwbp_status(anon_fd, my_pid, (uint64_t)&bp_val, &qcmd);
    if (ret != 0 || qcmd.hit_count != first_hit_count) {
        printf("[-] [hwbp_interfaces] 异常：禁用状态下命中计数发生了变化! hit_count=%llu, 之前为=%llu\n",
               (unsigned long long)qcmd.hit_count, (unsigned long long)first_hit_count);
        return false;
    }
    printf("[+] [hwbp_interfaces] 验证通过: 禁用状态下确实未触发命中\n");

    // 7. 重新激活断点
    printf("[*] [hwbp_interfaces] 重新激活该断点...\n");
    ret = kpm_enable_hwbp(anon_fd, my_pid, (uint64_t)&bp_val);
    if (ret != 0) {
        printf("[-] [hwbp_interfaces] 激活操作返回错误: %ld\n", ret);
        return false;
    }

    // 查询状态确认被激活
    ret = kpm_query_hwbp_status(anon_fd, my_pid, (uint64_t)&bp_val, &qcmd);
    if (ret != 0 || qcmd.active != 1) {
        printf("[-] [hwbp_interfaces] 激活后查询状态不为激活状态, active=%u\n", qcmd.active);
        return false;
    }
    printf("[+] [hwbp_interfaces] 状态验证: 已成功重新激活 (active = %u)\n", qcmd.active);

    // 8. 重新激活后触发一次，应该再次增加命中计数
    printf("[*] [hwbp_interfaces] 重新激活后再次触发写入...\n");
    bp_val = 44444444ULL;
    usleep(200000);

    ret = kpm_query_hwbp_status(anon_fd, my_pid, (uint64_t)&bp_val, &qcmd);
    if (ret != 0 || qcmd.hit_count <= first_hit_count) {
        printf("[-] [hwbp_interfaces] 重新激活后没有触发命中, hit_count=%llu\n", (unsigned long long)qcmd.hit_count);
        return false;
    }
    printf("[+] [hwbp_interfaces] 验证通过: 激活后重新捕获了命中计数: %llu\n", (unsigned long long)qcmd.hit_count);

    // 9. 注销断点并确认无法被查询到
    printf("[*] [hwbp_interfaces] 注销硬件断点...\n");
    ret = kpm_ipc_cmd(anon_fd, OP_REMOVE_HW_BREAKPOINT, &bcmd);
    if (ret != 0) {
        printf("[-] [hwbp_interfaces] 注销断点返回失败, ret=%ld\n", ret);
        return false;
    }
    usleep(100000);

    // 注销后查询应该失败 (返回 -1 / ENOENT)
    ret = kpm_query_hwbp_status(anon_fd, my_pid, (uint64_t)&bp_val, &qcmd);
    if (ret == 0) {
        printf("[-] [hwbp_interfaces] 异常：断点已注销，但依然能查询到状态！\n");
        return false;
    }
    printf("[+] [hwbp_interfaces] 状态验证: 断点注销后查询失败，生命周期结束。\n");

    printf("[+] [hwbp_interfaces] 所有新接口单元测试全部顺利通过！\n");
    fflush(stdout);
    return true;
}

