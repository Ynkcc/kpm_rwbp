#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <signal.h>

#define _KP_KPMODULE_H_
#include "io_struct.h"

// 本地定义 SuperCall 相关的系统调用号和常量，以规避可能存在错误或已弃用的 KernelPatch 头文件
// 45 号系统调用在 KernelPatch/APatch 中被用于处理 supercall（特权系统调用）
#define __NR_supercall 45

// SuperCall 命令代码
#define SUPERCALL_HELLO 0x1000          // 握手/测试连接命令
#define SUPERCALL_HELLO_MAGIC 0x11581158 // 握手成功时期望返回的 Magic 数
#define SUPERCALL_KPM_LOAD 0x1020        // 加载 KPM (KernelPatch Module) 模块命令
#define SUPERCALL_KPM_UNLOAD 0x1021      // 卸载 KPM 模块命令
#define SUPERCALL_KPM_CONTROL 0x1022     // 向已加载的 KPM 模块发送控制参数命令

// KPM 相关的配置参数
#define KPM_KEY "QWERTY1234"             // 用于鉴权的 SuperKey (与 APatch 保持一致)
#define KPM_NAME_STR "kpm_lsdriver_v4"   // 要加载/卸载的内核模块名称
#define KPM_PATH_STR "/sdcard/kpm_lsdriver.kpm" // 存储在 SD 卡上的内核模块文件路径

/**
 * 构造包含版本号和命令的 64 位整型参数
 * 匹配 KernelPatch 0.13.2 版本的调用协议
 * 
 * @param cmd 命令代码 (如 SUPERCALL_HELLO 等)
 * @return 组装后的 64 位参数
 */
static inline long ver_and_cmd(long cmd)
{
    // 构造版本号：主版本号 0，次版本号 13，修订版本号 2
    uint32_t version_code = (0 << 16) + (13 << 8) + 2;
    // 将版本号放在高 32 位，Magic (0x1158) 放在 16~31 位，命令放在低 16 位
    return ((long)version_code << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

/**
 * 检查 APatch 是否就绪且 SuperKey 是否正确
 * 
 * @param key 鉴权用的 SuperKey
 * @return 如果就绪且 key 正确，返回 true，否则返回 false
 */
static inline bool sc_ready(const char *key)
{
    if (!key || !key[0]) return false;
    long ret = syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_HELLO));
    return ret == SUPERCALL_HELLO_MAGIC;
}

/**
 * 通过 SuperCall 协议加载内核模块 (KPM)
 * 
 * @param key 鉴权用的 SuperKey
 * @param path KPM 模块在用户态的路径
 * @param args 传递给内核模块的初始化参数
 * @param reserved 保留参数，传 NULL
 * @return 系统调用返回值 (0 表示成功，负值表示失败)
 */
static inline long sc_kpm_load(const char *key, const char *path, const char *args, void *reserved)
{
    if (!key || !key[0]) return -1;
    if (!path || strlen(path) <= 0) return -1;
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_LOAD), path, args, reserved);
}

/**
 * 通过 SuperCall 协议卸载指定的内核模块 (KPM)
 * 
 * @param key 鉴权用的 SuperKey
 * @param name 要卸载的 KPM 模块名称
 * @param reserved 保留参数，传 NULL
 * @return 系统调用返回值 (0 表示成功，负值表示失败)
 */
static inline long sc_kpm_unload(const char *key, const char *name, void *reserved)
{
    if (!key || !key[0]) return -1;
    if (!name || strlen(name) <= 0) return -1;
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_UNLOAD), name, reserved);
}

/**
 * 发送控制指令给已加载的内核模块 (KPM)
 * 
 * @param key 鉴权用的 SuperKey
 * @param name 内核模块名称
 * @param ctl_args 发送给模块控制句柄的参数字符串
 * @param out_msg 用于接收内核模块返回消息的缓冲区
 * @param outlen 缓冲区长度
 * @return 系统调用返回值 (0 表示成功，负值表示失败)
 */
static inline long sc_kpm_control(const char *key, const char *name, const char *ctl_args, char *out_msg, long outlen)
{
    if (!key || !key[0]) return -1;
    if (!name || strlen(name) <= 0) return -1;
    if (!ctl_args || strlen(ctl_args) <= 0) return -1;
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_CONTROL), name, ctl_args, out_msg, outlen);
}

int main()
{
    printf("[*] Starting KPM Lsdriver Test Program...\n");

    // 创建子进程，在后台将内核日志 (dmesg -w) 实时重定向到日志文件中，便于调试和查看内核驱动的 printk 输出
    pid_t dmesg_pid = fork();
    if (dmesg_pid == 0) {
        // 子进程 logic: 捕获内核日志
        // 先删除可能存在的旧日志文件
        system("rm -f /data/local/tmp/kpm_dmesg.txt");
        // 执行 dmesg -w，并重定向到目标文件
        execlp("sh", "sh", "-c", "exec dmesg -w > /data/local/tmp/kpm_dmesg.txt", NULL);
        perror("[-] Failed to execute sh -c dmesg");
        exit(1);
    } else if (dmesg_pid < 0) {
        perror("[-] Failed to fork dmesg logging process");
    } else {
        printf("[+] Spawned dmesg logging process (PID: %d)\n", dmesg_pid);
        fflush(stdout);
        usleep(200000);
    }

// 统一的清理与退出宏定义，确保程序退出时终止后台 dmesg 捕捉进程
#define CLEANUP_AND_EXIT(code) \
    do { \
        if (dmesg_pid > 0) { \
            kill(dmesg_pid, SIGTERM); \
            waitpid(dmesg_pid, NULL, 0); \
            printf("[*] Terminated dmesg logging process\n"); \
        } \
        return (code); \
    } while(0)

    // 1. 设置当前进程的进程名称为 "LS"。
    // 这是核心步骤，因为内核模块在运行时会遍历进程列表，专门寻找名称为 "LS" 的进程，
    // 并将其在 0x2025827000 处的共享内存映射到内核空间，用于用户态和内核态的高效无锁通信。
    if (prctl(PR_SET_NAME, "LS") != 0) {
        perror("[-] Failed to set process name to LS");
        CLEANUP_AND_EXIT(1);
    }
    printf("[+] Process name successfully set to 'LS'\n");

    // 2. 检查 APatch 环境及 SuperKey 是否可用
    if (!sc_ready(KPM_KEY)) {
        printf("[-] APatch is not ready or superkey is incorrect!\n");
        CLEANUP_AND_EXIT(1);
    }
    printf("[+] APatch is ready with superkey: %s\n", KPM_KEY);

    // 3. 卸载可能已经加载的同名驱动，防止冲突
    printf("[*] STEP 1: Unloading any existing driver...\n");
    fflush(stdout);
    usleep(200000);
    long unload_init_ret = sc_kpm_unload(KPM_KEY, KPM_NAME_STR, NULL);
    printf("[+] STEP 1 Done: Unload returned %ld\n", unload_init_ret);
    fflush(stdout);
    usleep(200000);

    // 4. 在指定固定地址 0x2025827000 上进行匿名内存映射 (mmap)
    // 映射的大小为 struct req_obj 的大小。该共享内存结构体定义在 io_struct.h 中，
    // 包含了控制标志位（req->kernel，req->user）、操作码（req->op）和数据缓冲区（rw_info）。
    printf("[*] STEP 2: Mapping shared memory at 0x2025827000...\n");
    fflush(stdout);
    usleep(200000);
    void *mmap_addr = mmap((void *)0x2025827000, sizeof(struct req_obj), PROT_READ | PROT_WRITE, 
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mmap_addr == MAP_FAILED || mmap_addr != (void *)0x2025827000) {
        perror("[-] mmap failed");
        CLEANUP_AND_EXIT(1);
    }
    // 初始化共享内存，将当前进程 PID 写入，让内核识别该请求来源
    memset(mmap_addr, 0, sizeof(struct req_obj));
    struct req_obj *req = (struct req_obj *)mmap_addr;
    req->pid = getpid();
    printf("[+] STEP 2 Done: Shared memory mapped at %p, PID set to %d\n", req, req->pid);
    fflush(stdout);
    usleep(200000);

    // 5. 加载 KPM 内核模块
    printf("[*] STEP 3: Loading KPM module from %s...\n", KPM_PATH_STR);
    fflush(stdout);
    usleep(200000);
    long load_ret = sc_kpm_load(KPM_KEY, KPM_PATH_STR, "", NULL);
    if (load_ret != 0) {
        printf("[-] sc_kpm_load failed with code: %ld\n", load_ret);
        fflush(stdout);
        CLEANUP_AND_EXIT(1);
    }
    printf("[+] STEP 3 Done: KPM module loaded successfully!\n");
    fflush(stdout);
    usleep(200000);

    // 6. 发送 "start" 控制命令启动内核线程
    // 驱动模块加载后，需通过 control 接口发送 "start" 触发其初始化工作线程与内存监听逻辑
    printf("[*] STEP 4: Sending 'start' command to KPM driver...\n");
    fflush(stdout);
    usleep(200000);
    char ctl_res[64] = {0};
    long ctl_ret = sc_kpm_control(KPM_KEY, KPM_NAME_STR, "start", ctl_res, sizeof(ctl_res));
    printf("[+] STEP 4 Done: sc_kpm_control returned: %ld, result message: %s\n", ctl_ret, ctl_res);
    fflush(stdout);
    usleep(200000);

    if (ctl_ret != 0) {
        printf("[-] Failed to send start command\n");
        fflush(stdout);
        CLEANUP_AND_EXIT(1);
    }

    // 7. 等待内核驱动线程发现本进程并完成共享内存页面映射
    // 当内核驱动线程成功绑定并把用户态的物理页映射 to 内核后，会将 req->user 设为 true，从而完成握手
    printf("[*] STEP 5: Waiting for driver thread to map shared memory...\n");
    fflush(stdout);
    usleep(200000);
    int timeout = 100; // 超时时间：10秒 (100 * 100毫秒)
    while (!req->user && timeout-- > 0) {
        usleep(100000);
    }

    if (!req->user) {
        printf("[-] STEP 5 Done: Driver connection timeout. req->user is still false.\n");
        fflush(stdout);
        CLEANUP_AND_EXIT(1);
    }
    printf("[+] STEP 5 Done: Driver connected and mapped! req->user is true.\n");
    fflush(stdout);
    usleep(200000);

    // 8. 测试内存读写功能
    // 我们定义一个本地变量 test_value，通过驱动在内核态对其进行读取和改写，以验证读写通道的正确性
    int test_value = 556677;
    printf("[*] STEP 6: Performing read/write tests on local variable at %p, current value: %d\n", &test_value, test_value);
    fflush(stdout);
    usleep(200000);

    // --- 内存读取测试 (Read Test) ---
    req->pid = getpid();                              // 设置要操作的进程 PID (这里是自身)
    req->op = op_r;                                   // 操作码设为 op_r (读操作)
    req->rw_info.rw_addr = (uintptr_t)&test_value;    // 要读取的目标地址
    req->rw_info.size = sizeof(test_value);           // 读取的字节数
    printf("[*] STEP 6.1: Writing kernel=true to trigger read...\n");
    fflush(stdout);
    usleep(200000);
    req->kernel = true;                               // 通知内核线程：有新请求需要处理
    req->user = false;                                // 重置完成标志，等待内核响应

    // 轮询等待内核线程处理完毕
    timeout = 50;
    while (!req->user && timeout-- > 0) {
        usleep(10000);
    }
    if (!req->user) {
        printf("[-] STEP 6.1 Done: Read operation timed out!\n");
        fflush(stdout);
        CLEANUP_AND_EXIT(1);
    }
    // 从共享内存的数据缓冲区读取内核返回的数据
    int read_val = *(int *)(req->rw_info.user_buffer);
    printf("[+] STEP 6.1 Done: Driver read value: %d, op status: %d\n", read_val, req->status);
    fflush(stdout);
    usleep(200000);

    // --- 内存写入测试 (Write Test) ---
    int new_value = 998877;
    printf("[*] STEP 6.2: Requesting driver to write new value: %d\n", new_value);
    fflush(stdout);
    usleep(200000);
    req->pid = getpid();                              // 目标 PID
    req->op = op_w;                                   // 操作码设为 op_w (写操作)
    req->rw_info.rw_addr = (uintptr_t)&test_value;    // 要修改的目标地址
    req->rw_info.size = sizeof(test_value);           // 写入的字节数
    *(int *)(req->rw_info.user_buffer) = new_value;   // 将要写入的数据填入共享内存缓冲区
    req->kernel = true;                               // 通知内核线程处理请求
    req->user = false;                                // 等待标志重置

    // 轮询等待内核写入完成
    timeout = 50;
    while (!req->user && timeout-- > 0) {
        usleep(10000);
    }
    if (!req->user) {
        printf("[-] STEP 6.2 Done: Write operation timed out!\n");
        fflush(stdout);
        CLEANUP_AND_EXIT(1);
    }
    printf("[+] STEP 6.2 Done: Driver write status: %d\n", req->status);
    printf("[+] Local variable value after driver write: %d (expected %d)\n", test_value, new_value);
    fflush(stdout);
    usleep(200000);

    // 验证本地变量是否真的被修改为了 new_value
    if (test_value == new_value) {
        printf("[+] SUCCESS: All driver read/write test cases passed!\n");
    } else {
        printf("[-] FAILURE: Value mismatch!\n");
    }
    fflush(stdout);
    usleep(200000);

    // 9. 清理并卸载内核驱动
    // 发送 op_kexit 操作码，通知内核的工作线程安全退出并释放映射
    printf("[*] STEP 7: Stopping driver kernel threads...\n");
    fflush(stdout);
    usleep(200000);
    req->op = op_kexit;
    req->kernel = true;
    req->user = false;
    usleep(200000);

    // 调用 APatch 接口卸载 KPM 模块，释放内核空间资源
    printf("[*] STEP 8: Unloading driver KPM module...\n");
    fflush(stdout);
    usleep(200000);
    long unload_ret = sc_kpm_unload(KPM_KEY, KPM_NAME_STR, NULL);
    printf("[+] STEP 8 Done: Unload returned %ld\n", unload_ret);
    fflush(stdout);
    usleep(200000);

    CLEANUP_AND_EXIT(0);
}
