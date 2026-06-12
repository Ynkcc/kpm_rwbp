#include "kernel_compat.h"
#include "mem_reader.h"
#include "dispatcher.h"
#include "hwbp.h"
#include <compiler.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/list.h>
#include <syscall.h>
#include <linux/cred.h>
#include <linux/err.h>

struct file;
struct cred;
struct kiocb;
struct iov_iter;
struct io_comp_batch;
struct dir_context;
struct poll_table_struct;
struct vm_area_struct;
struct inode;
struct seq_file;
struct file_lock;
struct pipe_inode_info;
struct io_uring_cmd;



#define syscall_set_retval(args, val) ((args)->ret = (val))
#define syscall_set_handled(args, handled) ((args)->skip_origin = (handled))

// 模块元信息声明
KPM_NAME("kpm_RWBP");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ynk");
KPM_DESCRIPTION("Kernel Memory Reader & HWBP KPM (Refactored)");

// 共享内存通道用户态虚拟地址
static unsigned long shm_user_vaddr = 0;

// 自动清理共享内存通道
static void cleanup_shm_channel(void) {
    shm_user_vaddr = 0;
}

// 控制端进程指针
static void *current_control_task = NULL;

// 自动清理内核资源
void handle_cleanup(void) {
    pr_info("[kpm_RWBP] 控制端进程已退出，开始自动清理内核资源...\n");
    unregister_all_hwbp();
    cleanup_shm_channel();
}

// 引导与敲门事件系统调用 Hook 拦截器
static void rwbp_fstatfs_hook(hook_fargs2_t *args, void *udata) {
    uint64_t arg0 = syscall_argn(args, 0);
    uint64_t arg1 = syscall_argn(args, 1);

    // 1. 判断是否匹配控制 Magic
    if (arg1 != 0xDEADC0DEULL) {
        return;
    }

    // 2. 校验特权用户
    struct cred *cred = *(struct cred **)((uintptr_t)current + task_struct_offset.cred_offset);
    uid_t caller_uid = *(uid_t *)((uintptr_t)cred + cred_offset.uid_offset);
    if (caller_uid != 0) {
        return;
    }

    // 3. 通信分支逻辑：握手绑定阶段 vs 事件执行阶段
    if (shm_user_vaddr == 0) {
        pr_info("[kpm_RWBP] 收到共享内存通道握手请求，用户虚拟地址: 0x%llx\n", (unsigned long long)arg0);
        uint32_t magic_val = 0;
        
        // 尝试从用户空间虚拟地址读取 magic，以校验合法性
        long err = compat_copy_from_user(&magic_val, (void __user *)arg0, sizeof(uint32_t));
        if (err == 0 && magic_val == SHM_MAGIC) {
            shm_user_vaddr = (unsigned long)arg0;
            current_control_task = get_current(); // 记录控制进程
            syscall_set_retval(args, 0);          // 返回 0 告知握手成功
            syscall_set_handled(args, true);
            pr_info("[kpm_RWBP] 成功绑定共享内存通道，虚拟地址: 0x%lx\n", shm_user_vaddr);
        } else {
            pr_warn("[kpm_RWBP] 共享内存 Magic 校验失败！magic=0x%x, err=%ld\n", magic_val, err);
            syscall_set_retval(args, -EINVAL);
            syscall_set_handled(args, true);
        }
    } else {

        // 使用局部栈缓冲区做指令交互
        shm_channel_t local_shm;
        long err = compat_copy_from_user(&local_shm, (void __user *)shm_user_vaddr, sizeof(shm_channel_t));
        if (err == 0) {
            if (local_shm.status == 1) {
                local_shm.status = 2; // 处理中
                long ret = rwbp_dispatch(&local_shm);
                local_shm.retval = (int32_t)ret;
                local_shm.status = 0; // 处理完成
                // 写回用户态
                compat_copy_to_user((void __user *)shm_user_vaddr, &local_shm, sizeof(shm_channel_t));
            }
        } else {
            pr_warn("[kpm_RWBP] 读取用户态共享内存失败: err=%ld\n", err);
        }

        syscall_set_retval(args, 0);
        syscall_set_handled(args, true);
    }
}

// 进程退出系统调用 Hook 拦截器
static void rwbp_exit_group_hook(hook_fargs1_t *args, void *udata) {
    if (current_control_task && current_control_task == get_current()) {
        handle_cleanup();
        current_control_task = NULL;
    }
}

// KPM 初始化回调
static long rwbp_init(const char *args, const char *event, void *reserved) {
  pr_info("[kpm_RWBP] 优化重构版本初始化中...\n");

  // 调用兼容层进行符号获取与页表配置动态探测
  long ret = compat_init();
  if (ret != 0) {
    pr_err("[kpm_RWBP] 初始化内核兼容层失败: %ld\n", ret);
    return ret;
  }

  // 挂钩系统调用
  hook_syscalln(44, 3, rwbp_fstatfs_hook, 0, 0);       // __NR_fstatfs (引导)
  hook_syscalln(94, 1, rwbp_exit_group_hook, 0, 0);  // __NR_exit_group (自动清理)

  pr_info("[kpm_RWBP] 初始化成功，系统调用 Hook 已就绪！\n");
  return 0;
}

// KPM 退出回调
static long rwbp_exit(void *reserved) {
  pr_info("[kpm_RWBP] 模块安全注销中...\n");

  // 1. 先解挂系统调用 Hook，阻断新指令和新引导
  unhook_syscalln(44, rwbp_fstatfs_hook, 0);
  unhook_syscalln(94, rwbp_exit_group_hook, 0);

  // 2. 等待所有的在途 Work 任务执行完毕 (安全退出屏障)
  while (in_flight > 0) {
      pr_info("[kpm_RWBP] 模块注销等待中... 在途工作任务数: %d\n", in_flight);
      kfunc(msleep)(10);
  }

  // 3. 执行最终彻底清理
  handle_cleanup();
  remove_wp_hook();

  pr_info("[kpm_RWBP] 模块已安全卸载...\n");
  return 0;
}

// 注册回调 (无需 CTL0 控制通道，完全依靠匿名 Inode ioctl 控制)
KPM_INIT(rwbp_init);
KPM_EXIT(rwbp_exit);
