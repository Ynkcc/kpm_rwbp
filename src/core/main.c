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

// 完全对齐 Linux 6.6 内核的 file_operations 伪声明
struct file_operations {
    void *owner;
    long long (*llseek) (struct file *, long long, int);
    long (*read) (struct file *, char *, unsigned long, long long *);
    long (*write) (struct file *, const char *, unsigned long, long long *);
    long (*read_iter) (struct kiocb *, struct iov_iter *);
    long (*write_iter) (struct kiocb *, struct iov_iter *);
    int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
    int (*iterate_shared) (struct file *, struct dir_context *);
    unsigned int (*poll) (struct file *, struct poll_table_struct *);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    int (*mmap) (struct file *, struct vm_area_struct *);
    unsigned long mmap_supported_flags;
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, void *id);
    int (*release) (struct inode *, struct file *);
    int (*fsync) (struct file *, long long, long long, int);
    int (*fasync) (int, struct file *, int);
    int (*lock) (struct file *, int, struct file_lock *);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*flock) (struct file *, int, struct file_lock *);
    long (*splice_write)(struct pipe_inode_info *, struct file *, long long *, unsigned long, unsigned int);
    long (*splice_read)(struct file *, long long *, struct pipe_inode_info *, unsigned long, unsigned int);
    void (*splice_eof)(struct file *);
    int (*setlease)(struct file *, int, struct file_lock **, void **);
    long (*fallocate)(struct file *, int, long long, long long);
    void (*show_fdinfo)(struct seq_file *, struct file *);
    unsigned long (*copy_file_range)(struct file *, long long, struct file *, long long, unsigned long, unsigned int);
    long long (*remap_file_range)(struct file *, long long, struct file *, long long, long long, unsigned int);
    int (*fadvise)(struct file *, long long, long long, int);
    int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
    int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

#define syscall_set_retval(args, val) ((args)->ret = (val))
#define syscall_set_handled(args, handled) ((args)->skip_origin = (handled))

// 模块元信息声明
KPM_NAME("kpm_RWBP");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ynk");
KPM_DESCRIPTION("Kernel Memory Reader & HWBP KPM (Refactored)");

// 控制端进程指针
static void *current_control_task = NULL;

// 自动清理内核资源
void handle_cleanup(void) {
    pr_info("[kpm_RWBP] 控制端进程已退出，开始自动清理内核资源...\n");
    unregister_all_hwbp();
}

// 匿名 FD 绑定的 ioctl 执行函数
static long anon_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    pr_info("[kpm_RWBP] anon_ioctl called: file=%p, cmd=%u, arg=%lx\n", file, cmd, arg);
    kfunc(msleep)(50);
    return rwbp_dispatch(cmd, arg);
}

// 匿名文件操作结构体
static struct file_operations anon_fops = {
    .unlocked_ioctl = anon_ioctl,
    .compat_ioctl = anon_ioctl,
};

// 引导阶段系统调用 Hook 拦截器
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
    
    int64_t current_timestamp = kfunc(ktime_get_real_seconds)();
    int64_t received_timestamp = (int64_t)arg0;
    int64_t diff = current_timestamp - received_timestamp;

    pr_info("[kpm_RWBP] fstatfs_hook matched: uid=%d, diff=%lld, arg0=%llx\n", (int)caller_uid, (long long)diff, (unsigned long long)arg0);

    if (diff < -3 || diff > 3) {
        return;
    }

    // 4. 生成匿名描述符并注入当前进程
    int fd = kfunc(get_unused_fd_flags)(0);
    if (fd >= 0) {
        struct file *file = kfunc(anon_inode_getfile)("rwbp_anon", &anon_fops, NULL, 0);
        if (!IS_ERR(file)) {
            kfunc(fd_install)(fd, file);
            current_control_task = get_current(); // 记录控制进程
            syscall_set_retval(args, fd);
            syscall_set_handled(args, true);
            pr_info("[kpm_RWBP] 成功为控制进程 PID %d 注入匿名控制 FD %d\n", (int)syscall_argn(args, 0), fd);
        } else {
            kfunc(put_unused_fd)(fd);
        }
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
