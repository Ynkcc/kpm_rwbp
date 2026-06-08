#include "kernel_compat.h"
#include "mem_reader.h"
#include <compiler.h>
#include <kpmodule.h>
#include <linux/errno.h>
#include <linux/printk.h>

// 模块元信息声明
KPM_NAME("kpm_RWBP");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("ynk");
KPM_DESCRIPTION("Kernel Memory Reader KPM");

// KPM 初始化回调
static long rwbp_init(const char *args, const char *event, void *reserved) {
  pr_info("[kpm_RWBP] 重构版本初始化中...\n");

  // 调用兼容层进行符号获取与页表配置动态探测
  long ret = compat_init();
  if (ret != 0) {
    pr_err("[kpm_RWBP] 初始化内核兼容层失败: %ld\n", ret);
    return ret;
  }

  pr_info("[kpm_RWBP] 初始化成功！\n");
  return 0;
}

// KPM 控制回调 (KPM_CTL0)
// 用户态传入 args，例如 "read <pid> <addr> <size>"
static long rwbp_control0(const char *args, char *__user out_msg, int outlen) {
  uint32_t pid = 0;
  uint64_t addr = 0;
  uint64_t size = 0;

  // 解析参数 "read %d %lx %lld"
  if (kf_sscanf(args, "read %u %lx %lu", &pid, &addr, &size) == 3) {
    if (size > (uint64_t)outlen) {
      size = outlen;
    }
    return read_process_memory(pid, addr, size, out_msg);
  }

  return -EINVAL;
}

// KPM 退出回调
static long rwbp_exit(void *reserved) {
  pr_info("[kpm_RWBP] 模块已安全卸载...\n");
  return 0;
}

// 注册回调
KPM_INIT(rwbp_init);
KPM_CTL0(rwbp_control0);
KPM_EXIT(rwbp_exit);
