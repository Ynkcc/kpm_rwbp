#ifndef __SUPERCALL_H__
#define __SUPERCALL_H__

#include <unistd.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

// KernelPatch 版本码
#define MAJOR 0
#define MINOR 10
#define PATCH 7

// 超级调用号 (ARM64)
#define __NR_supercall 45

// 超级调用命令
#define SUPERCALL_KPM_LOAD 0x1020
#define SUPERCALL_KPM_UNLOAD 0x1021
#define SUPERCALL_KPM_CONTROL 0x1022

// 辅助函数：构造超级调用所需要的控制数据
static inline long ver_and_cmd(long cmd)
{
    uint32_t version_code = (MAJOR << 16) + (MINOR << 8) + PATCH;
    return ((long)version_code << 32) | (0x1158 << 16) | (cmd & 0xFFFF);
}

// 加载 KPM 模块
static inline long sc_kpm_load(const char *key, const char *path, const char *args)
{
    if (!key || !key[0]) return -EINVAL;
    if (!path || !path[0]) return -EINVAL;
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_LOAD), path, args, NULL);
}

// 卸载 KPM 模块
static inline long sc_kpm_unload(const char *key, const char *name)
{
    if (!key || !key[0]) return -EINVAL;
    if (!name || !name[0]) return -EINVAL;
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_UNLOAD), name, NULL);
}

// 发送 KPM 控制消息
static inline long sc_kpm_control(const char *key, const char *name, const char *ctl_args, char *out_msg, long outlen)
{
    if (!key || !key[0]) return -EINVAL;
    if (!name || !name[0]) return -EINVAL;
    if (!ctl_args || !ctl_args[0]) return -EINVAL;
    return syscall(__NR_supercall, key, ver_and_cmd(SUPERCALL_KPM_CONTROL), name, ctl_args, out_msg, outlen);
}

#endif // __SUPERCALL_H__
