#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "kpm_ctrl.h"
#include "../include/supercall.h"

int kpm_load(const char *key, const char *path)
{
    long ret = sc_kpm_load(key, path, "");
    if (ret != 0) {
        printf("[-] sc_kpm_load 失败: %ld\n", ret);
        return -1;
    }
    return 0;
}

void kpm_unload(const char *key, const char *name)
{
    long ret = sc_kpm_unload(key, name);
    printf("[*] kpm_unload 返回: %ld\n", ret);
}

int get_anon_fd(void)
{
    long timestamp = (long)time(NULL);
    // ARM64: 44 = __NR_fstatfs，触发引导 Hook 获取匿名控制 FD
    int fd = (int)syscall(44, timestamp, (void *)0xDEADC0DEULL);
    if (fd < 0)
        perror("[-] fstatfs bypass redirect 失败");
    return fd;
}
