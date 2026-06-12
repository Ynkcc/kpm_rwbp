#ifndef KPM_CTRL_H
#define KPM_CTRL_H

// 默认配置（与 src/core/main.c 中 KPM_NAME 保持一致）
#define KPM_KEY  "QWERTY1234"
#define KPM_NAME "kpm_RWBP"
#define KPM_PATH "/data/local/tmp/kpm_RWBP.kpm"

// 加载 KPM，成功返回 0，失败返回 -1
int kpm_load(const char *key, const char *path);

// 卸载 KPM
void kpm_unload(const char *key, const char *name);

// 触发 Hook 获取匿名控制 FD，失败返回 -1
int get_anon_fd(void);

#endif // KPM_CTRL_H
