#!/bin/bash
set -e

# 获取当前脚本所在目录
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KALLSYMS_OUT="$OUT_DIR/kallsyms.txt"
CONFIG_OUT="$OUT_DIR/kernel.config"

# 1. 拉取 kallsyms
# 获取当前 kptr_restrict 值
ORIG_VAL=$(adb shell "su -c 'cat /proc/sys/kernel/kptr_restrict'" | tr -d '\r\n')
echo "当前 kptr_restrict 值为: $ORIG_VAL"

# 将其设为 0 以显示真实符号地址
echo "正在将 kptr_restrict 设为 0..."
adb shell "su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'"

# 拷贝 kallsyms 到临时目录并拉取，避免 adb shell 文本转换问题
echo "正在拉取 /proc/kallsyms..."
adb shell "su -c 'cp /proc/kallsyms /data/local/tmp/kallsyms.txt && chmod 666 /data/local/tmp/kallsyms.txt'"
adb pull /data/local/tmp/kallsyms.txt "$KALLSYMS_OUT"
adb shell "rm /data/local/tmp/kallsyms.txt"

# 恢复原始的 kptr_restrict 值
echo "正在恢复 kptr_restrict 为 $ORIG_VAL..."
adb shell "su -c 'echo $ORIG_VAL > /proc/sys/kernel/kptr_restrict'"

# 2. 拉取内核 config
echo "正在尝试拉取内核 config..."
if adb shell "su -c 'ls /proc/config.gz'" >/dev/null 2>&1; then
    echo "发现 /proc/config.gz，正在拉取并解压到 $CONFIG_OUT..."
    adb shell "su -c 'cp /proc/config.gz /data/local/tmp/config.gz && chmod 666 /data/local/tmp/config.gz'"
    adb pull /data/local/tmp/config.gz "$OUT_DIR/config.gz"
    adb shell "rm /data/local/tmp/config.gz"
    
    # 解压并重命名
    gunzip -f "$OUT_DIR/config.gz"
    mv "$OUT_DIR/config" "$CONFIG_OUT"
    echo "内核 config 已成功保存到 $CONFIG_OUT"
else
    echo "警告: 未在设备上找到 /proc/config.gz，无法直接拉取内核 config。"
fi

echo "拉取完成！"
