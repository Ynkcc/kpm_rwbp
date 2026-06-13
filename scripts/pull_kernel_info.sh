#!/usr/bin/env bash
set -euo pipefail

# 获取当前脚本所在目录
OUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 接受指定 DEVICE_SERIAL
DEVICE_SERIAL="${1:-${ANDROID_SERIAL:-}}"
local_serial="${DEVICE_SERIAL:-}"
adb_cmd="adb"
if [[ -n "${local_serial}" ]]; then
    adb_cmd="adb -s ${local_serial}"
    echo "[*] 使用指定设备: ${local_serial}"
else
    echo "[*] 使用默认设备"
fi

# 检查 adb 连接
${adb_cmd} devices | grep -q 'device$' || { echo "[-] 未检测到 adb 设备连接"; exit 1; }

# 获取 hostname 和内核版本
DEV_HOST=$(${adb_cmd} shell hostname | tr -d '\r\n')
if [[ -z "${DEV_HOST}" || "${DEV_HOST}" == "localhost" ]]; then
    DEV_HOST=$(${adb_cmd} shell getprop ro.product.device | tr -d '\r\n')
fi
if [[ -z "${DEV_HOST}" ]]; then
    DEV_HOST="generic"
fi
DEV_HOST=$(echo "${DEV_HOST}" | sed 's/[^a-zA-Z0-9_-]/_/g')

KVER=$(${adb_cmd} shell uname -r | tr -d '\r\n')
KVER=$(echo "${KVER}" | sed 's/[^a-zA-Z0-9_.-]/_/g')

KALLSYMS_OUT="${OUT_DIR}/kallsyms_${DEV_HOST}_${KVER}.txt"
CONFIG_OUT="${OUT_DIR}/kernel_${DEV_HOST}_${KVER}.config"

# 1. 拉取 kallsyms
# 获取当前 kptr_restrict 值
ORIG_VAL=$(${adb_cmd} shell "su -c 'cat /proc/sys/kernel/kptr_restrict'" | tr -d '\r\n')
echo "[*] 当前 kptr_restrict 值为: ${ORIG_VAL}"

# 将其设为 0 以显示真实符号地址
echo "[*] 正在将 kptr_restrict 设为 0..."
${adb_cmd} shell "su -c 'echo 0 > /proc/sys/kernel/kptr_restrict'"

# 拷贝 kallsyms 到临时目录并拉取，避免 adb shell 文本转换问题
echo "[*] 正在拉取 /proc/kallsyms..."
${adb_cmd} shell "su -c 'cp /proc/kallsyms /data/local/tmp/kallsyms.txt && chmod 666 /data/local/tmp/kallsyms.txt'"
${adb_cmd} pull /data/local/tmp/kallsyms.txt "${KALLSYMS_OUT}"
${adb_cmd} shell "rm /data/local/tmp/kallsyms.txt"

# 恢复原始的 kptr_restrict 值
echo "[*] 正在恢复 kptr_restrict 为 ${ORIG_VAL}..."
${adb_cmd} shell "su -c 'echo ${ORIG_VAL} > /proc/sys/kernel/kptr_restrict'"

# 2. 拉取内核 config
echo "[*] 正在尝试拉取内核 config..."
if ${adb_cmd} shell "su -c 'ls /proc/config.gz'" >/dev/null 2>&1; then
    echo "[*] 发现 /proc/config.gz，正在拉取并解压到 ${CONFIG_OUT}..."
    ${adb_cmd} shell "su -c 'cp /proc/config.gz /data/local/tmp/config.gz && chmod 666 /data/local/tmp/config.gz'"
    ${adb_cmd} pull /data/local/tmp/config.gz "${OUT_DIR}/config.gz"
    ${adb_cmd} shell "rm /data/local/tmp/config.gz"
    
    # 解压并重命名
    gunzip -f "${OUT_DIR}/config.gz"
    mv "${OUT_DIR}/config" "${CONFIG_OUT}"
    echo "[+] 内核 config 已成功保存到 ${CONFIG_OUT}"
else
    echo "[!] 警告: 未在设备上找到 /proc/config.gz，无法直接拉取内核 config。"
fi

echo "[+] 拉取完成！"
