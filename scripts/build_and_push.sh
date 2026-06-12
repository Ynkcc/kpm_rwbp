#!/usr/bin/env bash
# 一键编译 + 推送脚本
# 用法:
#   ./build_and_push.sh          # 编译全部 + 推送
#   ./build_and_push.sh build    # 仅编译
#   ./build_and_push.sh push     # 仅推送（跳过编译）
#   ./build_and_push.sh clean    # 清理构建产物


set -euo pipefail

# ========== 配置 ==========
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${PROJECT_ROOT}/out"
DEVICE_DIR="/data/local/tmp"

# 需要推送到设备的产物列表
PUSH_FILES=(
    "kpm_RWBP.kpm"
    "test_rwbp"
)

# ========== 颜色输出 ==========
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ========== 编译 ==========
do_build() {
    info "开始编译 (项目根目录: ${PROJECT_ROOT})"

    # 编译内核模块 + tests（根 Makefile 的 all 目标已包含 tests）
    make -C "${PROJECT_ROOT}" all

    echo ""
    ok "编译完成，产物列表:"
    ls -lh "${OUT_DIR}"/ 2>/dev/null || warn "out 目录为空"
}

# ========== 清理 ==========
do_clean() {
    info "清理构建产物..."
    make -C "${PROJECT_ROOT}" clean
    ok "清理完成"
}

# ========== 推送 ==========
do_push() {
    local serial="${DEVICE_SERIAL:-}"
    local adb_cmd="adb"
    if [[ -n "${serial}" ]]; then
        adb_cmd="adb -s ${serial}"
        info "推送产物到指定设备: ${serial} (${DEVICE_DIR})..."
    else
        info "推送产物到默认设备 (${DEVICE_DIR})..."
    fi

    # 检查 adb 连接
    ${adb_cmd} devices | grep -q 'device$' || fail "未检测到 adb 设备连接"

    local pushed=0
    for f in "${PUSH_FILES[@]}"; do
        local src="${OUT_DIR}/${f}"
        if [[ -f "${src}" ]]; then
            ${adb_cmd} push "${src}" "${DEVICE_DIR}/${f}"
            # 可执行文件设置权限（.kpm 不需要）
            if [[ "${f}" != *.kpm ]]; then
                ${adb_cmd} shell "chmod +x ${DEVICE_DIR}/${f}"
            fi
            pushed=$((pushed + 1))
        else
            warn "跳过不存在的文件: ${src}"
        fi
    done

    ok "推送完成，共 ${pushed} 个文件"
}


# ========== 主逻辑 ==========
cmd="${1:-all}"
DEVICE_SERIAL="${2:-${ANDROID_SERIAL:-}}"

case "${cmd}" in
    build)
        do_build
        ;;
    clean)
        do_clean
        ;;
    push)
        do_push
        ;;

    all)
        do_build
        do_push
        ;;
    *)
        echo "用法: $0 {build|push|clean|all} [device_serial]"
        echo "  build  - 仅编译"
        echo "  push   - 仅推送到设备"
        echo "  clean  - 清理构建产物"
        echo "  all    - 编译 + 推送 (默认)"
        exit 1
        ;;
esac
