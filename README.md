# KPM RWBP (Kernel Breakpoint Module)

`kpm_RWBP` 基于 [KernelPatch](./KernelPatch) 框架开发的内核模块，实现了内核态硬件断点以及内核态内存读写功能。

## 项目分支与版本说明

- **`rust-main` 分支（当前分支）**: Rust 版本，利用 Rust 重写的内核模块，为目前的主要开发和维护版本。
- **`main` 分支**: C++ 版本，落后于当前分支。缺少遍历页表直接读取。

---

## 核心功能

- **ARM64 硬件断点管理**: 支持硬件断点寄存器分配与在途任务追踪。
- **高效内存读写**: 支持通过系统调用拦截实现的高性能内核态内存直接读写。*注意:未实现并发安全*
- **跨内核版本兼容**: 适配 Android/Linux 多内核版本的符号解析与链接。仅测试`4.14`,`4.19`,`6.6`。

---

## 构建、部署与测试

在项目根目录下，你可以使用以下命令进行编译和部署：

*   **一键构建**:
    ```bash
    make all
    ```
    *(会自动调用 Cargo 构建 Rust 静态库，并通过 NDK 链接生成 `out/kpm_RWBP.kpm` 内核模块，同时编译测试程序)*

*   **构建并推送至设备**:
    ```bash
    ./scripts/build_and_push.sh all
    ```

*   **运行测试**:
    ```bash
    adb shell su -c "/data/local/tmp/test_rwbp"
    ```

---

## 开源协议

本项目采用 [GNU General Public License (GPL) 2.0](./LICENSE) 协议开源。
