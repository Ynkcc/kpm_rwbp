# kpm_rwbp 架构文档

> **维护约定**：本文档是代码库的结构性快照，供 AI 助手与人类快速定位，避免每次需求变更都重新全库探索。
> **更新规则**：
> - 阅读实际代码发现与本文档描述不一致时，更新本文档；
> - 仅函数级内部改动不需更新（本文只记录"结构性事实"：模块划分、关键类型、入口、数据流）；
> - 新增/删除模块文件、命令码、scheme、关键类型、构建目标时必须更新，并在文末"变更记录"追加一行。

## 项目定位

`kpm_RWBP` 是一个基于 KernelPatch（KP）框架的 ARM64 内核模块，使用 Rust（`no_std` + `staticlib`）实现。核心能力：

1. **跨进程内存读写**：手动遍历目标进程页表 + 内核线性映射区物理直写，规避 `access_process_vm` 的缺页侧信道；
2. **硬件断点/监视点管理**：两种 scheme（perf_event 路线 / 调试寄存器直写路线），命中记录环形缓冲供用户态拉取；
3. **Ghost 隐形内存**：绕过 VMA 直接向目标进程页表强插物理页，对 `/proc/pid/maps` 不可见，可写入代码并同步 I-Cache。

## 目录结构

```
kpm_rwbp/
├── Cargo.toml / build.rs / rust-toolchain.toml / Makefile
├── KernelPatch/               # KP 框架参考（头文件与实现）
├── kernel_source/             # 多版本内核参考源码（4.14 ~ 6.6 等）
├── scripts/                   # build_and_push.sh / pull_kernel_info.sh
├── src/
│   ├── lib.rs                 # 模块入口：KPM 元数据段、rwbp_init/rwbp_exit、panic_handler
│   ├── macros.rs              # sym!/sym_must!、pr_info!/pr_err!/pr_warn!、KernelBufWriter
│   ├── ffi/
│   │   ├── mod.rs             # hook_fargs0_t/4_t、hook_local_t、get_current()
│   │   ├── symbols.rs         # KernelSymbols(SYMS) 运行时 kallsyms 缓存、MandatorySymbols(M_SYMS)、KP 导出符号 extern
│   │   ├── offsets.rs         # TaskStructOffset / CredOffset / MmStructOffset（KP 导出，适配多内核版本）
│   │   └── routing.rs         # PteOp trait + apply_to_page_range()（按内核版本路由回调签名，>=5.3 / <5.3）
│   ├── hooks/
│   │   ├── syscall.rs         # rwbp_fstatfs_hook（IPC 命令入口）、rwbp_exit_group_hook（控制进程退出清理）
│   │   └── watchpoint.rs      # install_wp_hook / remove_wp_hook（wrap KP 的 watchpoint_handler）
│   ├── hwbp/
│   │   └── core.rs            # HwbpNode、RcuList、BP_LIST、scheme 1/2 注册/启停/命中记录、调试寄存器读写
│   ├── ipc/
│   │   ├── protocol.rs        # 命令码常量、#[repr(C)] 命令结构体、ShmChannel
│   │   └── dispatcher.rs      # rwbp_dispatch()、GHOST_POOL[16]、cleanup_ghost_pool()
│   ├── mm/
│   │   ├── process.rs         # copy_to_user/copy_from_user、手动页表遍历、read/write_process_memory
│   │   ├── ghost.rs           # GhostPage、ghost_alloc/free/write、ghost_sync_icache、find_hole_near
│   │   └── libc.rs            # volatile 手写 memset/memcpy（链接期替代 libc）
│   ├── sync/
│   │   ├── mod.rs             # RawSpinlock、KernelMutex<T>、RcuReadGuard、smp_wmb/smp_rmb
│   │   └── arc.rs             # KernelArc<T>（基于 kmalloc/kfree 的引用计数指针）
│   └── utils/
│       ├── error.rs           # Error 枚举（负 errno 语义）
│       └── list.rs            # ListHead（内核 list_head 仿制，含 RCU 变体）
└── tests/runner/              # Android 用户态测试程序（C）
```

## 入口与生命周期

`src/lib.rs` 定义 KPM 链接段约定：

- `.kpm.info`：`__kpm_info_name/version/license/author/description`。version 由 `build.rs` 从 git commit 计数生成（脏树追加 `-dirty`），经 `OUT_DIR/kpm_version.bin` 内联。
- `.kpm.init` → `rwbp_init`：① 初始化 `hwbp::core::BP_LIST`（RCU 链表头）；② `ffi::init_symbols()`（kallsyms 符号缓存、`linear_voffset` 计算、必选符号集校验）；③ `BP_LIST_LOCK.init()`；④ `hook_syscalln` 挂接 fstatfs(44) 与 exit_group(94) 两个系统调用。
- `.kpm.exit` → `rwbp_exit`：卸载两个 syscall hook → `remove_wp_hook` → `handle_cleanup()`（注销全部断点 + 清 Ghost 池）→ 临时 `rcu_read_unlock` 破自身 RCU 读临界区 → 自旋等待 `IN_FLIGHT` 计数归零 → `cleanup_ghost_pool()` → 对称恢复 `rcu_read_lock`。
- `panic_handler`：打印报错位置 + `dump_stack`（需 `dump_stack` feature）+ 刷日志后死循环挂起当前线程，防止静默失效或引发整机重启。

## IPC 通道与命令分发

数据流（无 ioctl，伪装系统调用）：

```
用户态 runner: syscall(44/fstatfs, cmd_struct_ptr, 0xDEADC0DE, cmd)
    └→ rwbp_fstatfs_hook (hooks/syscall.rs)
        门禁: arg1 == 0xDEADC0DE 且 caller uid == 0（task_struct.cred 偏移直读）
        ├→ 普通命令: copy_from_user 读请求结构体 → 执行 → copy_to_user 回写结果
        └→ Ghost 命令(8021-8023): 包成栈上临时 ShmChannel → rwbp_dispatch (ipc/dispatcher.rs)
        fargs->ret = 结果码; skip_origin = 1（吞掉原 syscall，返回值即 RPC 结果）
```

- `ShmChannel`（`ipc/protocol.rs`）：`{ magic='SHMC', cmd, status, retval, data_size, payload[3500] }`，`rwbp_dispatch` 校验 magic 后按 cmd 分发。

### 命令码一览（`ipc/protocol.rs`）

| 命令码 | 名称 | 功能 |
|---|---|---|
| 8001 | OP_READ_MEM | 读目标进程内存（数据入 payload） |
| 8002 | OP_WRITE_MEM | 写目标进程内存 |
| 8011 | OP_SET_HW_BREAKPOINT | 注册硬件断点（pid/addr/bp_type/len/scheme） |
| 8013 | OP_REMOVE_HW_BREAKPOINT | 注销指定断点 |
| 8014 | OP_REMOVE_ALL_HW_BREAKPOINT | 注销全部断点 |
| 8015 | OP_READ_HW_BP_INFO | 拉取命中记录（消费式） |
| 8016 | OP_GET_HW_BREAKPOINT_CAPS | 返回硬件 BRP/WRP 最大数量 |
| 8017 | OP_ENABLE_HW_BREAKPOINT | 启用已注册断点 |
| 8018 | OP_DISABLE_HW_BREAKPOINT | 暂停断点 |
| 8019 | OP_QUERY_HW_BREAKPOINT_STATUS | 查询断点状态（原地回填） |
| 8021 | OP_GHOST_ALLOC | 分配 Ghost 内存，回填 vaddr |
| 8022 | OP_GHOST_FREE | 释放 Ghost 内存 |
| 8023 | OP_GHOST_WRITE | 写 Ghost 内存（写后自动 `ghost_sync_icache`） |
| 8031 | OP_READ_OBSERVE_RECORDS | 拉取 OBSERVE 观测记录（perf/ptrace 下断行为，消费式） |

## 硬件断点（hwbp/core.rs）

管理结构：全局 RCU 链表 `BP_LIST` + 自旋锁 `BP_LIST_LOCK`，节点为 `HwbpNode`。

| scheme | 路线 | 机制 |
|---|---|---|
| 1 | perf_event | `register_user_hw_breakpoint` + 回调 `hwbp_triggered`；命中后"双向振荡状态机"：入口触发 → `modify_user_hw_breakpoint` 改到 LR → 返回触发 → 还原入口，实现函数进/出（含 X0 返回值）零时滞记录 |
| 2 | 寄存器直写 | `on_each_cpu` 写每核 `DBGWVR0/DBGWCR0`；`hook_wrap` KP 的 `watchpoint_handler`（`before_watchpoint_handler` 按 pid+addr 匹配）；命中后临时关 WCR 使能位，`queue_work_on` 异步恢复 |
| 999 | 已废弃 | 注册直接返回 `EINVAL` |

- 硬件能力探测：`mrs id_aa64dfr0_el1` 读 BRPs/WPRPs（`get_hwbp_caps`，含 +1 偏移语义）。
- 槽位：scheme 1 由内核 perf 子系统自动分配；scheme 2 固定占用 watchpoint 槽 0。
- 命中记录：每节点内嵌 16 深度环形缓冲 `hit_records[16]` + seqlock（`hit_record_seqs`），记录 `{hit_time, task_id, hit_addr, regs[31]+sp+pc+pstate}`；用户态经 `OP_READ_HW_BP_INFO` 消费式拉取（读后推进 tail 并清空）。

## 内存读写（mm/process.rs）

- 路径：手动遍历目标进程页表（`pgtable_phys`/`walk_to_pmd`）得到物理地址，加 `linear_voffset` 经内核线性映射区直接读/写；物理页无效则直接中断返回。
- 设计折衷（详见 AGENTS.md）：
  - **禁用 `access_process_vm`**：会触发缺页处理，产生 Pagemap present bit / PerfEvent min_flt 侧信道告警；
  - **不使用 `pfn_to_page`**：无导出符号，且硬编码 `struct page` 布局损害跨版本兼容；
  - **接受 TOCTOU 竞态**：无锁直写在极端并发下可能污染被重新分配的物理页导致 Panic，作为"错误尽早暴露"哲学下的明确取舍。
- 使用约束：仅直写目标进程私有可写内存（堆/栈/.data/.bss），避免污染共享只读页或全局零页。

## Ghost 内存（mm/ghost.rs）

绕过 `vm_area_struct`，直接改页表注入物理页，对 `/proc/pid/maps` 隐形。

- `GhostPage`：`{task, mm, vaddr, kaddr(线性映射区虚址), pfn, installed_pte, order, alloc_size, installed}`；`kaddr==1` 表示池占位符。
- `ghost_alloc`：`__get_free_pages(GFP_KERNEL|__GFP_ZERO)` → `find_hole_near`（用 `find_vma` 在附近找 VMA 空洞）→ `apply_to_page_range`（`ffi/routing.rs`，按内核版本路由）逐页强插 PTE（保留模板属性，置 VALID|TYPE_PAGE|AF，清 UXN/GP/RDONLY，失败逐页回滚）→ `tlbi vmalle1is`。
- `ghost_free`：清 PTE → TLB + `ic ialluis` → `on_each_cpu` IPI 脱离映射 → `free_pages` + `mmput`。
- `ghost_write`：经内核直接映射区拷贝，不经过用户页表。
- `ghost_sync_icache`：逐 64B 行 `dc cvau` 清 D-Cache → `ic ialluis` 全失效 → dsb/isb，保证注入指令可执行。
- 池管理：`ipc/dispatcher.rs` 中 `GHOST_POOL[16]`（`Option<GhostPage>` + spinlock）；模块卸载与控制进程 `exit_group` 时清理。

## 运行时基础设施

- **符号体系（ffi/symbols.rs）**：`SYMS` 为运行时 kallsyms 查找结果缓存；`M_SYMS`（`MandatorySymbols`）为缺一不可的符号集，`init_symbols()` 阶段校验失败即初始化失败；KP 直接导出的函数以 extern 声明。
- **版本兼容（ffi/routing.rs + offsets.rs）**：内核结构体偏移由 KP 导出（`TaskStructOffset`/`CredOffset`/`MmStructOffset`）；`apply_to_page_range` 按 >=5.3 / <5.3 自动路由回调签名。
- **同步原语（sync/）**：`RawSpinlock`（借内核 `_raw_spin_lock_irqsave`）、`KernelMutex<T>`、`RcuReadGuard`、`KernelArc<T>`（kmalloc/kfree 引用计数）、`ListHead`（含 RCU 变体 `add_rcu`/`del_rcu`）。
- **错误模型（utils/error.rs）**：`Error` 枚举，负 errno 语义，直接映射 syscall 返回值。

## 构建流程（Makefile / build.rs）

1. **Rust 静态库**：nightly，`cargo build -Z build-std=core,compiler_builtins --target aarch64-linux-android --release`；`RUSTFLAGS="-C relocation-model=static -C opt-level=3"`；`DUMP_STACK=1` 启用 `--features dump_stack`。产物 `target/aarch64-linux-android/release/libkpm_rwbp.a`。
2. **.kpm 打包**：`ld.lld -r` + 临时 linker script 合并 `.text/.rodata/.data/.bss/.kpm.info/.kpm.init/.kpm.exit` 段 → `out/kpm_RWBP.kpm`；强制 undefined 关键符号（`__kpm_info_*`、`__kpm_initcall_rwbp_init`、`__kpm_exitcall_rwbp_exit`、`mem*`、`rust_eh_personality`）；`llvm-strip` 剥离 `.eh_frame`/debug。
3. **测试程序**：NDK `aarch64-linux-android31-clang` 编译 `tests/runner` → `out/test_rwbp`。

关键 profile（Cargo.toml）：`crate-type = ["staticlib"]`、edition 2024、`panic="abort"`、release `lto=true / opt-level="z" / codegen-units=1`；依赖仅 `zerocopy 0.8`（repr(C) 协议结构零拷贝序列化）。

## 测试（tests/runner）

Android 用户态程序，通过 `syscall(44, ptr, 0xDEADC0DE, cmd)` 与模块交互；`main.c` 调度并汇总 PASS/FAIL。参数：`--case`、`--scheme 1-2`、`--timeout ms`。

| case | 内容 |
|---|---|
| mem / mem-write | 跨进程内存读 / 写 |
| mem-list / mem-array | 链表式逐指针读取（40 位掩码）/ 连续数组读取 |
| hwbp-self | scheme 1/2 各自自测（固定地址写入 + XOR 校验、命中记录） |
| hwbp-target / hwbp-scale / hwbp-concurrency / hwbp-interfaces | 跨进程断点 / 规模 / 并发 / 接口面（enable/disable/query/caps） |
| ghost | Ghost alloc/write/free 生命周期 |
| observe-perf / observe-ptrace / observe-resolve | OBSERVE 方案 P0：perf/ptrace 下断拦截记录回读比对；路径归因由 runner 经 /proc/<pid>/maps 完成。需显式 `--case` 指定，未并入 all |

协议镜像：`tests/include/dispatcher.h`、`supercall.h` 与 `src/ipc/protocol.rs` 保持一致，修改命令结构体时须同步。

## 变更记录

- 初始版本：生成于 rust-main 分支，覆盖 src/ 模块划分、IPC 协议（8001-8023）、hwbp scheme 1/2、mm 读写与 Ghost 机制、构建与测试流程。
- 新增 IPC 命令码 8031（OP_READ_OBSERVE_RECORDS，`ObserveRecord`/`ObserveInfoCmd`）与 tests/runner/case_observe.c P0 骨架（observe-perf/observe-ptrace/observe-resolve）；内核侧 observe hook 尚未实现。
- 实现 `src/hooks/observe.rs`（OBSERVE 模式）：hook_syscalln 拦截 perf_event_open(241)/ptrace(117)，捕获硬件断点行为入 64 深度环形缓冲。设计取舍：内核侧零结构体偏移（不读 vma/file，路径归因移至用户态消费端）；pid/tid 经 `__task_pid_nr_ns` 获取（KP 的 tgid/pid 偏移在部分设备未填充）；`mm_offset` 直读不可靠，跨 mm 操作一律走 `get_task_mm`+`mmput`。
