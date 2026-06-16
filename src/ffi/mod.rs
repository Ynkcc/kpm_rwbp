// FFI bindings - 类型与 KernelPatch 头文件兼容

use core::ffi::c_void;
use core::ffi::c_int;

pub mod offsets;
pub mod symbols;

pub use offsets::{TaskStructOffset, CredOffset};
pub use symbols::{
    PerfEventAttr, lookup_sym, init_symbols, kver, SYMS,
    has_syscall_wrapper, kallsyms_lookup_name,
    // 直接可用的 KP 核心导出符号（无需 init_symbols）
    hook_syscalln, unhook_syscalln, hook_wrap, hook_unwrap_remove,
    printk,
    task_ext_size, reg_task_local, has_task_local, task_local_ptr,
    sys_call_table, compat_sys_call_table, has_config_compat,
    raw_syscall0, raw_syscall1, raw_syscall2, raw_syscall3,
    raw_syscall4, raw_syscall5, raw_syscall6,
    commit_su, task_su, is_su_allow_uid, su_add_allow_uid, su_remove_allow_uid,
    su_allow_uid_nums, su_reset_path, su_get_path,
    set_ap_mod_exclude, get_ap_mod_exclude,
    write_kstorage, read_kstorage, get_kstorage, remove_kstorage,
    hotpatch, hotpatch_nosync,
    // 结构体偏移（KP 导出）
    task_struct_offset, cred_offset,
};

/// 拦截时用于保留寄存器或局部私有上下文的内核数据块
#[repr(C)]
pub struct hook_local_t {
    pub data: [u64; 8],
}

/// 系统调用 Hook 触发时传入的内核寄存器及控制参数结构
#[repr(C, align(8))]
pub struct hook_fargs0_t {
    pub chain: *mut c_void,
    pub skip_origin: c_int,
    pub local: hook_local_t,
    pub ret: u64,
    pub args: [u64; 4],
}

/// Watchpoint 硬件拦截触发时传入的特定寄存器与控制参数结构
#[repr(C, align(8))]
pub struct hook_fargs4_t {
    pub chain: *mut c_void,
    pub skip_origin: c_int,
    pub local: hook_local_t,
    pub ret: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
}

/// Hook 错误码
pub type hook_err_t = i32;

/// KPM 模块回调类型
pub type mod_initcall_t = Option<unsafe extern "C" fn(args: *const u8, event: *const u8, reserved: *mut c_void) -> i64>;
pub type mod_ctl0call_t = Option<unsafe extern "C" fn(ctl_args: *const u8, out_msg: *mut u8, outlen: c_int) -> i64>;
pub type mod_ctl1call_t = Option<unsafe extern "C" fn(a1: *mut c_void, a2: *mut c_void, a3: *mut c_void) -> i64>;
pub type mod_exitcall_t = Option<unsafe extern "C" fn(reserved: *mut c_void) -> i64>;

// Type aliases for backward compatibility
/// System call hook fargs (alias for hook_fargs0_t)
pub type HookFargs0 = hook_fargs0_t;
/// Watchpoint hardware breakpoint fargs (alias for hook_fargs4_t)
pub type HookFargs3 = hook_fargs4_t;

/// 读取当前 CPU core 的 sp_el0 寄存器，用于快速定位当前 task_struct 指针
#[inline(always)]
pub unsafe fn get_current() -> *mut c_void {
    let sp_el0: u64;
    core::arch::asm!("mrs {}, sp_el0", out(reg) sp_el0);
    sp_el0 as *mut c_void
}