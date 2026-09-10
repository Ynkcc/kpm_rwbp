#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

// 提供编译器需要的符号（内核会在运行时提供实际实现）
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() -> ! {
    loop {}
}

#[unsafe(no_mangle)]
pub extern "C" fn memcmp(_a: *const u8, _b: *const u8, _n: usize) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 { unsafe {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }
    if (dest as usize) < (src as usize) {
        for i in 0..n {
            core::ptr::write_volatile(dest.add(i), core::ptr::read_volatile(src.add(i)));
        }
    } else if (dest as usize) > (src as usize) {
        for i in (0..n).rev() {
            core::ptr::write_volatile(dest.add(i), core::ptr::read_volatile(src.add(i)));
        }
    }
    dest
}}

#[macro_use]
pub mod macros;

pub mod ffi;
pub mod sync;
pub mod utils;
pub mod mm;
pub mod hwbp;
pub mod hooks;
pub mod ipc;

use core::ffi::c_void;
use core::sync::atomic::Ordering;

// Metadata for the KernelPatch Loader
#[unsafe(no_mangle)]
#[unsafe(link_section = ".kpm.info")]
#[used]
pub static __kpm_info_name: [u8; 14] = *b"name=kpm_RWBP\0";

// 版本号 = git commit 计数（纯数字），由 build.rs 写入 kpm_version.bin
// 模板："version=<N>\0"，内容直接内联进字节数组，KP loader 可直接扰描
#[unsafe(no_mangle)]
#[unsafe(link_section = ".kpm.info")]
#[used]
pub static __kpm_info_version: [u8; include_bytes!(concat!(env!("OUT_DIR"), "/kpm_version.bin")).len()] =
    *include_bytes!(concat!(env!("OUT_DIR"), "/kpm_version.bin"));

#[unsafe(no_mangle)]
#[unsafe(link_section = ".kpm.info")]
#[used]
pub static __kpm_info_license: [u8; 15] = *b"license=GPL v2\0";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".kpm.info")]
#[used]
pub static __kpm_info_author: [u8; 11] = *b"author=ynk\0";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".kpm.info")]
#[used]
pub static __kpm_info_description: [u8; 51] = *b"description=Kernel Memory Reader & HWBP KPM (Rust)\0";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".kpm.init")]
#[used]
pub static mut __kpm_initcall_rwbp_init: unsafe extern "C" fn(*const u8, *const u8, *mut c_void) -> i64 = rwbp_init;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".kpm.exit")]
#[used]
pub static mut __kpm_exitcall_rwbp_exit: unsafe extern "C" fn(*mut c_void) -> i64 = rwbp_exit;

// KPM initialization callback
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text")]
pub unsafe extern "C" fn rwbp_init(_args: *const u8, _event: *const u8, _reserved: *mut c_void) -> i64 {
    unsafe {
        pr_info!("kpm_RWBP 模块初始化中...");

        // 初始化全局硬件断点管理链表，防止空指针解引用引发内核崩溃
        let bp_list_ptr = crate::hwbp::core::BP_LIST.get_ptr();
        (*bp_list_ptr).init();

        // 初始化内核符号
        if let Err(e) = crate::ffi::init_symbols() {
            pr_err!("初始化内核符号失败: {}", e);
            return e as i64;
        }

        // 初始化全局自旋锁，安全兼容 Debug 内核
        crate::hwbp::core::BP_LIST_LOCK.init();

        // 挂钩系统调用
        let ret_fstatfs = crate::ffi::hook_syscalln(
            44, // __NR_fstatfs
            3,  // narg
            crate::hooks::syscall::rwbp_fstatfs_hook as *const c_void,
            core::ptr::null(),
            core::ptr::null_mut(),
        );
        pr_info!("hook_syscalln fstatfs 返回: {}", ret_fstatfs);

        let ret_exit_group = crate::ffi::hook_syscalln(
            94, // __NR_exit_group
            1,  // narg
            crate::hooks::syscall::rwbp_exit_group_hook as *const c_void,
            core::ptr::null(),
            core::ptr::null_mut(),
        );
        pr_info!("hook_syscalln exit_group 返回: {}", ret_exit_group);

        // 挂载 OBSERVE 观测 hook（perf_event_open / ptrace）
        if let Err(e) = crate::hooks::observe::install_observe_hooks() {
            pr_warn!("observe 观测 hook 挂载失败: {}，跳过（其余功能不受影响）", e);
        }

        pr_info!("kpm_RWBP 初始化成功，系统调用 Hook 已就绪！");
        0
    }
}

// KPM exit callback
pub unsafe extern "C" fn rwbp_exit(_reserved: *mut c_void) -> i64 {
    unsafe {
        pr_info!("模块安全注销中...");

        crate::ffi::unhook_syscalln(
            44,
            crate::hooks::syscall::rwbp_fstatfs_hook as *const c_void,
            core::ptr::null(),
        );
        crate::ffi::unhook_syscalln(
            94,
            crate::hooks::syscall::rwbp_exit_group_hook as *const c_void,
            core::ptr::null(),
        );
        crate::hooks::watchpoint::remove_wp_hook();
        crate::hooks::observe::remove_observe_hooks();

        // 先注销和排队清理任务，触发 IN_FLIGHT 的递增和排队
        crate::hooks::syscall::handle_cleanup();

        // 先手动释放 KernelPatch 框架在 supercall 分发器中对本进程持有的 RCU 读锁，
        // 从而避免在此后的 msleep 中触发 Warning，并且打破 synchronize_rcu 的死锁环，使清理工作项可以顺利运行并递减 IN_FLIGHT
        if let Some(rcu_read_unlock_fn) = crate::sym!(rcu_read_unlock) {
            rcu_read_unlock_fn();
        }

        // 再循环等待所有在途的任务完全退空
        while crate::hwbp::core::IN_FLIGHT.load(Ordering::SeqCst) > 0 {
            pr_info!("模块注销等待中... 在途工作任务数: {}", crate::hwbp::core::IN_FLIGHT.load(Ordering::SeqCst));
            if let Some(msleep_fn) = sym!(msleep) {
                msleep_fn(10);
            }
        }

        // 清理所有的 Ghost 内存，防范物理页泄漏
        crate::ipc::dispatcher::cleanup_ghost_pool();
 
        // 重新获取 RCU 读锁，以满足 KernelPatch 卸载框架外层对 rcu_read_unlock() 的对称调用
        if let Some(rcu_read_lock_fn) = crate::sym!(rcu_read_lock) {
            rcu_read_lock_fn();
        }

        pr_info!("模块已安全卸载...");
        0
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // 尽早暴露错误：利用上文修改后的宏输出详细的 Panic 文件与行号信息
    crate::pr_err!("FATAL KERNEL PANIC: {}", info);

    unsafe {
        // 利用内核 dump_stack 打印出完整的调用链，精确定位死机上下文
        if let Some(dump_fn) = crate::sym!(dump_stack) {
            dump_fn();
        }

        // 确保日志能顺利刷写到 dmesg
        if let Some(msleep_fn) = crate::sym!(msleep) {
            // 假设当前非硬中断上下文（多数由于指针或业务逻辑引发的 panic 处于进程级）
            msleep_fn(50);
        }

        // 移除原有的 brk #1，防止 panic_on_oops 生效导致设备直接关机或重启
        // core::arch::asm!("brk #1", options(nostack, nomem));
    }

    // 通过死循环仅将当前出问题的内核线程挂起（Task Hang）。
    // 其余无直接依赖的系统进程将继续存活，从而使你能够通过 adb shell 或串口执行 dmesg 查看日志。
    loop {}
}
