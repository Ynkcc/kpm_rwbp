// Watchpoint 拦截钩子安装与管理

use crate::ffi::lookup_sym;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// 安装 watchpoint_handler 拦截钩子
/// callback 是 scheme 3 watchpoint 触发时调用的回调函数（作为原始指针传入）
pub unsafe fn install_wp_hook(callback: *const c_void) {
    if HOOK_INSTALLED.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_err() {
        return;
    }

    let wp_handler_addr: Option<*mut c_void> = lookup_sym("watchpoint_handler");
    if let Some(addr) = wp_handler_addr {
        // hook_wrap 是 KP 导出的直接 extern 函数
        let err = crate::ffi::hook_wrap(
            addr,
            3,
            callback,
            core::ptr::null(),
            core::ptr::null_mut(),
        );
        if err == 0 {
            pr_info!("watchpoint_handler hooked successfully!");
        } else {
            HOOK_INSTALLED.store(false, Ordering::SeqCst);
            pr_err!("Failed to hook watchpoint_handler, err={}", err);
        }
    } else {
        HOOK_INSTALLED.store(false, Ordering::SeqCst);
        pr_err!("watchpoint_handler symbol not found!");
    }
}

/// 卸载 watchpoint_handler 拦截钩子
pub unsafe fn remove_wp_hook() {
    if HOOK_INSTALLED.compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
        let wp_handler_addr: Option<*mut c_void> = lookup_sym("watchpoint_handler");
        if let Some(addr) = wp_handler_addr {
            // hook_unwrap_remove 是 KP 导出的直接 extern 函数
            crate::ffi::hook_unwrap_remove(
                addr,
                crate::hwbp::core::before_watchpoint_handler as *const c_void,
                core::ptr::null(),
                1,
            );
        }
    }
}
