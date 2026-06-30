use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering, AtomicU64};

static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);
static INSTALLED_CALLBACK: AtomicU64 = AtomicU64::new(0);

/// 安装 watchpoint_handler 拦截钩子
/// callback 是 scheme 3 watchpoint 触发时调用的回调函数（作为原始指针传入）
pub unsafe fn install_wp_hook(callback: *const c_void) { unsafe {
    if HOOK_INSTALLED.compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed).is_err() {
        return;
    }

    let wp_handler_addr = crate::sym!(watchpoint_handler);
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
            INSTALLED_CALLBACK.store(callback as u64, Ordering::SeqCst);
            pr_info!("watchpoint_handler hooked successfully!");
        } else {
            HOOK_INSTALLED.store(false, Ordering::SeqCst);
            pr_err!("Failed to hook watchpoint_handler, err={}", err);
        }
    } else {
        HOOK_INSTALLED.store(false, Ordering::SeqCst);
        pr_err!("watchpoint_handler symbol not found!");
    }
}}

/// 卸载 watchpoint_handler 拦截钩子
pub unsafe fn remove_wp_hook() { unsafe {
    if HOOK_INSTALLED.compare_exchange(true, false, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
        let wp_handler_addr = crate::sym!(watchpoint_handler);
        let callback = INSTALLED_CALLBACK.swap(0, Ordering::SeqCst) as *const c_void;
        if let Some(addr) = wp_handler_addr {
            if !callback.is_null() {
                // hook_unwrap_remove 是 KP 导出的直接 extern 函数
                crate::ffi::hook_unwrap_remove(
                    addr,
                    callback,
                    core::ptr::null(),
                    1,
                );
            }
        }
    }
}}
