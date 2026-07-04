// 系统调用拦截 Hook 逻辑与管理
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::ffi::{get_current, HookFargs0};
use zerocopy::IntoBytes;

// 全局控制变量
pub static SHM_USER_VADDR: AtomicU64 = AtomicU64::new(0);
pub static CURRENT_CONTROL_TGID: AtomicU64 = AtomicU64::new(0);

// Syscall 参数提取辅助函数
#[inline(always)]
pub unsafe fn get_syscall_arg(hook_fargs: *mut c_void, n: usize) -> u64 { unsafe {
    let fargs = hook_fargs as *mut HookFargs0;
    if crate::ffi::has_syscall_wrapper != 0 {
        let pt_regs = (*fargs).args[0] as *const crate::hwbp::core::PtRegs;
        if pt_regs.is_null() {
            0
        } else {
            (*pt_regs).regs[n]
        }
    } else {
        (*fargs).args[n]
    }
}}

#[inline(always)]
pub unsafe fn syscall_set_retval(hook_fargs: *mut c_void, val: u64) { unsafe {
    let fargs = hook_fargs as *mut HookFargs0;
    (*fargs).ret = val;
}}

#[inline(always)]
pub unsafe fn syscall_set_handled(hook_fargs: *mut c_void, handled: bool) { unsafe {
    let fargs = hook_fargs as *mut HookFargs0;
    (*fargs).skip_origin = if handled { 1 } else { 0 };
}}

pub unsafe fn handle_cleanup() {
    pr_info!("控制端进程已退出，开始自动清理内核资源...");
    let _ = crate::hwbp::core::unregister_all_hwbp();
    unsafe {
        crate::ipc::dispatcher::cleanup_ghost_pool();
    }
    SHM_USER_VADDR.store(0, Ordering::SeqCst);
}

// __NR_fstatfs (44) 系统调用拦截 Hook
pub unsafe extern "C" fn rwbp_fstatfs_hook(args: *mut crate::ffi::hook_fargs4_t, _udata: *mut c_void) { unsafe {
    let arg0 = get_syscall_arg(args as *mut c_void, 0);
    let arg1 = get_syscall_arg(args as *mut c_void, 1);

    // 1. 检查控制魔数 - arg1 应该是 0xDEADC0DE
    if arg1 != 0xDEADC0DEu64 {
        return;
    }

    // 2. 验证特权用户 (caller_uid == 0)
    let current = get_current();
    let cred_addr = *( (current as usize + crate::ffi::task_struct_offset.cred_offset as usize) as *const usize );
    let caller_uid = *( (cred_addr + crate::ffi::cred_offset.uid_offset as usize) as *const u32 );
    if caller_uid != 0 {
        return;
    }

    let tgid = *( (current as usize + crate::ffi::task_struct_offset.tgid_offset as usize) as *const u32 );
    let cmd = get_syscall_arg(args as *mut c_void, 2) as u32;
    let user_ptr = arg0 as *const c_void;

    let ret: i64 = match cmd {
        crate::ipc::protocol::OP_READ_MEM => {
            let mut rcmd = core::mem::zeroed::<crate::ipc::protocol::CopyMemory>();
            let rcmd_slice = core::slice::from_raw_parts_mut(&mut rcmd as *mut _ as *mut u8, core::mem::size_of::<crate::ipc::protocol::CopyMemory>());
            if let Err(err) = crate::mm::copy_from_user(rcmd_slice, user_ptr) {
                err as i64
            } else {
                match crate::mm::read_process_memory(rcmd.pid, rcmd.addr, rcmd.size, rcmd.buffer) {
                    Ok(read_res) => read_res as i64,
                    Err(err) => err as i64,
                }
            }
        }
        crate::ipc::protocol::OP_WRITE_MEM => {
            let mut wcmd = core::mem::zeroed::<crate::ipc::protocol::WriteMemory>();
            let wcmd_slice = core::slice::from_raw_parts_mut(&mut wcmd as *mut _ as *mut u8, core::mem::size_of::<crate::ipc::protocol::WriteMemory>());
            if let Err(err) = crate::mm::copy_from_user(wcmd_slice, user_ptr) {
                err as i64
            } else {
                match crate::mm::write_process_memory(wcmd.pid, wcmd.addr, wcmd.size, wcmd.buffer) {
                    Ok(write_res) => write_res as i64,
                    Err(err) => err as i64,
                }
            }
        }
        crate::ipc::protocol::OP_SET_HW_BREAKPOINT => {
            let mut bcmd = core::mem::zeroed::<crate::ipc::protocol::HwBreakpointCmd>();
            let bcmd_slice = core::slice::from_raw_parts_mut(&mut bcmd as *mut _ as *mut u8, core::mem::size_of::<crate::ipc::protocol::HwBreakpointCmd>());
            if let Err(err) = crate::mm::copy_from_user(bcmd_slice, user_ptr) {
                err as i64
            } else {
                let _ = CURRENT_CONTROL_TGID.compare_exchange(
                    0,
                    tgid as u64,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                match crate::hwbp::core::register_hwbp(bcmd.pid, bcmd.addr, bcmd.bp_type, bcmd.len, bcmd.scheme) {
                    Ok(_) => 0,
                    Err(err) => err as i64,
                }
            }
        }
        crate::ipc::protocol::OP_REMOVE_HW_BREAKPOINT => {
            let mut bcmd = core::mem::zeroed::<crate::ipc::protocol::HwBreakpointCmd>();
            let bcmd_slice = core::slice::from_raw_parts_mut(&mut bcmd as *mut _ as *mut u8, core::mem::size_of::<crate::ipc::protocol::HwBreakpointCmd>());
            if let Err(err) = crate::mm::copy_from_user(bcmd_slice, user_ptr) {
                err as i64
            } else {
                match crate::hwbp::core::unregister_hwbp(bcmd.pid, bcmd.addr) {
                    Ok(_) => 0,
                    Err(err) => err as i64,
                }
            }
        }
        crate::ipc::protocol::OP_REMOVE_ALL_HW_BREAKPOINT => {
            match crate::hwbp::core::unregister_all_hwbp() {
                Ok(_) => 0,
                Err(err) => err as i64,
            }
        }
        crate::ipc::protocol::OP_READ_HW_BP_INFO => {
            let mut icmd = core::mem::zeroed::<crate::ipc::protocol::HwbpInfoCmd>();
            let icmd_slice = core::slice::from_raw_parts_mut(&mut icmd as *mut _ as *mut u8, core::mem::size_of::<crate::ipc::protocol::HwbpInfoCmd>());
            if let Err(err) = crate::mm::copy_from_user(icmd_slice, user_ptr) {
                err as i64
            } else {
                let mut actual_count = 0;
                match crate::hwbp::core::read_hwbp_info(
                    icmd.pid,
                    icmd.max_count,
                    icmd.user_buf as *mut c_void,
                    &mut actual_count,
                ) {
                    Ok(_) => {
                        let actual_count_offset = core::mem::offset_of!(crate::ipc::protocol::HwbpInfoCmd, actual_count);
                        let dest_ptr = (arg0 + actual_count_offset as u64) as *mut c_void;
                        let src_slice = &actual_count.to_ne_bytes();
                        if let Err(err) = crate::mm::copy_to_user(dest_ptr, src_slice) {
                            err as i64
                        } else {
                            0
                        }
                    }
                    Err(err) => err as i64,
                }
            }
        }
        crate::ipc::protocol::OP_GET_HW_BREAKPOINT_CAPS => {
            let (brps, wrps) = crate::hwbp::core::get_hwbp_caps();
            let caps = crate::ipc::protocol::HwbpCaps {
                max_breakpoints: brps,
                max_watchpoints: wrps,
            };
            let caps_slice = caps.as_bytes();
            if let Err(err) = crate::mm::copy_to_user(user_ptr as *mut c_void, caps_slice) {
                err as i64
            } else {
                0
            }
        }
        crate::ipc::protocol::OP_ENABLE_HW_BREAKPOINT | crate::ipc::protocol::OP_DISABLE_HW_BREAKPOINT => {
            let mut bcmd = core::mem::zeroed::<crate::ipc::protocol::HwBreakpointCmd>();
            let bcmd_slice = core::slice::from_raw_parts_mut(&mut bcmd as *mut _ as *mut u8, core::mem::size_of::<crate::ipc::protocol::HwBreakpointCmd>());
            if let Err(err) = crate::mm::copy_from_user(bcmd_slice, user_ptr) {
                err as i64
            } else {
                if cmd == crate::ipc::protocol::OP_ENABLE_HW_BREAKPOINT {
                    match crate::hwbp::core::enable_hwbp(bcmd.pid, bcmd.addr) {
                        Ok(_) => 0,
                        Err(err) => err as i64,
                    }
                } else {
                    match crate::hwbp::core::disable_hwbp(bcmd.pid, bcmd.addr) {
                        Ok(_) => 0,
                        Err(err) => err as i64,
                    }
                }
            }
        }
        crate::ipc::protocol::OP_QUERY_HW_BREAKPOINT_STATUS => {
            let mut qcmd = core::mem::zeroed::<crate::ipc::protocol::HwbpQueryCmd>();
            let qcmd_slice = core::slice::from_raw_parts_mut(&mut qcmd as *mut _ as *mut u8, core::mem::size_of::<crate::ipc::protocol::HwbpQueryCmd>());
            if let Err(err) = crate::mm::copy_from_user(qcmd_slice, user_ptr) {
                err as i64
            } else {
                match crate::hwbp::core::query_hwbp_status(qcmd.pid, qcmd.addr, &mut qcmd) {
                    Ok(_) => {
                        if let Err(err) = crate::mm::copy_to_user(user_ptr as *mut c_void, qcmd.as_bytes()) {
                            err as i64
                        } else {
                            0
                        }
                    }
                    Err(err) => err as i64,
                }
            }
        }
        crate::ipc::protocol::OP_GHOST_ALLOC |
        crate::ipc::protocol::OP_GHOST_FREE |
        crate::ipc::protocol::OP_GHOST_WRITE => {
            let copy_size = match cmd {
                crate::ipc::protocol::OP_GHOST_ALLOC => core::mem::size_of::<crate::ipc::protocol::GhostAllocCmd>(),
                crate::ipc::protocol::OP_GHOST_FREE => core::mem::size_of::<crate::ipc::protocol::GhostFreeCmd>(),
                crate::ipc::protocol::OP_GHOST_WRITE => core::mem::size_of::<crate::ipc::protocol::GhostWriteCmd>(),
                _ => 0,
            };
            let mut shm_temp = core::mem::zeroed::<crate::ipc::protocol::ShmChannel>();
            shm_temp.magic = crate::ipc::protocol::SHM_MAGIC;
            shm_temp.cmd = cmd;
            let payload_slice = core::slice::from_raw_parts_mut(shm_temp.payload.as_mut_ptr(), copy_size);
            if let Err(err) = crate::mm::copy_from_user(payload_slice, user_ptr) {
                err as i64
            } else {
                crate::ipc::dispatcher::rwbp_dispatch(&mut shm_temp)
            }
        }
        _ => -22, // -EINVAL
    };

    syscall_set_retval(args as *mut c_void, ret as u64);
    syscall_set_handled(args as *mut c_void, true);
}}

// __NR_exit_group (94) 系统调用拦截 Hook，在控制进程退出时清理资源
pub unsafe extern "C" fn rwbp_exit_group_hook(_args: *mut crate::ffi::hook_fargs4_t, _udata: *mut c_void) { unsafe {
    let current = get_current();
    let tgid = *( (current as usize + crate::ffi::task_struct_offset.tgid_offset as usize) as *const u32 );
    let ctrl_tgid = CURRENT_CONTROL_TGID.load(Ordering::SeqCst);
    if ctrl_tgid != 0 && ctrl_tgid == tgid as u64 {
        handle_cleanup();
        CURRENT_CONTROL_TGID.store(0, Ordering::SeqCst);
    }
}}
