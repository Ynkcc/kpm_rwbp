// 系统调用拦截 Hook 逻辑与管理
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::ffi::{get_current, HookFargs0};

// 全局控制变量
pub static SHM_USER_VADDR: AtomicU64 = AtomicU64::new(0);
pub static CURRENT_CONTROL_TASK: AtomicU64 = AtomicU64::new(0);

// Syscall 参数提取辅助函数
#[inline(always)]
pub unsafe fn get_syscall_arg(hook_fargs: *mut c_void, n: usize) -> u64 {
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
}

#[inline(always)]
pub unsafe fn syscall_set_retval(hook_fargs: *mut c_void, val: u64) {
    let fargs = hook_fargs as *mut HookFargs0;
    (*fargs).ret = val;
}

#[inline(always)]
pub unsafe fn syscall_set_handled(hook_fargs: *mut c_void, handled: bool) {
    let fargs = hook_fargs as *mut HookFargs0;
    (*fargs).skip_origin = if handled { 1 } else { 0 };
}

pub unsafe fn handle_cleanup() {
    pr_info!("控制端进程已退出，开始自动清理内核资源...");
    let _ = crate::hwbp::core::unregister_all_hwbp();
    SHM_USER_VADDR.store(0, Ordering::SeqCst);
}

// __NR_fstatfs (44) 系统调用拦截 Hook
pub unsafe extern "C" fn rwbp_fstatfs_hook(args: *mut crate::ffi::hook_fargs4_t, _udata: *mut c_void) {
    let arg0 = get_syscall_arg(args as *mut c_void, 0);
    let arg1 = get_syscall_arg(args as *mut c_void, 1);
    pr_info!("rwbp_fstatfs_hook: arg0=0x{:x}, arg1=0x{:x}", arg0, arg1);

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

    // 3. 握手与请求分发逻辑
    let shm_user_vaddr = SHM_USER_VADDR.load(Ordering::SeqCst);
    if shm_user_vaddr == 0 {
        pr_info!("收到共享内存通道握手请求，用户虚拟地址: 0x{:x}", arg0);
        let mut magic_val = 0u32;
        let copy_res = crate::mm::copy_from_user(
            core::slice::from_raw_parts_mut(&mut magic_val as *mut u32 as *mut u8, 4),
            arg0 as *const c_void,
        );

        if copy_res.is_ok() && magic_val == crate::ipc::SHM_MAGIC {
            SHM_USER_VADDR.store(arg0, Ordering::SeqCst);
            CURRENT_CONTROL_TASK.store(current as u64, Ordering::SeqCst);
            // 返回 0 表示成功，测试程序会把它当作有效返回值
            syscall_set_retval(args as *mut c_void, 0);
            syscall_set_handled(args as *mut c_void, true);
            pr_info!("成功绑定共享内存通道，虚拟地址: 0x{:x}", arg0);
        } else {
            pr_warn!("共享内存 Magic 校验失败！magic=0x{:x}, err={:?}", magic_val, copy_res);
            syscall_set_retval(args as *mut c_void, -22i64 as u64); // -EINVAL
            syscall_set_handled(args as *mut c_void, true);
        }
    } else {
        let malloc_fn = match crate::sym!(__kmalloc) {
            Some(f) => f,
            None => {
                syscall_set_retval(args as *mut c_void, -38i64 as u64); // -ENOSYS
                syscall_set_handled(args as *mut c_void, true);
                return;
            }
        };
        let kfree_fn = match crate::sym!(kfree) {
            Some(f) => f,
            None => {
                syscall_set_retval(args as *mut c_void, -38i64 as u64); // -ENOSYS
                syscall_set_handled(args as *mut c_void, true);
                return;
            }
        };

        // 动态分配缓冲区，避免内核栈溢出
        let local_shm = malloc_fn(core::mem::size_of::<crate::ipc::ShmChannel>(), 0xcc0u32) as *mut crate::ipc::ShmChannel;
        if local_shm.is_null() {
            syscall_set_retval(args as *mut c_void, -12i64 as u64); // -ENOMEM
            syscall_set_handled(args as *mut c_void, true);
            return;
        }

        let copy_res = crate::mm::copy_from_user(
            core::slice::from_raw_parts_mut(local_shm as *mut u8, core::mem::size_of::<crate::ipc::ShmChannel>()),
            shm_user_vaddr as *const c_void,
        );

        if copy_res.is_ok() {
            if (*local_shm).status == 1 {
                (*local_shm).status = 2; // processing
                let ret = crate::ipc::rwbp_dispatch(local_shm);
                (*local_shm).retval = ret as i32;
                (*local_shm).status = 0; // done

                let write_back_sz = core::mem::offset_of!(crate::ipc::ShmChannel, payload) + (*local_shm).data_size as usize;
                let _ = crate::mm::copy_to_user(
                    shm_user_vaddr as *mut c_void,
                    core::slice::from_raw_parts(local_shm as *const u8, write_back_sz),
                );
            }
        } else {
            pr_warn!("读取用户态共享内存失败: err={:?}", copy_res);
        }

        kfree_fn(local_shm as *const c_void);
        syscall_set_retval(args as *mut c_void, 0);
        syscall_set_handled(args as *mut c_void, true);
    }
}

// __NR_exit_group (94) 系统调用拦截 Hook，在控制进程退出时清理资源
pub unsafe extern "C" fn rwbp_exit_group_hook(_args: *mut crate::ffi::hook_fargs4_t, _udata: *mut c_void) {
    let current = get_current();
    let ctrl_task = CURRENT_CONTROL_TASK.load(Ordering::SeqCst);
    if ctrl_task != 0 && ctrl_task == current as u64 {
        handle_cleanup();
        CURRENT_CONTROL_TASK.store(0, Ordering::SeqCst);
    }
}
