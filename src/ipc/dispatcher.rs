// 共享内存请求的核心分发逻辑

use crate::mm::{read_process_memory, write_process_memory};
use crate::mm::ghost::{ghost_alloc, ghost_free, ghost_write, ghost_sync_icache, GhostPage};
use crate::hwbp::core::{
    register_hwbp, unregister_hwbp, unregister_all_hwbp, read_hwbp_info,
    get_hwbp_caps, enable_hwbp, disable_hwbp, query_hwbp_status,
};
use crate::ipc::protocol::*;
use crate::utils::Error;
use crate::sync::RawSpinlock;
use core::ffi::c_void;
use zerocopy::FromBytes;

static mut GHOST_POOL: [Option<GhostPage>; 16] = [
    None, None, None, None, None, None, None, None,
    None, None, None, None, None, None, None, None,
];
static GHOST_POOL_LOCK: RawSpinlock = RawSpinlock::new();

pub unsafe fn cleanup_ghost_pool() {
    let mut pages = [
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
    ];
    {
        let _guard = GHOST_POOL_LOCK.lock();
        unsafe {
            for i in 0..16 {
                pages[i] = GHOST_POOL[i].take();
            }
        }
    }
    for i in 0..16 {
        if let Some(mut gp) = pages[i].take() {
            unsafe {
                let _ = ghost_free(&mut gp);
            }
        }
    }
}

pub unsafe fn rwbp_dispatch(shm: *mut ShmChannel) -> i64 {
    unsafe {
        if shm.is_null() || (*shm).magic != SHM_MAGIC {
            pr_warn!("rwbp_dispatch: 无效的共享内存魔数或空指针！");
            return Error::EINVAL as i64;
        }

        let shm_ref = &mut *shm;
        let cmd = shm_ref.cmd;
        pr_info!("rwbp_dispatch 收到命令: cmd={}", cmd);

        match cmd {
            OP_READ_MEM => {
                let Ok((rcmd, _)) = CopyMemory::read_from_prefix(&shm_ref.payload[..]) else {
                    pr_warn!("解析 CopyMemory 结构失败");
                    return Error::EINVAL as i64;
                };

                pr_info!(
                    "读内存参数: pid={}, addr=0x{:x}, size={}",
                    rcmd.pid,
                    rcmd.addr,
                    rcmd.size
                );

                if rcmd.size > shm_ref.payload.len() as u64 {
                    return Error::EINVAL as i64;
                }

                let dest_user_addr = shm_ref.payload.as_mut_ptr() as u64;
                match read_process_memory(rcmd.pid, rcmd.addr, rcmd.size, dest_user_addr) {
                    Ok(read_res) => {
                        pr_info!("read_process_memory 成功返回: {}", read_res);
                        shm_ref.data_size = read_res as u32;
                        read_res as i64
                    }
                    Err(err) => {
                        pr_warn!("read_process_memory 失败: {}", err);
                        shm_ref.data_size = 0;
                        err as i64
                    }
                }
            }
            OP_WRITE_MEM => {
                let Ok((wcmd, _)) = WriteMemory::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                pr_info!(
                    "写内存参数: pid={}, addr=0x{:x}, size={}",
                    wcmd.pid,
                    wcmd.addr,
                    wcmd.size
                );

                match write_process_memory(wcmd.pid, wcmd.addr, wcmd.size, wcmd.buffer) {
                    Ok(write_res) => {
                        pr_info!("write_process_memory 成功返回: {}", write_res);
                        shm_ref.data_size = 0;
                        write_res as i64
                    }
                    Err(err) => {
                        pr_warn!("write_process_memory 失败: {}", err);
                        shm_ref.data_size = 0;
                        err as i64
                    }
                }
            }
            OP_SET_HW_BREAKPOINT => {
                let Ok((bcmd, _)) = HwBreakpointCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                match register_hwbp(bcmd.pid, bcmd.addr, bcmd.bp_type, bcmd.len, bcmd.scheme) {
                    Ok(_) => 0,
                    Err(err) => err as i64,
                }
            }
            OP_REMOVE_HW_BREAKPOINT => {
                let Ok((bcmd, _)) = HwBreakpointCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                match unregister_hwbp(bcmd.pid, bcmd.addr) {
                    Ok(_) => 0,
                    Err(err) => err as i64,
                }
            }
            OP_REMOVE_ALL_HW_BREAKPOINT => {
                match unregister_all_hwbp() {
                    Ok(_) => 0,
                    Err(err) => err as i64,
                }
            }
            OP_READ_HW_BP_INFO => {
                let Ok((icmd, _)) = HwbpInfoCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                let max_allowed = shm_ref.payload.len() / core::mem::size_of::<HwbpHitItem>();
                let request_count = core::cmp::min(icmd.max_count, max_allowed as u64);

                let mut actual_count = 0;
                match read_hwbp_info(
                    icmd.pid,
                    request_count,
                    shm_ref.payload.as_mut_ptr() as *mut c_void,
                    &mut actual_count,
                ) {
                    Ok(_) => {
                        shm_ref.data_size = (actual_count * core::mem::size_of::<HwbpHitItem>() as u64) as u32;
                        0
                    }
                    Err(err) => err as i64,
                }
            }
            OP_GET_HW_BREAKPOINT_CAPS => {
                let (brps, wrps) = unsafe { get_hwbp_caps() };
                let caps = HwbpCaps {
                    max_breakpoints: brps,
                    max_watchpoints: wrps,
                };
                shm_ref.data_size = core::mem::size_of::<HwbpCaps>() as u32;
                use zerocopy::IntoBytes;
                shm_ref.payload[..core::mem::size_of::<HwbpCaps>()].copy_from_slice(caps.as_bytes());
                0
            }
            OP_ENABLE_HW_BREAKPOINT => {
                let Ok((bcmd, _)) = HwBreakpointCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                match enable_hwbp(bcmd.pid, bcmd.addr) {
                    Ok(_) => 0,
                    Err(err) => err as i64,
                }
            }
            OP_DISABLE_HW_BREAKPOINT => {
                let Ok((bcmd, _)) = HwBreakpointCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                match disable_hwbp(bcmd.pid, bcmd.addr) {
                    Ok(_) => 0,
                    Err(err) => err as i64,
                }
            }
            OP_QUERY_HW_BREAKPOINT_STATUS => {
                let Ok((mut qcmd, _)) = HwbpQueryCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                match query_hwbp_status(qcmd.pid, qcmd.addr, &mut qcmd) {
                    Ok(_) => {
                        shm_ref.data_size = core::mem::size_of::<HwbpQueryCmd>() as u32;
                        use zerocopy::IntoBytes;
                        shm_ref.payload[..core::mem::size_of::<HwbpQueryCmd>()].copy_from_slice(qcmd.as_bytes());
                        0
                    }
                    Err(err) => err as i64,
                }
            }
            OP_GHOST_ALLOC => {
                let Ok((acmd, _)) = GhostAllocCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                let mut slot_idx = None;
                {
                    let _guard = GHOST_POOL_LOCK.lock();
                    unsafe {
                        for i in 0..16 {
                            if GHOST_POOL[i].is_none() {
                                GHOST_POOL[i] = Some(GhostPage::placeholder());
                                slot_idx = Some(i);
                                break;
                            }
                        }
                    }
                }

                let Some(idx) = slot_idx else {
                    return Error::ENOSPC as i64;
                };

                unsafe {
                    let task = {
                        let find_fn = crate::sym_must!(find_task_by_vpid);
                        find_fn(acmd.pid as i32)
                    };
                    if task.is_null() {
                        let _guard = GHOST_POOL_LOCK.lock();
                        GHOST_POOL[idx] = None;
                        return Error::ESRCH as i64;
                    }

                    let mm = {
                        let get_mm_fn = crate::sym_must!(get_task_mm);
                        get_mm_fn(task)
                    };
                    if mm.is_null() {
                        let _guard = GHOST_POOL_LOCK.lock();
                        GHOST_POOL[idx] = None;
                        return Error::EFAULT as i64;
                    }

                    let mut gp = GhostPage::default();
                    match ghost_alloc(task, mm, acmd.near_addr, acmd.range, acmd.pte_template, acmd.num_pages, &mut gp) {
                        Ok(_) => {
                            let alloc_vaddr = gp.vaddr;
                            {
                                let _guard = GHOST_POOL_LOCK.lock();
                                GHOST_POOL[idx] = Some(gp);
                            }

                            shm_ref.data_size = core::mem::size_of::<u64>() as u32;
                            let vaddr_bytes = alloc_vaddr.to_ne_bytes();
                            shm_ref.payload[..8].copy_from_slice(&vaddr_bytes);

                            let mmput_fn = crate::sym_must!(mmput);
                            mmput_fn(mm);
                            alloc_vaddr as i64
                        }
                        Err(err) => {
                            {
                                let _guard = GHOST_POOL_LOCK.lock();
                                GHOST_POOL[idx] = None;
                            }
                            let mmput_fn = crate::sym_must!(mmput);
                            mmput_fn(mm);
                            err as i64
                        }
                    }
                }
            }
            OP_GHOST_FREE => {
                let Ok((fcmd, _)) = GhostFreeCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                let mut target_gp = None;
                let mut target_idx = None;
                {
                    let _guard = GHOST_POOL_LOCK.lock();
                    unsafe {
                        for i in 0..16 {
                            if let Some(ref gp) = GHOST_POOL[i] {
                                if !gp.is_placeholder() && gp.vaddr == fcmd.vaddr {
                                    target_gp = GHOST_POOL[i].take();
                                    target_idx = Some(i);
                                    break;
                                }
                            }
                        }
                    }
                }

                let Some(mut gp) = target_gp else {
                    return Error::ENOENT as i64;
                };

                unsafe {
                    match ghost_free(&mut gp) {
                        Ok(_) => 0,
                        Err(err) => {
                            let _guard = GHOST_POOL_LOCK.lock();
                            let idx = target_idx.unwrap();
                            if GHOST_POOL[idx].is_none() {
                                GHOST_POOL[idx] = Some(gp);
                            }
                            err as i64
                        }
                    }
                }
            }
            OP_GHOST_WRITE => {
                let Ok((wcmd, _)) = GhostWriteCmd::read_from_prefix(&shm_ref.payload[..]) else {
                    return Error::EINVAL as i64;
                };

                let size = wcmd.size as usize;
                if size == 0 {
                    return 0;
                }

                unsafe {
                    let kmalloc_fn = crate::sym_must!(kmalloc);
                    let kfree_fn = crate::sym_must!(kfree);

                    let kbuf = kmalloc_fn(size, 0xcc0); // GFP_KERNEL
                    if kbuf.is_null() {
                        return Error::ENOMEM as i64;
                    }

                    let kbuf_slice = core::slice::from_raw_parts_mut(kbuf as *mut u8, size);
                    match crate::mm::copy_from_user(kbuf_slice, wcmd.buffer as *const c_void) {
                        Ok(_) => {
                            let mut write_res = Ok(());
                            {
                                let _guard = GHOST_POOL_LOCK.lock();
                                let mut gp_idx = None;
                                for i in 0..16 {
                                    if let Some(ref gp) = GHOST_POOL[i] {
                                        if !gp.is_placeholder() && gp.vaddr == wcmd.vaddr {
                                            gp_idx = Some(i);
                                            break;
                                        }
                                    }
                                }

                                if let Some(idx) = gp_idx {
                                    let gp_ref = GHOST_POOL[idx].as_ref().unwrap();
                                    write_res = ghost_write(gp_ref, wcmd.offset, kbuf_slice);
                                    if write_res.is_ok() {
                                        ghost_sync_icache(gp_ref);
                                    }
                                } else {
                                    write_res = Err(Error::ENOENT);
                                }
                            }

                            kfree_fn(kbuf);
                            match write_res {
                                Ok(_) => 0,
                                Err(err) => err as i64,
                            }
                        }
                        Err(err) => {
                            kfree_fn(kbuf);
                            err as i64
                        }
                    }
                }
            }
            _ => {
                pr_warn!("未知的命令: {}", cmd);
                Error::EINVAL as i64
            }
        }
    }
}
