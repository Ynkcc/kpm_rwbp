// 共享内存请求的核心分发逻辑

use crate::mm::{read_process_memory, write_process_memory};
use crate::hwbp::core::{register_hwbp, unregister_hwbp, unregister_all_hwbp, read_hwbp_info};
use crate::ipc::protocol::*;
use crate::utils::Error;
use core::ffi::c_void;
use zerocopy::FromBytes;

pub unsafe fn rwbp_dispatch(shm: *mut ShmChannel) -> i64 {
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
        _ => {
            pr_warn!("未知的命令: {}", cmd);
            Error::EINVAL as i64
        }
    }
}
