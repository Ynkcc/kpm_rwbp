// 进程虚拟内存读写与内核/用户空间数据拷贝

use core::ffi::c_void;

/// 将内核数据拷贝到用户空间虚拟地址
pub fn copy_to_user(to: *mut c_void, from: &[u8]) -> Result<(), i32> {
    if to.is_null() {
        return Err(-14); // EFAULT
    }
    unsafe {
        if let Some(copy_fn) = crate::sym!(__arch_copy_to_user) {
            let ret = copy_fn(to, from.as_ptr() as *const c_void, from.len() as u64);
            if ret == 0 {
                return Ok(());
            }
        }
        if let Some(copy_fn) = crate::sym!(copy_to_user_nofault) {
            let ret = copy_fn(to, from.as_ptr() as *const c_void, from.len());
            if ret == 0 {
                return Ok(());
            }
        }
    }
    Err(-14) // EFAULT
}

/// 从用户空间虚拟地址拷贝数据到内核缓冲区
pub fn copy_from_user(to: &mut [u8], from: *const c_void) -> Result<(), i32> {
    if from.is_null() {
        return Err(-14); // EFAULT
    }
    unsafe {
        if let Some(copy_fn) = crate::sym!(__arch_copy_from_user) {
            let ret = copy_fn(to.as_mut_ptr() as *mut c_void, from, to.len() as u64);
            if ret == 0 {
                return Ok(());
            }
        }
        if let Some(copy_fn) = crate::sym!(copy_from_user_nofault) {
            let ret = copy_fn(to.as_mut_ptr() as *mut c_void, from, to.len());
            if ret == 0 {
                return Ok(());
            }
        }
    }
    Err(-14) // EFAULT
}

/// 读取指定进程的用户虚拟内存数据，并安全写入另一个用户态虚拟地址（或内核虚拟地址）
pub fn read_process_memory(pid: u32, vaddr: u64, size: u64, dest_user_addr: u64) -> Result<usize, i32> {
    let task = unsafe {
        if let Some(find_fn) = crate::sym!(find_task_by_vpid) {
            find_fn(pid as i32)
        } else {
            core::ptr::null_mut()
        }
    };
    if task.is_null() {
        return Err(-3); // ESRCH
    }

    let access_fn = match crate::sym!(access_process_vm) {
        Some(f) => f,
        None => return Err(-38), // ENOSYS
    };

    let mut remaining = size as usize;
    let mut cur_vaddr = vaddr;
    let mut cur_outbuf = dest_user_addr;
    let mut total_copied = 0;
    let mut kbuf = [0u8; 4096];

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, kbuf.len());
        let read_bytes = unsafe {
            access_fn(task, cur_vaddr, kbuf.as_mut_ptr() as *mut c_void, chunk as i32, 0)
        };
        if read_bytes <= 0 {
            break;
        }

        let copied = read_bytes as usize;
        let copy_err = if cur_outbuf >= 0xffff000000000000u64 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    kbuf.as_ptr(),
                    cur_outbuf as *mut u8,
                    copied,
                );
            }
            0
        } else {
            match copy_to_user(cur_outbuf as *mut c_void, &kbuf[..copied]) {
                Ok(_) => 0,
                Err(_) => copied,
            }
        };

        let successful_copied = copied - copy_err;
        total_copied += successful_copied;

        if successful_copied < chunk {
            break;
        }

        remaining -= successful_copied;
        cur_vaddr += successful_copied as u64;
        cur_outbuf += successful_copied as u64;
    }

    Ok(total_copied)
}

/// 从一个用户态（或内核态）源虚拟地址，安全写入指定进程的虚拟内存中
pub fn write_process_memory(pid: u32, vaddr: u64, size: u64, src_user_addr: u64) -> Result<usize, i32> {
    let task = unsafe {
        if let Some(find_fn) = crate::sym!(find_task_by_vpid) {
            find_fn(pid as i32)
        } else {
            core::ptr::null_mut()
        }
    };
    if task.is_null() {
        return Err(-3); // ESRCH
    }

    let access_fn = match crate::sym!(access_process_vm) {
        Some(f) => f,
        None => return Err(-38), // ENOSYS
    };

    let mut remaining = size as usize;
    let mut cur_vaddr = vaddr;
    let mut cur_src = src_user_addr;
    let mut total_written = 0;
    let mut kbuf = [0u8; 4096];

    while remaining > 0 {
        let chunk = core::cmp::min(remaining, kbuf.len());
        let copy_err = if cur_src >= 0xffff000000000000u64 {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    cur_src as *const u8,
                    kbuf.as_mut_ptr(),
                    chunk,
                );
            }
            0
        } else {
            match copy_from_user(&mut kbuf[..chunk], cur_src as *const c_void) {
                Ok(_) => 0,
                Err(_) => chunk,
            }
        };

        let to_write = chunk - copy_err;
        if to_write == 0 {
            break;
        }

        let written = unsafe {
            access_fn(task, cur_vaddr, kbuf.as_mut_ptr() as *mut c_void, to_write as i32, 0x01) // FOLL_WRITE 是 0x01
        };
        if written <= 0 {
            break;
        }

        let written_bytes = written as usize;
        total_written += written_bytes;

        if written_bytes < to_write {
            break;
        }

        remaining -= written_bytes;
        cur_vaddr += written_bytes as u64;
        cur_src += written_bytes as u64;
    }

    Ok(total_written)
}
