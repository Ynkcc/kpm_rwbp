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

struct Arm64Paging {
    page_shift: u64,
    page_size: u64,
    page_level: u64,
    pxd_bits: u64,
    pxd_ptrs: u64,
}

impl Arm64Paging {
    fn new() -> Self {
        let tcr_el1: u64;
        unsafe {
            core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr_el1);
        }
        let t1sz = (tcr_el1 >> 16) & 0x3f;
        let va_bits = 64 - t1sz;
        let tg1 = (tcr_el1 >> 30) & 3;
        let page_shift = match tg1 {
            1 => 14,
            3 => 16,
            _ => 12,
        };
        let page_size = 1u64 << page_shift;
        let page_level = (va_bits - 4) / (page_shift - 3);
        let pxd_bits = page_shift - 3;
        let pxd_ptrs = 1u64 << pxd_bits;

        Self {
            page_shift,
            page_size,
            page_level,
            pxd_bits,
            pxd_ptrs,
        }
    }
}

pub unsafe fn pgtable_phys(pgd_va: u64, va: u64) -> u64 {
    let paging = Arm64Paging::new();
    let pxd_bits = paging.pxd_bits;
    let pxd_ptrs = paging.pxd_ptrs;
    let mut cur_pxd_va = pgd_va;
    let mut pxd_pa = 0;

    for lv in (4 - paging.page_level)..4 {
        let pxd_shift = pxd_bits * (4 - lv) + 3;
        let pxd_index = ((va >> pxd_shift) & (pxd_ptrs - 1)) as usize;

        let pxd_entry_ptr = (cur_pxd_va + (pxd_index as u64 * 8)) as *const u64;
        let pxd_desc = *pxd_entry_ptr;

        let valid_table = pxd_desc & 0b11;
        if valid_table == 0b11 {
            let mask = ((1u64 << (48 - paging.page_shift)) - 1) << paging.page_shift;
            pxd_pa = pxd_desc & mask;
        } else if valid_table == 0b01 {
            let bits_val = (3 - lv) * pxd_bits;
            let block_bits = bits_val + paging.page_shift;
            let mask = ((1u64 << (48 - block_bits)) - 1) << block_bits;
            pxd_pa = (pxd_desc & mask) + (va & (((1u64 << bits_val) - 1) << paging.page_shift));
            break;
        } else {
            return 0;
        }

        cur_pxd_va = pxd_pa.wrapping_add(crate::ffi::SYMS.linear_voffset);
    }

    if pxd_pa != 0 {
        pxd_pa + (va & (paging.page_size - 1))
    } else {
        0
    }
}

/// 读取指定进程的用户虚拟内存数据，并安全写入另一个用户态虚拟地址（零拷贝直接读取）
pub fn read_process_memory(pid: u32, vaddr: u64, size: u64, dest_user_addr: u64) -> Result<usize, i32> {
    let task = unsafe {
        if let Some(find_fn) = crate::sym!(find_task_by_vpid) {
            find_fn(pid as i32)
        } else {
            return Err(-3); // ESRCH
        }
    };
    if task.is_null() {
        return Err(-3); // ESRCH
    }

    let mm = unsafe {
        if let Some(get_mm_fn) = crate::sym!(get_task_mm) {
            get_mm_fn(task)
        } else {
            return Err(-14); // EFAULT
        }
    };
    if mm.is_null() {
        return Err(-14); // EFAULT
    }

    let pgd_offset = unsafe { crate::ffi::mm_struct_offset.pgd_offset } as usize;
    let pgd_addr = (mm as usize + pgd_offset) as *const u64;
    let pgd_va = unsafe { *pgd_addr };
    if pgd_va == 0 {
        unsafe {
            if let Some(mmput_fn) = crate::sym!(mmput) {
                mmput_fn(mm);
            }
        }
        return Err(-14);
    }

    let paging = Arm64Paging::new();
    let page_size = paging.page_size;

    let mut remaining = size as usize;
    let mut cur_vaddr = vaddr;
    let mut cur_outbuf = dest_user_addr;
    let mut total_copied = 0;

    static ZERO_BUF: [u8; 4096] = [0u8; 4096];

    while remaining > 0 {
        let offset_in_page = cur_vaddr & (page_size - 1);
        let bytes_left_in_page = page_size - offset_in_page;
        let chunk = core::cmp::min(remaining, bytes_left_in_page as usize);

        let phys_addr = unsafe { pgtable_phys(pgd_va, cur_vaddr) };
        if phys_addr == 0 {
            // 页被换出或未映射，跳过并填零
            let mut zero_rem = chunk;
            let mut cur_zero_out = cur_outbuf;
            while zero_rem > 0 {
                let zero_chunk = core::cmp::min(zero_rem, ZERO_BUF.len());
                if let Err(_) = copy_to_user(cur_zero_out as *mut c_void, &ZERO_BUF[..zero_chunk]) {
                    break;
                }
                zero_rem -= zero_chunk;
                cur_zero_out += zero_chunk as u64;
            }
            if zero_rem > 0 {
                break;
            }
        } else {
            let kva = phys_addr.wrapping_add(unsafe { crate::ffi::SYMS.linear_voffset });
            let kva_slice = unsafe { core::slice::from_raw_parts(kva as *const u8, chunk) };
            if let Err(_) = copy_to_user(cur_outbuf as *mut c_void, kva_slice) {
                break;
            }
        }

        total_copied += chunk;
        remaining -= chunk;
        cur_vaddr += chunk as u64;
        cur_outbuf += chunk as u64;
    }

    unsafe {
        if let Some(mmput_fn) = crate::sym!(mmput) {
            mmput_fn(mm);
        }
    }

    Ok(total_copied)
}

/// 从一个用户态源虚拟地址，安全写入指定进程的虚拟内存中（零拷贝直接写入）
pub fn write_process_memory(pid: u32, vaddr: u64, size: u64, src_user_addr: u64) -> Result<usize, i32> {
    let task = unsafe {
        if let Some(find_fn) = crate::sym!(find_task_by_vpid) {
            find_fn(pid as i32)
        } else {
            return Err(-3); // ESRCH
        }
    };
    if task.is_null() {
        return Err(-3); // ESRCH
    }

    let mm = unsafe {
        if let Some(get_mm_fn) = crate::sym!(get_task_mm) {
            get_mm_fn(task)
        } else {
            return Err(-14); // EFAULT
        }
    };
    if mm.is_null() {
        return Err(-14); // EFAULT
    }

    let pgd_offset = unsafe { crate::ffi::mm_struct_offset.pgd_offset } as usize;
    let pgd_addr = (mm as usize + pgd_offset) as *const u64;
    let pgd_va = unsafe { *pgd_addr };
    if pgd_va == 0 {
        unsafe {
            if let Some(mmput_fn) = crate::sym!(mmput) {
                mmput_fn(mm);
            }
        }
        return Err(-14);
    }

    let paging = Arm64Paging::new();
    let page_size = paging.page_size;

    let mut remaining = size as usize;
    let mut cur_vaddr = vaddr;
    let mut cur_src = src_user_addr;
    let mut total_written = 0;

    while remaining > 0 {
        let offset_in_page = cur_vaddr & (page_size - 1);
        let bytes_left_in_page = page_size - offset_in_page;
        let chunk = core::cmp::min(remaining, bytes_left_in_page as usize);

        let phys_addr = unsafe { pgtable_phys(pgd_va, cur_vaddr) };
        if phys_addr == 0 {
            // 页未映射，无法写入，终止
            break;
        }

        let kva = phys_addr.wrapping_add(unsafe { crate::ffi::SYMS.linear_voffset });
        let kva_slice = unsafe { core::slice::from_raw_parts_mut(kva as *mut u8, chunk) };
        if let Err(_) = copy_from_user(kva_slice, cur_src as *const c_void) {
            break;
        }

        total_written += chunk;
        remaining -= chunk;
        cur_vaddr += chunk as u64;
        cur_src += chunk as u64;
    }

    unsafe {
        if let Some(mmput_fn) = crate::sym!(mmput) {
            mmput_fn(mm);
        }
    }

    Ok(total_written)
}
