// 进程虚拟内存读写与内核/用户空间数据拷贝

use core::ffi::c_void;
use crate::utils::Error;

/// 将内核数据拷贝到用户空间虚拟地址
pub fn copy_to_user(to: *mut c_void, from: &[u8]) -> Result<(), Error> {
    if to.is_null() {
        return Err(Error::EFAULT);
    }
    unsafe {
        let copy_fn = crate::sym_must!(__arch_copy_to_user);
        let ret = copy_fn(to, from.as_ptr() as *const c_void, from.len() as u64);
        if ret == 0 {
            return Ok(());
        }
        if let Some(copy_fn) = crate::sym!(copy_to_user_nofault) {
            let ret = copy_fn(to, from.as_ptr() as *const c_void, from.len());
            if ret == 0 {
                return Ok(());
            }
        }
    }
    Err(Error::EFAULT)
}

/// 从用户空间虚拟地址拷贝数据到内核缓冲区
pub fn copy_from_user(to: &mut [u8], from: *const c_void) -> Result<(), Error> {
    if from.is_null() {
        return Err(Error::EFAULT);
    }
    unsafe {
        let copy_fn = crate::sym_must!(__arch_copy_from_user);
        let ret = copy_fn(to.as_mut_ptr() as *mut c_void, from, to.len() as u64);
        if ret == 0 {
            return Ok(());
        }
        if let Some(copy_fn) = crate::sym!(copy_from_user_nofault) {
            let ret = copy_fn(to.as_mut_ptr() as *mut c_void, from, to.len());
            if ret == 0 {
                return Ok(());
            }
        }
    }
    Err(Error::EFAULT)
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

pub unsafe fn pgtable_phys(pgd_va: u64, va: u64) -> u64 { unsafe {
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
}}

#[derive(Clone, Copy)]
struct PmdWalkResult {
    is_table: bool,
    is_block: bool,
    pte_table_va: u64,
    block_phys_base: u64,
}

unsafe fn walk_to_pmd(pgd_va: u64, va: u64, paging: &Arm64Paging) -> PmdWalkResult { unsafe {
    let pxd_bits = paging.pxd_bits;
    let pxd_ptrs = paging.pxd_ptrs;
    let mut cur_pxd_va = pgd_va;

    for lv in (4 - paging.page_level)..=2 {
        let pxd_shift = pxd_bits * (4 - lv) + 3;
        let pxd_index = ((va >> pxd_shift) & (pxd_ptrs - 1)) as usize;

        let pxd_entry_ptr = (cur_pxd_va + (pxd_index as u64 * 8)) as *const u64;
        let pxd_desc = *pxd_entry_ptr;

        let valid_table = pxd_desc & 0b11;
        if valid_table == 0b11 {
            let mask = ((1u64 << (48 - paging.page_shift)) - 1) << paging.page_shift;
            let pxd_pa = pxd_desc & mask;
            if lv == 2 {
                return PmdWalkResult {
                    is_table: true,
                    is_block: false,
                    pte_table_va: pxd_pa.wrapping_add(crate::ffi::SYMS.linear_voffset),
                    block_phys_base: 0,
                };
            }
            cur_pxd_va = pxd_pa.wrapping_add(crate::ffi::SYMS.linear_voffset);
        } else if valid_table == 0b01 {
            let bits_val = (3 - lv) * pxd_bits;
            let block_bits = bits_val + paging.page_shift;
            let mask = ((1u64 << (48 - block_bits)) - 1) << block_bits;
            let block_pa = pxd_desc & mask;
            return PmdWalkResult {
                is_table: false,
                is_block: true,
                pte_table_va: 0,
                block_phys_base: block_pa,
            };
        } else {
            break;
        }
    }

    PmdWalkResult {
        is_table: false,
        is_block: false,
        pte_table_va: 0,
        block_phys_base: 0,
    }
}}

/// 读取指定进程的用户虚拟内存数据，并安全写入另一个用户态虚拟地址（零拷贝直接读取，支持PTE缓存）
pub fn read_process_memory(pid: u32, vaddr: u64, size: u64, dest_user_addr: u64) -> Result<usize, Error> {
    let task = unsafe {
        let find_fn = crate::sym_must!(find_task_by_vpid);
        find_fn(pid as i32)
    };
    if task.is_null() {
        return Err(Error::ESRCH);
    }

    let mm = unsafe {
        let get_mm_fn = crate::sym_must!(get_task_mm);
        get_mm_fn(task)
    };
    if mm.is_null() {
        return Err(Error::EFAULT);
    }

    let pgd_offset = unsafe { crate::ffi::mm_struct_offset.pgd_offset } as usize;
    let pgd_addr = (mm as usize + pgd_offset) as *const u64;
    let pgd_va = unsafe { *pgd_addr };
    if pgd_va == 0 {
        unsafe {
            let mmput_fn = crate::sym_must!(mmput);
            mmput_fn(mm);
        }
        return Err(Error::EFAULT);
    }

    let paging = Arm64Paging::new();
    let page_size = paging.page_size;

    let mut remaining = size as usize;
    let mut cur_vaddr = vaddr;
    let mut cur_outbuf = dest_user_addr;
    let mut total_copied = 0;

    static ZERO_BUF: [u8; 4096] = [0u8; 4096];

    let mut last_pmd_base = !0u64;
    let mut cached_res = PmdWalkResult {
        is_table: false,
        is_block: false,
        pte_table_va: 0,
        block_phys_base: 0,
    };

    while remaining > 0 {
        let offset_in_page = cur_vaddr & (page_size - 1);
        let bytes_left_in_page = page_size - offset_in_page;
        let chunk = core::cmp::min(remaining, bytes_left_in_page as usize);

        let pmd_size = 1u64 << (paging.page_shift + paging.pxd_bits);
        let cur_pmd_base = cur_vaddr & !(pmd_size - 1);

        if cur_pmd_base != last_pmd_base {
            cached_res = unsafe { walk_to_pmd(pgd_va, cur_vaddr, &paging) };
            last_pmd_base = cur_pmd_base;
        }

        let phys_addr = if cached_res.is_block {
            cached_res.block_phys_base + (cur_vaddr & (pmd_size - 1))
        } else if cached_res.is_table && cached_res.pte_table_va != 0 {
            let pte_index = ((cur_vaddr >> paging.page_shift) & (paging.pxd_ptrs - 1)) as usize;
            let pte_entry_ptr = (cached_res.pte_table_va + (pte_index as u64 * 8)) as *const u64;
            let pte_desc = unsafe { *pte_entry_ptr };
            let valid_page = pte_desc & 0b11;
            if valid_page == 0b11 || valid_page == 0b01 {
                let mask = ((1u64 << (48 - paging.page_shift)) - 1) << paging.page_shift;
                let page_pa = pte_desc & mask;
                if page_pa != 0 {
                    page_pa + (cur_vaddr & (page_size - 1))
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        };

        let mut is_valid = phys_addr != 0;
        if is_valid {
            let pfn = phys_addr >> paging.page_shift;
            let is_valid_pfn = unsafe {
                if let Some(pfn_fn) = crate::ffi::SYMS.pfn_valid {
                    pfn_fn(pfn) != 0
                } else {
                    true
                }
            };
            if !is_valid_pfn {
                is_valid = false;
            }
        }

        if !is_valid {
            // 页被换出、未映射或 PFN 无效，跳过并填零
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

        if let Some(resched) = crate::sym!(cond_resched) {
            unsafe { resched(); }
        }
    }

    unsafe {
        let mmput_fn = crate::sym_must!(mmput);
        mmput_fn(mm);
    }

    Ok(total_copied)
}

/// 从一个用户态源虚拟地址，安全写入指定进程的虚拟内存中（零拷贝直接写入，支持PTE缓存）
pub fn write_process_memory(pid: u32, vaddr: u64, size: u64, src_user_addr: u64) -> Result<usize, Error> {
    let task = unsafe {
        let find_fn = crate::sym_must!(find_task_by_vpid);
        find_fn(pid as i32)
    };
    if task.is_null() {
        return Err(Error::ESRCH);
    }

    let mm = unsafe {
        let get_mm_fn = crate::sym_must!(get_task_mm);
        get_mm_fn(task)
    };
    if mm.is_null() {
        return Err(Error::EFAULT);
    }

    let pgd_offset = unsafe { crate::ffi::mm_struct_offset.pgd_offset } as usize;
    let pgd_addr = (mm as usize + pgd_offset) as *const u64;
    let pgd_va = unsafe { *pgd_addr };
    if pgd_va == 0 {
        unsafe {
            let mmput_fn = crate::sym_must!(mmput);
            mmput_fn(mm);
        }
        return Err(Error::EFAULT);
    }

    let paging = Arm64Paging::new();
    let page_size = paging.page_size;

    let mut remaining = size as usize;
    let mut cur_vaddr = vaddr;
    let mut cur_src = src_user_addr;
    let mut total_copied = 0;

    let mut last_pmd_base = !0u64;
    let mut cached_res = PmdWalkResult {
        is_table: false,
        is_block: false,
        pte_table_va: 0,
        block_phys_base: 0,
    };

    while remaining > 0 {
        let offset_in_page = cur_vaddr & (page_size - 1);
        let bytes_left_in_page = page_size - offset_in_page;
        let chunk = core::cmp::min(remaining, bytes_left_in_page as usize);

        let pmd_size = 1u64 << (paging.page_shift + paging.pxd_bits);
        let cur_pmd_base = cur_vaddr & !(pmd_size - 1);

        if cur_pmd_base != last_pmd_base {
            cached_res = unsafe { walk_to_pmd(pgd_va, cur_vaddr, &paging) };
            last_pmd_base = cur_pmd_base;
        }

        let phys_addr = if cached_res.is_block {
            cached_res.block_phys_base + (cur_vaddr & (pmd_size - 1))
        } else if cached_res.is_table && cached_res.pte_table_va != 0 {
            let pte_index = ((cur_vaddr >> paging.page_shift) & (paging.pxd_ptrs - 1)) as usize;
            let pte_entry_ptr = (cached_res.pte_table_va + (pte_index as u64 * 8)) as *const u64;
            let pte_desc = unsafe { *pte_entry_ptr };
            let valid_page = pte_desc & 0b11;
            if valid_page == 0b11 || valid_page == 0b01 {
                let mask = ((1u64 << (48 - paging.page_shift)) - 1) << paging.page_shift;
                let page_pa = pte_desc & mask;
                if page_pa != 0 {
                    page_pa + (cur_vaddr & (page_size - 1))
                } else {
                    0
                }
            } else {
                0
            }
        } else {
            0
        };

        let mut is_valid = phys_addr != 0;
        if is_valid {
            let pfn = phys_addr >> paging.page_shift;
            let is_valid_pfn = unsafe {
                if let Some(pfn_fn) = crate::ffi::SYMS.pfn_valid {
                    pfn_fn(pfn) != 0
                } else {
                    true
                }
            };
            if !is_valid_pfn {
                is_valid = false;
            }
        }

        if !is_valid {
            // 页被换出、未映射或 PFN 无效，直接返回错误，绕过缺页探测
            break;
        } else {
            let kva = phys_addr.wrapping_add(unsafe { crate::ffi::SYMS.linear_voffset });
            let kva_slice = unsafe { core::slice::from_raw_parts_mut(kva as *mut u8, chunk) };
            if let Err(_) = copy_from_user(kva_slice, cur_src as *const c_void) {
                break;
            }
        }

        total_copied += chunk;
        remaining -= chunk;
        cur_vaddr += chunk as u64;
        cur_src += chunk as u64;

        if let Some(resched) = crate::sym!(cond_resched) {
            unsafe { resched(); }
        }
    }

    unsafe {
        let mmput_fn = crate::sym_must!(mmput);
        mmput_fn(mm);
    }

    Ok(total_copied)
}
