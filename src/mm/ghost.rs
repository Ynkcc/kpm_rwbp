// VMA-less 物理内存注入实现 (Ghost Memory)
// 绕过 vm_area_struct 映射，直接在页表注入 PTE，在 maps 中隐形

use core::ffi::c_void;
use crate::utils::Error;
use crate::ffi::{SYMS, routing::{self, PteOp}};

// PTE 属性常量
const PTE_VALID: u64 = 1 << 0;
const PTE_TYPE_PAGE: u64 = 3 << 0;
const PTE_AF: u64 = 1 << 10;
const PTE_UXN: u64 = 1 << 54;
const ARM64_PFN_MASK: u64 = 0x0000_FFFF_FFFF_F000_u64;

const GFP_KERNEL_FLAG: u32 = 0xcc0;  // ___GFP_RECLAIM | __GFP_IO | __GFP_FS
const GFP_ZERO_FLAG: u32 = 0x100;    // __GFP_ZERO

/// VMA 头部结构，用于在内存里查找 Gap 时做内存布局解析（适应 5.4 及其它内核版本的通用布局）
#[repr(C)]
struct VmaHead {
    vm_start: u64,
    vm_end: u64,
}

/// GhostPage 控制结构体
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GhostPage {
    pub task: *mut c_void,
    pub mm: *mut c_void,
    pub vaddr: u64,            // 注入到目标进程的用户态虚拟地址
    pub kaddr: u64,            // 内核直接映射区对应的虚拟地址 (kva)
    pub pfn: u64,              // 物理页帧号 Base
    pub installed_pte: u64,    // 注入的 PTE 值
    pub order: u32,            // 物理分配的 order (页数为 2^order)
    pub alloc_size: u64,       // 实际分配字节大小
    pub installed: bool,
}

impl Default for GhostPage {
    fn default() -> Self {
        Self {
            task: core::ptr::null_mut(),
            mm: core::ptr::null_mut(),
            vaddr: 0,
            kaddr: 0,
            pfn: 0,
            installed_pte: 0,
            order: 0,
            alloc_size: 0,
            installed: false,
        }
    }
}

impl GhostPage {
    pub fn placeholder() -> Self {
        Self {
            task: core::ptr::null_mut(),
            mm: core::ptr::null_mut(),
            vaddr: 0,
            kaddr: 1, // 1 表示占位符
            pfn: 0,
            installed_pte: 0,
            order: 0,
            alloc_size: 0,
            installed: false,
        }
    }

    pub fn is_placeholder(&self) -> bool {
        self.kaddr == 1 && !self.installed
    }
}

// 1. PTE 占用检测操作
struct PteOccupiedOp {
    occupied: bool,
}

impl PteOp for PteOccupiedOp {
    unsafe fn call(&mut self, pte: *mut c_void, _addr: u64) -> i32 {
        let p = pte as *mut u64;
        unsafe {
            if (*p & PTE_VALID) != 0 {
                self.occupied = true;
            }
        }
        0
    }
}

unsafe fn vaddr_is_occupied(mm: *mut c_void, va: u64) -> bool {
    let mut op = PteOccupiedOp { occupied: false };
    unsafe {
        let _ = routing::apply_to_page_range(mm, va, 0x1000, &mut op);
    }
    op.occupied
}

/// 在 mm 中寻找合适物理空洞的 Gap 查找算法，借助 find_vma 越过 dense 映射，O(1)
unsafe fn find_hole_near(mm: *mut c_void, near: u64, range: u64, num_pages: u32) -> u64 {
    let need = (num_pages as u64) * 0x1000;
    let near_page = near & !0xFFF_u64;
    let lo = if near_page > range { near_page - range } else { 0 };
    let hi = near_page + range;
    let mut best: u64 = 0;
    let mut best_dist: u64 = !0u64;
    let mut addr = lo;

    unsafe {
        let find_vma_fn = match SYMS.find_vma {
            Some(f) => f,
            None => return 0,
        };

        while addr < hi {
            let gap_start: u64;
            let gap_end: u64;

            let vma_ptr = find_vma_fn(mm, addr);
            if vma_ptr.is_null() {
                gap_start = addr;
                gap_end = hi;
            } else {
                let vma = vma_ptr as *const VmaHead;
                let vm_start = (*vma).vm_start;
                let vm_end = (*vma).vm_end;

                if vm_start >= hi {
                    gap_start = addr;
                    gap_end = hi;
                } else if vm_start > addr {
                    gap_start = addr;
                    gap_end = vm_start;
                } else {
                    addr = vm_end;
                    continue;
                }
            }

            if gap_end - gap_start >= need {
                let cand = if near_page >= gap_start && near_page + need <= gap_end {
                    near_page
                } else if near_page < gap_start {
                    gap_start
                } else {
                    gap_end - need
                };

                let d = if cand > near_page { cand - near_page } else { near_page - cand };
                if d < best_dist && !vaddr_is_occupied(mm, cand) {
                    best_dist = d;
                    best = cand;
                }
            }

            if vma_ptr.is_null() {
                break;
            }
            let vma = vma_ptr as *const VmaHead;
            if (*vma).vm_start >= hi {
                break;
            }
            addr = (*vma).vm_end;
        }
    }

    best
}

// 2. PTE 安装操作
struct InstallPteOp {
    pte_val: u64,
    written: bool,
}

impl PteOp for InstallPteOp {
    unsafe fn call(&mut self, pte: *mut c_void, _addr: u64) -> i32 {
        let p = pte as *mut u64;
        unsafe {
            if *p != 0 && (*p & PTE_VALID) != 0 {
                return -17; // -EEXIST
            }
            *p = self.pte_val;
        }
        self.written = true;
        0
    }
}

// 3. PTE 清除操作
struct ClearPteOp {
    cleared: bool,
}

impl PteOp for ClearPteOp {
    unsafe fn call(&mut self, pte: *mut c_void, _addr: u64) -> i32 {
        let p = pte as *mut u64;
        unsafe {
            *p = 0;
        }
        self.cleared = true;
        0
    }
}



fn pages_to_order(n: u32) -> u32 {
    let mut order = 0;
    while (1 << order) < n {
        order += 1;
    }
    order
}

/// 申请分配物理页面并注入到进程的页表中 (VMA-less Ghost Memory)
pub unsafe fn ghost_alloc(
    task: *mut c_void,
    mm: *mut c_void,
    near: u64,
    range: u64,
    pte_template: u64,
    num_pages: u32,
    out: &mut GhostPage,
) -> Result<(), Error> {
    if num_pages == 0 {
        return Err(Error::EINVAL);
    }

    unsafe {
        let get_free_pages_fn = SYMS.__get_free_pages.ok_or(Error::ENOSYS)?;
        let free_pages_fn = SYMS.free_pages.ok_or(Error::ENOSYS)?;

        let order = pages_to_order(num_pages);
        
        // 1. 申请 2^order 连续物理页并填零
        let kva = get_free_pages_fn(GFP_KERNEL_FLAG | GFP_ZERO_FLAG, order);
        if kva == 0 {
            return Err(Error::ENOMEM);
        }

        let page_pa_base = kva.wrapping_sub(SYMS.linear_voffset);

        // 2. 在进程中寻找 Gap
        let vaddr = find_hole_near(mm, near, range, 1 << order);
        if vaddr == 0 {
            free_pages_fn(kva, order);
            return Err(Error::ENOSPC);
        }

        // 3. 逐页强插页表项 (PTE)
        for i in 0..(1 << order) {
            let page_pa = page_pa_base + (i as u64) * 0x1000;
            let mut new_pte = (pte_template & !ARM64_PFN_MASK) | (page_pa & ARM64_PFN_MASK);
            new_pte |= PTE_VALID | PTE_TYPE_PAGE | PTE_AF;
            new_pte &= !PTE_UXN; // 使之可以执行
            new_pte &= !(1_u64 << 50); // 清除 PTE_GP
            new_pte &= !(1_u64 << 7);  // 清除 PTE_RDONLY

            let mut install_op = InstallPteOp {
                pte_val: new_pte,
                written: false,
            };

            let target_page_va = vaddr + (i as u64) * 0x1000;
            let ret = routing::apply_to_page_range(mm, target_page_va, 0x1000, &mut install_op);

            if ret.is_err() || !install_op.written {
                // 回滚已经强插的页面
                for j in 0..i {
                    let mut clear_op = ClearPteOp { cleared: false };
                    let _ = routing::apply_to_page_range(mm, vaddr + (j as u64) * 0x1000, 0x1000, &mut clear_op);
                }
                free_pages_fn(kva, order);
                return Err(ret.err().unwrap_or(Error::EFAULT));
            }
        }

        // 4. TLB 刷写广播
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
            options(nostack)
        );

        out.task = task;
        out.mm = mm;
        out.vaddr = vaddr;
        out.kaddr = kva;
        out.pfn = page_pa_base >> 12;
        out.installed_pte = (pte_template & !ARM64_PFN_MASK) | (page_pa_base & ARM64_PFN_MASK);
        out.order = order;
        out.alloc_size = ((1 << order) as u64) * 0x1000;
    }
    out.installed = true;

    Ok(())
}

unsafe extern "C" fn ghost_free_drain_ipi(_arg: *mut c_void) {
    unsafe {
        core::arch::asm!(
            "ic ialluis",  // 使 I-Cache 缓存行失效
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}

/// 释放申请的 Ghost 页面，解挂页表并刷新 CPU 缓存
pub unsafe fn ghost_free(gp: &mut GhostPage) -> Result<(), Error> {
    if !gp.installed {
        return Ok(());
    }

    unsafe {
        let free_pages_fn = SYMS.free_pages.ok_or(Error::ENOSYS)?;
        let mmput_fn = SYMS.mmput.ok_or(Error::ENOSYS)?;

        let page_count = 1 << gp.order;
        for i in 0..page_count {
            let mut clear_op = ClearPteOp { cleared: false };
            let _ = routing::apply_to_page_range(gp.mm, gp.vaddr + (i as u64) * 0x1000, 0x1000, &mut clear_op);
        }

        // TLB 刷页指令清理缓存，防止后来的调用再度利用已被销毁的 PTE 地址
        core::arch::asm!(
            "dsb ishst",
            "tlbi vmalle1is",
            "dsb ish",
            "ic ialluis",
            "dsb ish",
            "isb",
            options(nostack)
        );

        // 核间 IPI 同步，驱使所有 CPU 核心瞬间脱离此内存段以防崩溃
        if let Some(on_each_cpu_fn) = SYMS.on_each_cpu {
            let ipi_cb: unsafe extern "C" fn(*mut c_void) = ghost_free_drain_ipi;
            on_each_cpu_fn(ipi_cb, core::ptr::null_mut(), 1);
        } else {
            pr_warn!("ghost_free: SYMS.on_each_cpu 不存在，跳过核间 IPI同步！");
        }

        free_pages_fn(gp.kaddr, gp.order);
        mmput_fn(gp.mm);
    }

    gp.installed = false;
    gp.kaddr = 0;
    gp.vaddr = 0;
    gp.mm = core::ptr::null_mut();
    gp.task = core::ptr::null_mut();

    Ok(())
}

/// 内核直接映射区快速写入数据
pub fn ghost_write(gp: &GhostPage, offset: u32, src: &[u8]) -> Result<(), Error> {
    if !gp.installed {
        return Err(Error::EINVAL);
    }
    if (offset as u64) + (src.len() as u64) > gp.alloc_size {
        return Err(Error::EINVAL);
    }
    unsafe {
        let dest = (gp.kaddr + (offset as u64)) as *mut u8;
        core::ptr::copy_nonoverlapping(src.as_ptr(), dest, src.len());
    }
    Ok(())
}

/// 数据同步及清理 ARM64 D-Cache 与 I-Cache 缓存，确保最新修改的指令集可用
pub fn ghost_sync_icache(gp: &GhostPage) {
    if !gp.installed {
        return;
    }
    let start = gp.kaddr;
    let end = gp.kaddr + gp.alloc_size;
    let mut line = start & !63u64;
    while line < end {
        unsafe {
            core::arch::asm!("dc cvau, {}", in(reg) line);
        }
        line += 64;
    }
    unsafe {
        core::arch::asm!(
            "dsb ish",
            "ic ialluis",
            "dsb ish",
            "isb",
            options(nostack)
        );
    }
}
