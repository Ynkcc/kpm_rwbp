// 硬件断点/监视点核心业务与生命周期管理

use crate::ffi::{get_current, PerfEventAttr};
use crate::sync::{RawSpinlock, KernelArc};
use crate::utils::{ListHead, Error};
use core::ffi::c_void;
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering, AtomicBool, AtomicU64, AtomicU32};
use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};

// 全局状态变量
pub struct RcuList {
    head: core::cell::UnsafeCell<ListHead>,
}

unsafe impl Sync for RcuList {}

impl RcuList {
    pub const fn new() -> Self {
        Self {
            head: core::cell::UnsafeCell::new(ListHead {
                next: core::ptr::null_mut(),
                prev: core::ptr::null_mut(),
            }),
        }
    }

    pub fn get_ptr(&self) -> *mut ListHead {
        self.head.get()
    }
}

pub static BP_LIST: RcuList = RcuList::new();
pub static BP_LIST_LOCK: RawSpinlock = RawSpinlock::new();
pub static IN_FLIGHT: AtomicI32 = AtomicI32::new(0);

/// 硬件断点命中事件的内核记录格式
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct HwbpHitRecord {
    pub hit_time: u64,
    pub task_id: u32,
    pub _pad: u32,
    pub hit_addr: u64,
    pub regs_info: crate::ipc::protocol::HwbpRegsSnapshot,
}

/// 模仿内核的 work_struct 结构体，用于异步延时注销/恢复硬件断点
#[repr(C)]
pub struct WorkStruct {
    pub data: usize,
    pub entry: ListHead,
    pub func: unsafe extern "C" fn(work: *mut WorkStruct),
}

impl WorkStruct {
    /// 初始化工作项，绑定回调函数，并初始化内部链表指针
    pub fn init(&mut self, func: unsafe extern "C" fn(work: *mut WorkStruct)) {
        self.data = 0;
        self.entry.next = &mut self.entry as *mut _;
        self.entry.prev = &mut self.entry as *mut _;
        self.func = func;
    }
}

/// 维护单个硬件断点状态的控制结构体
#[repr(C)]
pub struct HwbpNode {
    pub list: ListHead,
    pub bp: *mut c_void,
    pub pid: u32,
    pub addr: u64,
    pub bp_type: u32,
    pub len: u32,
    pub hit_count: AtomicU64,
    pub unreg_work: WorkStruct,
    pub orig_attr: PerfEventAttr,
    pub is_temp_bp: AtomicBool,
    pub recovery_work: WorkStruct,
    pub scheme: u32,
    pub next_instruction_attr: PerfEventAttr,
    pub hit_records: [HwbpHitRecord; 16],
    pub hit_record_seqs: [AtomicU32; 16],
    pub hit_record_head: AtomicU64, // 写入游标 (单调递增)
    pub hit_record_tail: AtomicU64, // 读取游标 (单调递增)
    pub active: AtomicBool,
}

impl Drop for HwbpNode {
    fn drop(&mut self) {
        pr_info!("kpm_rwbp: HwbpNode 被物理释放, 目标地址=0x{:x}, PID={}", self.addr, self.pid);
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// 注册断点工作包装结构
#[repr(C)]
pub struct RegisterWork {
    pub work: WorkStruct,
    pub pid: u32,
    pub addr: u64,
    pub bp_type: u32,
    pub len: u32,
    pub scheme: u32,
}


// 寄存器辅助读写宏：用于访问 ARM64 硬件调试寄存器 (BVR/BCR, WVR/WCR)
macro_rules! read_sysreg {
    ($reg_prefix:ident, $n:expr) => {
        match $n {
            0 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "0_el1"), out(reg) v); v }
            1 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "1_el1"), out(reg) v); v }
            2 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "2_el1"), out(reg) v); v }
            3 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "3_el1"), out(reg) v); v }
            4 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "4_el1"), out(reg) v); v }
            5 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "5_el1"), out(reg) v); v }
            6 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "6_el1"), out(reg) v); v }
            7 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "7_el1"), out(reg) v); v }
            8 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "8_el1"), out(reg) v); v }
            9 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "9_el1"), out(reg) v); v }
            10 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "10_el1"), out(reg) v); v }
            11 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "11_el1"), out(reg) v); v }
            12 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "12_el1"), out(reg) v); v }
            13 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "13_el1"), out(reg) v); v }
            14 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "14_el1"), out(reg) v); v }
            15 => { let mut v: u64; core::arch::asm!(concat!("mrs {}, ", stringify!($reg_prefix), "15_el1"), out(reg) v); v }
            _ => 0,
        }
    };
}

macro_rules! write_sysreg {
    ($reg_prefix:ident, $n:expr, $val:expr) => {
        match $n {
            0 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "0_el1, {}"), in(reg) $val),
            1 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "1_el1, {}"), in(reg) $val),
            2 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "2_el1, {}"), in(reg) $val),
            3 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "3_el1, {}"), in(reg) $val),
            4 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "4_el1, {}"), in(reg) $val),
            5 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "5_el1, {}"), in(reg) $val),
            6 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "6_el1, {}"), in(reg) $val),
            7 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "7_el1, {}"), in(reg) $val),
            8 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "8_el1, {}"), in(reg) $val),
            9 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "9_el1, {}"), in(reg) $val),
            10 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "10_el1, {}"), in(reg) $val),
            11 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "11_el1, {}"), in(reg) $val),
            12 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "12_el1, {}"), in(reg) $val),
            13 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "13_el1, {}"), in(reg) $val),
            14 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "14_el1, {}"), in(reg) $val),
            15 => core::arch::asm!(concat!("msr ", stringify!($reg_prefix), "15_el1, {}"), in(reg) $val),
            _ => {}
        }
        core::arch::asm!("isb");
    };
}

#[inline(always)] pub unsafe fn read_wcr(n: i32) -> u64 { unsafe { read_sysreg!(dbgwcr, n) } }
#[inline(always)] pub unsafe fn write_wcr(n: i32, val: u64) { unsafe { write_sysreg!(dbgwcr, n, val); } }
#[inline(always)] unsafe fn read_wvr(n: i32) -> u64 { unsafe { read_sysreg!(dbgwvr, n) } }
#[inline(always)] unsafe fn write_wvr(n: i32, val: u64) { unsafe { write_sysreg!(dbgwvr, n, val); } }
#[inline(always)] unsafe fn read_bcr(n: i32) -> u64 { unsafe { read_sysreg!(dbgbcr, n) } }
#[inline(always)] unsafe fn write_bcr(n: i32, val: u64) { unsafe { write_sysreg!(dbgbcr, n, val); } }
#[inline(always)] unsafe fn read_bvr(n: i32) -> u64 { unsafe { read_sysreg!(dbgbvr, n) } }
#[inline(always)] unsafe fn write_bvr(n: i32, val: u64) { unsafe { write_sysreg!(dbgbvr, n, val); } }

unsafe fn read_wb_reg(reg_idx: i32, n: i32) -> u64 {
    unsafe {
        if reg_idx == 0 {
            read_bvr(n)
        } else if reg_idx == 16 {
            read_bcr(n)
        } else if reg_idx == 32 {
            read_wvr(n)
        } else if reg_idx == 48 {
            read_wcr(n)
        } else {
            0
        }
    }
}

unsafe fn write_wb_reg(reg_idx: i32, n: i32, val: u64) {
    unsafe {
        if reg_idx == 0 {
            write_bvr(n, val);
        } else if reg_idx == 16 {
            write_bcr(n, val);
        } else if reg_idx == 32 {
            write_wvr(n, val);
        } else if reg_idx == 48 {
            write_wcr(n, val);
        }
    }
}

pub fn calc_hw_addr(bp_addr: u64, bp_type: u32, bp_len: u32) -> u64 {
    let alignment_mask = if bp_type == 4 {
        0x3
    } else if bp_len == 8 {
        0x7
    } else if bp_len == 4 {
        0x3
    } else {
        0x7
    };
    bp_addr & !alignment_mask
}

unsafe fn toggle_bp_registers_directly(
    bp_addr: u64,
    bp_type: u32,
    bp_len: u32,
    enable: bool,
) -> bool {
    let hw_addr = calc_hw_addr(bp_addr, bp_type, bp_len);
    let (ctrl_reg, val_reg, max_slots) = if bp_type == 4 {
        (16, 0, 6)
    } else {
        (48, 32, 4)
    };

    unsafe {
        for i in 0..max_slots {
            let addr = read_wb_reg(val_reg, i);
            if addr == hw_addr {
                let mut ctrl = read_wb_reg(ctrl_reg, i);
                if enable {
                    ctrl |= 0x1;
                } else {
                    ctrl &= !0x1;
                }
                write_wb_reg(ctrl_reg, i, ctrl);
                pr_info!("toggle_bp_registers_directly: 插槽 {}, 控制值 0x{:x}", i, ctrl);
                return true;
            }
        }
    }
    pr_warn!("toggle_bp_registers_directly: 未找到匹配地址 0x{:x} 的插槽！", hw_addr);
    false
}

/// 临时失效期满后，恢复硬件断点
pub unsafe extern "C" fn recovery_bp_work_func(work: *mut WorkStruct) {
    unsafe {
        let node_offset = core::mem::offset_of!(HwbpNode, recovery_work);
        let node = (work as usize - node_offset) as *mut HwbpNode;
        pr_info!("recovery_bp_work_func: 恢复断点 {:p}, 方案 {}", (*node).bp, (*node).scheme);

        if (*node).active.load(Ordering::Acquire) {
            match (*node).scheme {
                2 => {
                    if let Some(on_each_cpu) = crate::sym!(on_each_cpu) {
                        on_each_cpu(write_wp_regs_on_cpu, node as *mut c_void, 1);
                    }
                }
                1 => {
                    if let Some(enable_fn) = crate::sym!(perf_event_enable) {
                        enable_fn((*node).bp);
                    }
                }
                _ => {}
            }
        }
        (*node).is_temp_bp.store(false, Ordering::Release);
        
        let _arc = KernelArc::from_raw_transferred(node);
    }
}

pub unsafe extern "C" fn write_wp_regs_on_cpu(info: *mut c_void) {
    unsafe {
        let node = info as *mut HwbpNode;
        let hw_addr = calc_hw_addr((*node).addr, (*node).bp_type, (*node).len);
        write_wb_reg(32, 0, hw_addr);
        let ctrl = 1 | (3 << 1) | (3 << 3) | (0xff << 5);
        write_wb_reg(48, 0, ctrl);

        let mut mdscr: u64 = 0;
        core::arch::asm!("mrs {}, mdscr_el1", out(reg) mdscr);
        mdscr |= 1u64 << 15;
        core::arch::asm!("msr mdscr_el1, {}", in(reg) mdscr);
        core::arch::asm!("isb");
    }
}

unsafe extern "C" fn disable_wp_regs_on_cpu(_info: *mut c_void) {
    unsafe {
        write_wb_reg(48, 0, 0);
        write_wb_reg(32, 0, 0);
    }
}

unsafe extern "C" fn unregister_bp_work_func(work: *mut WorkStruct) {
    unsafe {
        let node_offset = core::mem::offset_of!(HwbpNode, unreg_work);
        let node = (work as usize - node_offset) as *mut HwbpNode;

        if let Some(cancel_fn) = crate::sym!(cancel_work_sync) {
            let cancelled = cancel_fn(&mut (*node).recovery_work as *mut _ as *mut c_void);
            if cancelled != 0 {
                let _ = KernelArc::from_raw_transferred(node);
            }
        }

        match (*node).scheme {
            2 => {
                let mut has_other_scheme3 = false;
                let guard = BP_LIST_LOCK.lock();
                let bp_list_ptr = BP_LIST.get_ptr();
                let mut curr = (*bp_list_ptr).next;
                while curr != bp_list_ptr {
                    let node_offset = core::mem::offset_of!(HwbpNode, list);
                    let other_node = (curr as usize - node_offset) as *mut HwbpNode;
                    if other_node != node && (*other_node).scheme == 2 && (*other_node).active.load(Ordering::Acquire) {
                        has_other_scheme3 = true;
                        break;
                    }
                    curr = (*curr).next;
                }
                drop(guard);

                if !has_other_scheme3 {
                    if let Some(on_each_cpu) = crate::sym!(on_each_cpu) {
                        on_each_cpu(disable_wp_regs_on_cpu, core::ptr::null_mut(), 1);
                    }
                }
            }
            1 => {
                if let Some(unreg_fn) = crate::sym!(unregister_hw_breakpoint) {
                    unreg_fn((*node).bp);
                }
            }
            _ => {}
        }

        if let Some(sync_rcu) = crate::sym!(synchronize_rcu) {
            sync_rcu();
        }

        let _arc = KernelArc::from_raw_transferred(node);
    }
}

/// ARM64 处理器寄存器布局
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct PtRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

// Hook callback structures for Scheme 3 watchpoint
#[repr(C, align(8))]
#[derive(Immutable, KnownLayout, Clone, Copy)]
pub struct HookFargs3 {
    pub chain: *mut c_void,
    pub skip_origin: c_int,
    pub local: HookLocal,
    pub ret: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
}

#[repr(C)]
#[derive(Immutable, KnownLayout, Clone, Copy)]
pub struct HookLocal {
    pub data: [u64; 8],
}

/// Scheme 3 watchpoint 拦截钩子回调函数（公开供 hooks 模块在卸载时使用）
pub unsafe extern "C" fn before_watchpoint_handler(args: *mut HookFargs3, _udata: *mut c_void) {
    unsafe {
        let addr = (*args).arg0;
        let regs = (*args).arg2 as *mut PtRegs;
        let mut found_node: *mut HwbpNode = core::ptr::null_mut();
        let mut is_matched = false;

        let _rcu_guard = crate::sync::RcuReadGuard::new();

        let bp_list_ptr = BP_LIST.get_ptr();
        let mut curr = (*bp_list_ptr).next_rcu();
        while curr != bp_list_ptr {
            let node_offset = core::mem::offset_of!(HwbpNode, list);
            let node = (curr as usize - node_offset) as *mut HwbpNode;
            if (*node).scheme == 2 {
                let task = get_current();
                let pid_fn = crate::sym_must!(__task_pid_nr_ns);
                let tgid = pid_fn(task, 1, core::ptr::null_mut()) as u32;
                if (*node).pid == tgid && (*node).active.load(Ordering::Acquire) {
                    let hw_addr = calc_hw_addr((*node).addr, (*node).bp_type, (*node).len);
                    if (addr & !7u64) == hw_addr {
                        is_matched = true;
                        if (*node)
                            .is_temp_bp
                            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                            .is_ok()
                        {
                            (*node).hit_count.fetch_add(1, Ordering::Relaxed);
                            let arc = KernelArc::from_raw(node);
                            found_node = arc.into_raw();
                        }
                        break;
                    }
                }
            }
            curr = (*curr).next_rcu();
        }

        if is_matched {
            let ctrl = read_wcr(0);
            write_wcr(0, ctrl & !1u64);
        }

        if !found_node.is_null() {
            pr_info!(
                "Scheme 3 Hooked watchpoint triggered! addr=0x{:x}, PC=0x{:x}",
                addr,
                if regs.is_null() { 0 } else { (*regs).pc }
            );

            if !regs.is_null() {
                let head = (*found_node).hit_record_head.fetch_add(1, Ordering::Acquire);
                let idx = (head % 16) as usize;
                let rec = &mut (*found_node).hit_records[idx];
                let seq_atom = &(*found_node).hit_record_seqs[idx];

                let seq = seq_atom.load(Ordering::Relaxed).wrapping_add(1);
                seq_atom.store(seq, Ordering::Release);
                crate::sync::smp_wmb();

                let task = get_current();
                let pid_fn = crate::sym_must!(__task_pid_nr_ns);
                rec.task_id = pid_fn(task, 0, core::ptr::null_mut()) as u32;
                rec.hit_addr = (*found_node).addr;
                let regs_ref = &*regs;
                rec.regs_info.pc = regs_ref.pc;
                rec.regs_info.sp = regs_ref.sp;
                rec.regs_info.pstate = regs_ref.pstate;
                rec.regs_info.regs.copy_from_slice(&regs_ref.regs[..31]);

                if let Some(mono_ns_fn) = crate::sym!(ktime_get_mono_fast_ns) {
                    let t = mono_ns_fn();
                    rec.hit_time = if t == 0 { 1 } else { t };
                } else {
                    rec.hit_time = 1;
                }

                crate::sync::smp_wmb();

                seq_atom.store(seq.wrapping_add(1), Ordering::Release);
            }

            let mut ref_transferred = false;
            if let Some(queue_fn) = crate::sym!(queue_work_on) {
                let ret = queue_fn(0, crate::sym!(system_wq), &mut (*found_node).recovery_work as *mut _ as *mut c_void);
                if ret != 0 {
                    ref_transferred = true;
                }
            }

            if !ref_transferred {
                let _ = KernelArc::from_raw_transferred(found_node);
            }
        }
    }
}

/// 硬件调试断点（perf_event）触发的回调函数
unsafe extern "C" fn hwbp_triggered(bp: *mut c_void, _data: *mut c_void, regs: *mut c_void) {
    unsafe {
        let pt_regs = regs as *mut PtRegs;
        pr_info!("hwbp_triggered 触发! bp={:p}", bp);

        let mut found_node: *mut HwbpNode = core::ptr::null_mut();
        
        let _rcu_guard = crate::sync::RcuReadGuard::new();

        let bp_list_ptr = BP_LIST.get_ptr();
        let mut curr = (*bp_list_ptr).next_rcu();
        while curr != bp_list_ptr {
            let node_offset = core::mem::offset_of!(HwbpNode, list);
            let node = (curr as usize - node_offset) as *mut HwbpNode;
            if (*node).bp == bp && (*node).active.load(Ordering::Acquire) {
                let arc = KernelArc::from_raw(node);
                found_node = arc.into_raw();
                break;
            }
            curr = (*curr).next_rcu();
        }

        if found_node.is_null() {
            pr_warn!("hwbp_triggered: 未找到对应的 HwbpNode，bp={:p}", bp);
            return;
        }

        if (*found_node).scheme == 1 && (*found_node).is_temp_bp.load(Ordering::Acquire) {
            let _ = KernelArc::from_raw_transferred(found_node);
            return;
        }

        (*found_node).hit_count.fetch_add(1, Ordering::Relaxed);

        if !pt_regs.is_null() {
            let head = (*found_node).hit_record_head.fetch_add(1, Ordering::Acquire);
            let idx = (head % 16) as usize;
            let rec = &mut (*found_node).hit_records[idx];
            let seq_atom = &(*found_node).hit_record_seqs[idx];

            let seq = seq_atom.load(Ordering::Relaxed).wrapping_add(1);
            seq_atom.store(seq, Ordering::Release);
            crate::sync::smp_wmb();

            let task = get_current();
            let pid_fn = crate::sym_must!(__task_pid_nr_ns);
            rec.task_id = pid_fn(task, 0, core::ptr::null_mut()) as u32;
            rec.hit_addr = (*found_node).addr;
            let pt_regs_ref = &*pt_regs;
            rec.regs_info.pc = pt_regs_ref.pc;
            rec.regs_info.sp = pt_regs_ref.sp;
            rec.regs_info.pstate = pt_regs_ref.pstate;
            rec.regs_info.regs.copy_from_slice(&pt_regs_ref.regs[..31]);

            if let Some(mono_ns_fn) = crate::sym!(ktime_get_mono_fast_ns) {
                let t = mono_ns_fn();
                rec.hit_time = if t == 0 { 1 } else { t };
            } else {
                rec.hit_time = 1;
            }

            crate::sync::smp_wmb();

            seq_atom.store(seq.wrapping_add(1), Ordering::Release);
        }

        pr_info!("=== 硬件断点命中 ===");
        pr_info!(
            "PID: {}, 地址: 0x{:x}, 命中次数: {}",
            (*found_node).pid,
            (*found_node).addr,
            (*found_node).hit_count.load(Ordering::Relaxed)
        );
        pr_info!("PC 地址: 0x{:x}", if pt_regs.is_null() { 0 } else { (*pt_regs).pc });

        #[cfg(feature = "dump_stack")]
        if let Some(dump_fn) = crate::sym!(dump_stack) {
            dump_fn();
        }

        let mut ref_transferred = false;
        match (*found_node).scheme {
            1 => {
                if let Some(disable_fn) = crate::sym!(perf_event_disable_inatomic) {
                    disable_fn(bp);
                }
                (*found_node).is_temp_bp.store(true, Ordering::Release);
                if let Some(queue_fn) = crate::sym!(queue_work_on) {
                    let ret = queue_fn(
                        0,
                        crate::sym!(system_wq),
                        &mut (*found_node).recovery_work as *mut _ as *mut c_void,
                    );
                    if ret != 0 {
                        ref_transferred = true;
                    }
                }
            }
            999 => {
                pr_warn!("Scheme 999 触发。当前方案已安全降级为工作队列延时恢复，防止 atomic 上下文睡眠。");
                if let Some(disable_fn) = crate::sym!(perf_event_disable_inatomic) {
                    disable_fn(bp);
                }
                (*found_node).is_temp_bp.store(true, Ordering::Release);
                if let Some(queue_fn) = crate::sym!(queue_work_on) {
                    let ret = queue_fn(
                        0,
                        crate::sym!(system_wq),
                        &mut (*found_node).recovery_work as *mut _ as *mut c_void,
                    );
                    if ret != 0 {
                        ref_transferred = true;
                    }
                }
            }
            _ => {
                toggle_bp_registers_directly((*found_node).addr, (*found_node).bp_type, (*found_node).len, false);
                if let Some(disable_fn) = crate::sym!(perf_event_disable_inatomic) {
                    disable_fn(bp);
                }
            }
        }

        if !ref_transferred {
            let _ = KernelArc::from_raw_transferred(found_node);
        }
    }
}

#[allow(dead_code)]
unsafe fn arm64_move_bp_to_next_instruction(
    bp: *mut c_void,
    next_instruction_addr: u64,
    original_attr: &mut PerfEventAttr,
    next_instruction_attr: &mut PerfEventAttr,
) -> bool {
    if bp.is_null() || next_instruction_addr == 0 {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            original_attr as *const PerfEventAttr,
            next_instruction_attr as *mut PerfEventAttr,
            1,
        );
    }
    next_instruction_attr.bp_addr = next_instruction_addr;
    next_instruction_attr.bp_len = 4;
    next_instruction_attr.bp_type = 4;
    next_instruction_attr.set_disabled(false);

    unsafe {
        if let Some(modify_fn) = crate::sym!(modify_user_hw_breakpoint) {
            let ret = modify_fn(bp, next_instruction_attr);
            if ret == 0 {
                return true;
            }
        }
    }
    next_instruction_attr.bp_addr = 0;
    false
}

#[allow(dead_code)]
unsafe fn arm64_recovery_bp_to_original(
    bp: *mut c_void,
    original_attr: &mut PerfEventAttr,
    next_instruction_attr: &mut PerfEventAttr,
) -> bool {
    if bp.is_null() {
        return false;
    }
    unsafe {
        if let Some(modify_fn) = crate::sym!(modify_user_hw_breakpoint) {
            let ret = modify_fn(bp, original_attr);
            if ret == 0 {
                next_instruction_attr.bp_addr = 0;
                return true;
            }
        }
    }
    false
}

/// 注册一个进程硬件断点
pub fn register_hwbp(
    pid: u32,
    addr: u64,
    bp_type: u32,
    len: u32,
    scheme: u32,
) -> Result<(), Error> {
    pr_info!("register_hwbp: PID={}, 地址=0x{:x}, 类型={}, 长度={}, 方案={}", pid, addr, bp_type, len, scheme);

    // 检查重复注册
    let guard = BP_LIST_LOCK.lock();
    let bp_list_ptr = BP_LIST.get_ptr();
    let mut curr = unsafe { (*bp_list_ptr).next };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        if unsafe { (*node).pid == pid && (*node).addr == addr } {
            drop(guard);
            return Err(Error::EEXIST);
        }
        curr = unsafe { (*curr).next };
    }
    drop(guard);

    match scheme {
        999 => {
            pr_err!("register_hwbp: 方案 999 已被废弃，直接返回错误");
            return Err(Error::EINVAL);
        }
        2 => {
            unsafe {
                let install_fn = crate::sym!(watchpoint_handler_install_hook_helper); 
                if let Some(install) = install_fn {
                    install();
                } else {
                    crate::hooks::watchpoint::install_wp_hook(before_watchpoint_handler as *const c_void);
                }

                let node: KernelArc<HwbpNode> = KernelArc::new_zeroed().map_err(|_| Error::ENOMEM)?;
                let node_raw = node.as_raw();

                (*node_raw).pid = pid;
                (*node_raw).addr = addr;
                (*node_raw).bp_type = bp_type;
                (*node_raw).len = len;
                (*node_raw).scheme = 2;
                (*node_raw).active.store(true, Ordering::Release);
                (*node_raw).recovery_work.init(recovery_bp_work_func);

                let guard = BP_LIST_LOCK.lock();
                let bp_list_ptr = BP_LIST.get_ptr();
                (*bp_list_ptr).add_rcu(&mut (*node_raw).list);
                drop(guard);

                let _ = node.into_raw();

                if let Some(on_each_cpu) = crate::sym!(on_each_cpu) {
                    on_each_cpu(write_wp_regs_on_cpu, node_raw as *mut c_void, 1);
                }
                pr_info!("register_hwbp 方案 2: 初始化启用成功");
            }
            return Ok(());
        }
        1 => {
            let task = unsafe {
                let find_fn = crate::sym_must!(find_task_by_vpid);
                let task_ptr = find_fn(pid as i32);
                if task_ptr.is_null() {
                    return Err(Error::ESRCH);
                }
                task_ptr
            };

            let size = if unsafe { crate::ffi::kver >= ((6 << 16) + (0 << 8) + 0) } {
                136
            } else {
                112
            };

            let mut attr = PerfEventAttr::new(bp_type, size);
            attr.set_disabled(false);
            attr.set_exclude_kernel(true);
            attr.set_exclude_hv(true);
            attr.bp_addr = addr;
            attr.bp_len = len as u64;

            unsafe {
                let reg_fn = crate::sym!(register_user_hw_breakpoint).ok_or(Error::ENOSYS)?;
                let bp = reg_fn(&mut attr, hwbp_triggered, core::ptr::null_mut(), task);
                let bp_err = bp as isize;
                if bp_err < 0 && bp_err > -4096 {
                    pr_err!("register_hwbp: 硬件断点注册失败, 错误码={}", bp_err);
                    return Err(Error::from(bp_err as i32));
                }

                let node: KernelArc<HwbpNode> = match KernelArc::new_zeroed() {
                    Ok(n) => n,
                    Err(e) => {
                        if let Some(unreg_fn) = crate::sym!(unregister_hw_breakpoint) {
                            unreg_fn(bp);
                        }
                        return Err(Error::from(e));
                    }
                };

                let node_raw = node.as_raw();
                (*node_raw).bp = bp;
                (*node_raw).pid = pid;
                (*node_raw).addr = addr;
                (*node_raw).bp_type = bp_type;
                (*node_raw).len = len;
                (*node_raw).scheme = scheme;
                (*node_raw).orig_attr = attr;
                (*node_raw).active.store(true, Ordering::Release);
                (*node_raw).recovery_work.init(recovery_bp_work_func);

                let guard = BP_LIST_LOCK.lock();
                let bp_list_ptr = BP_LIST.get_ptr();
                (*bp_list_ptr).add_rcu(&mut (*node_raw).list);
                drop(guard);

                let _ = node.into_raw();

                if let Some(enable_fn) = crate::sym!(perf_event_enable) {
                    enable_fn(bp);
                }
                pr_info!("register_hwbp: 注册成功, bp指针={:p}", bp);
            }
        }
        _ => {
            pr_err!("register_hwbp: 不支持的方案 {}，仅支持方案 1 和 2", scheme);
            return Err(Error::EINVAL);
        }
    }

    Ok(())
}

/// 注销指定地址 of 进程硬件断点
pub fn unregister_hwbp(pid: u32, addr: u64) -> Result<(), Error> {
    let mut target_node: *mut HwbpNode = core::ptr::null_mut();

    let guard = BP_LIST_LOCK.lock();
    let bp_list_ptr = BP_LIST.get_ptr();
    let mut curr = unsafe { (*bp_list_ptr).next };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        if unsafe { (*node).pid == pid && (*node).addr == addr } {
            unsafe {
                (*node).active.store(false, Ordering::Release);
                (*curr).del_rcu();
            };
            target_node = node;
            break;
        }
        curr = unsafe { (*curr).next };
    }
    drop(guard);

    if target_node.is_null() {
        return Err(Error::ENOENT);
    }

    unsafe {
        let arc = KernelArc::from_raw_transferred(target_node);
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        (*target_node).unreg_work.init(unregister_bp_work_func);

        if let Some(queue_fn) = crate::sym!(queue_work_on) {
            let success = queue_fn(
                0,
                crate::sym!(system_wq),
                &mut (*target_node).unreg_work as *mut _ as *mut c_void,
            );
            if success != 0 {
                // 入队成功，转移所有权给工作项
                let _ = arc.into_raw();
            }
            // 若 success == 0，表明排队失败。arc 将在此作用域结束时被自动 Drop 释放。
            // 物理释放时，其 Drop 会自动执行 IN_FLIGHT.fetch_sub(1)，因此此处无需手动扣减。
        } else {
            // 无 queue_work_on 符号，同步调用
            let raw_node = arc.into_raw();
            unregister_bp_work_func(&mut (*raw_node).unreg_work);
        }
    }

    Ok(())
}

/// 注销所有的硬件断点
pub fn unregister_all_hwbp() -> Result<(), Error> {
    let mut head_to_free: *mut HwbpNode = core::ptr::null_mut();

    let guard = BP_LIST_LOCK.lock();
    unsafe {
        let bp_list_ptr = BP_LIST.get_ptr();
        let mut curr = (*bp_list_ptr).next;
        while curr != bp_list_ptr {
            let next = (*curr).next;
            let node_offset = core::mem::offset_of!(HwbpNode, list);
            let node = (curr as usize - node_offset) as *mut HwbpNode;
            (*node).active.store(false, Ordering::Release);
            (*curr).del_rcu();

            // 使用 unreg_work.data 串联临时单向链表
            (*node).unreg_work.data = head_to_free as usize;
            head_to_free = node;

            curr = next;
        }
    }
    drop(guard);

    let mut curr_node = head_to_free;
    while !curr_node.is_null() {
        unsafe {
            let next_node = (*curr_node).unreg_work.data as *mut HwbpNode;
            let arc = KernelArc::from_raw_transferred(curr_node);

            IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
            (*curr_node).unreg_work.init(unregister_bp_work_func);

            if let Some(queue_fn) = crate::sym!(queue_work_on) {
                let success = queue_fn(
                    0,
                    crate::sym!(system_wq),
                    &mut (*curr_node).unreg_work as *mut _ as *mut c_void,
                );
                if success != 0 {
                    let _ = arc.into_raw();
                }
            } else {
                let raw_node = arc.into_raw();
                unregister_bp_work_func(&mut (*raw_node).unreg_work);
            }

            curr_node = next_node;
        }
    }

    Ok(())
}

/// 安全读取进程的硬件断点触发记录，拷贝至用户缓冲区，并在读取后清空
pub fn read_hwbp_info(
    pid: u32,
    max_count: u64,
    user_buf: *mut c_void,
    actual_count: &mut u64,
) -> Result<(), Error> {
    if max_count == 0 || user_buf.is_null() {
        return Err(Error::EINVAL);
    }

    let malloc_fn = crate::sym_must!(kmalloc);
    let temp_records_ptr = unsafe {
        malloc_fn(
            16 * core::mem::size_of::<HwbpHitRecord>(),
            0x20u32,
        )
    } as *mut HwbpHitRecord;
    if temp_records_ptr.is_null() {
        return Err(Error::ENOMEM);
    }

    struct TempRecordsGuard(*mut HwbpHitRecord);
    impl Drop for TempRecordsGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let free_fn = crate::sym_must!(kfree);
                unsafe { free_fn(self.0 as *const c_void); }
            }
        }
    }
    let _records_guard = TempRecordsGuard(temp_records_ptr);

    let mut count_to_copy = 0;
    let mut _found_node: Option<KernelArc<HwbpNode>> = None;

    // 读者保护 of RcuReadGuard
    let _rcu_guard = crate::sync::RcuReadGuard::new();

    let bp_list_ptr = BP_LIST.get_ptr();
    let mut curr = unsafe { (*bp_list_ptr).next_rcu() };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        unsafe {
            if (*node).pid == pid {
                // 找到节点，递增引用并存入 Option 以保证其在函数运行期间的强引用生命周期
                _found_node = Some(KernelArc::from_raw(node));

                let head = (*node).hit_record_head.load(Ordering::Acquire);
                let mut tail = (*node).hit_record_tail.load(Ordering::Acquire);

                // 极端溢出处理：若生产端积压超过一整圈（16条），强制推进读取游标丢弃旧数据
                if head > tail + 16 {
                    tail = head - 16;
                }

                let available = core::cmp::min((head - tail) as usize, max_count as usize);
                let limit = core::cmp::min(available, 16);

                let mut i = 0;
                while i < limit {
                    let idx = (tail % 16) as usize;
                    let rec = &(*node).hit_records[idx];
                    let seq_atom = &(*node).hit_record_seqs[idx];

                    let mut success = false;
                    let mut rec_val = HwbpHitRecord {
                        hit_time: 0,
                        task_id: 0,
                        _pad: 0,
                        hit_addr: 0,
                        regs_info: crate::ipc::protocol::HwbpRegsSnapshot {
                            regs: [0; 31],
                            sp: 0,
                            pc: 0,
                            pstate: 0,
                        },
                    };

                    // 尝试读取，若发生冲突则重试最多 10 次
                    for _ in 0..10 {
                        let seq1 = seq_atom.load(Ordering::Acquire);
                        if seq1 % 2 != 0 {
                            // 奇数表示正在写入，重试
                            core::hint::spin_loop();
                            continue;
                        }
                        // 读取记录
                        rec_val = core::ptr::read_volatile(rec as *const HwbpHitRecord);
                        crate::sync::smp_rmb(); // 确保读数据完成后才二次检查序列号
                        let seq2 = seq_atom.load(Ordering::Acquire);
                        if seq1 == seq2 {
                            success = true;
                            break;
                        }
                    }

                    if !success {
                        // 重试失败或正在写入，终止本次读取，留待下次
                        break;
                    }

                    // 校验读取到的数据是否有效（初始状态为 0）
                    if rec_val.hit_time == 0 {
                        break;
                    }

                    core::ptr::write(temp_records_ptr.add(i), rec_val);
                    tail += 1;
                    i += 1;
                }
                
                count_to_copy = i;
                
                // 将推进后的游标反馈回结构体，下一次 IPC 将从新起点拉取
                (*node).hit_record_tail.store(tail, Ordering::Release);
                break;
            }
        }

        curr = unsafe { (*curr).next_rcu() };
    }

    // 【修复】：显式释放 RCU 读锁，防止后续 copy_to_user 缺页休眠导致死锁
    drop(_rcu_guard);

    // 锁已被全部安全释放，可以自由进行可能导致睡眠/缺页 of 拷贝
    use crate::mm::copy_to_user;
    use zerocopy::IntoBytes;
    for i in 0..count_to_copy {
        let dst = (user_buf as usize
            + i * core::mem::size_of::<HwbpHitRecord>()) as *mut c_void;
        let record_ref = unsafe { &*temp_records_ptr.add(i) };
        if (dst as usize) >= 0xffff000000000000usize {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    record_ref.as_bytes().as_ptr(),
                    dst as *mut u8,
                    core::mem::size_of::<HwbpHitRecord>(),
                );
            }
        } else {
            let copy_res = copy_to_user(dst, record_ref.as_bytes());
            if copy_res.is_err() {
                return Err(Error::EFAULT);
            }
        }
    }

    *actual_count = count_to_copy as u64;
    Ok(())
}
