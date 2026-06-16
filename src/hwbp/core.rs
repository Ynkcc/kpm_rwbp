// 硬件断点/监视点核心业务与生命周期管理

use crate::ffi::{get_current, PerfEventAttr};
use crate::sync::RawSpinlock;
use crate::utils::ListHead;
use core::ffi::c_void;
use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, AtomicU64, Ordering, AtomicBool};
use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};

// 全局状态变量
pub static mut BP_LIST: ListHead = ListHead {
    next: core::ptr::null_mut(),
    prev: core::ptr::null_mut(),
};
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
    pub is_temp_bp: bool,
    pub recovery_work: WorkStruct,
    pub scheme: u32,
    pub next_instruction_attr: PerfEventAttr,
    pub hit_records: [HwbpHitRecord; 16],
    pub hit_record_head: u32,
    pub hit_record_count: u32,
    pub hit_records_lock: RawSpinlock,
    pub active: AtomicBool,
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

#[inline(always)] pub unsafe fn read_wcr(n: i32) -> u64 { read_sysreg!(dbgwcr, n) }
#[inline(always)] pub unsafe fn write_wcr(n: i32, val: u64) { write_sysreg!(dbgwcr, n, val); }
#[inline(always)] unsafe fn read_wvr(n: i32) -> u64 { read_sysreg!(dbgwvr, n) }
#[inline(always)] unsafe fn write_wvr(n: i32, val: u64) { write_sysreg!(dbgwvr, n, val); }
#[inline(always)] unsafe fn read_bcr(n: i32) -> u64 { read_sysreg!(dbgbcr, n) }
#[inline(always)] unsafe fn write_bcr(n: i32, val: u64) { write_sysreg!(dbgbcr, n, val); }
#[inline(always)] unsafe fn read_bvr(n: i32) -> u64 { read_sysreg!(dbgbvr, n) }
#[inline(always)] unsafe fn write_bvr(n: i32, val: u64) { write_sysreg!(dbgbvr, n, val); }

unsafe fn read_wb_reg(reg_idx: i32, n: i32) -> u64 {
    if reg_idx == 0 { // DBG_REG_BVR
        read_bvr(n)
    } else if reg_idx == 16 { // DBG_REG_BCR
        read_bcr(n)
    } else if reg_idx == 32 { // DBG_REG_WVR
        read_wvr(n)
    } else if reg_idx == 48 { // DBG_REG_WCR
        read_wcr(n)
    } else {
        0
    }
}

unsafe fn write_wb_reg(reg_idx: i32, n: i32, val: u64) {
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
        (16, 0, 6) // BCR, BVR
    } else {
        (48, 32, 4) // WCR, WVR
    };

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
    pr_warn!("toggle_bp_registers_directly: 未找到匹配地址 0x{:x} 的插槽！", hw_addr);
    false
}

/// 临时失效期满后，恢复硬件断点
pub unsafe extern "C" fn recovery_bp_work_func(work: *mut WorkStruct) {
    let node_offset = core::mem::offset_of!(HwbpNode, recovery_work);
    let node = (work as usize - node_offset) as *mut HwbpNode;
    pr_info!("recovery_bp_work_func: 恢复断点 {:p}, 方案 {}", (*node).bp, (*node).scheme);

    if (*node).scheme == 3 {
        if let Some(on_each_cpu) = crate::sym!(on_each_cpu) {
            on_each_cpu(write_wp_regs_on_cpu, node as *mut c_void, 0);
        }
    } else if !(*node).bp.is_null() {
        if let Some(enable_fn) = crate::sym!(perf_event_enable) {
            enable_fn((*node).bp);
        }
    }
    (*node).is_temp_bp = false;
}

pub unsafe extern "C" fn write_wp_regs_on_cpu(info: *mut c_void) {
    let node = info as *mut HwbpNode;
    let hw_addr = calc_hw_addr((*node).addr, (*node).bp_type, (*node).len);
    write_wb_reg(32, 0, hw_addr); // WVR0
    let ctrl = 1 | (3 << 1) | (3 << 3) | (0xff << 5);
    write_wb_reg(48, 0, ctrl); // WCR0

    // 在 MDSCR_EL1 中使能监视点
    let mut mdscr: u64 = 0;
    core::arch::asm!("mrs {}, mdscr_el1", out(reg) mdscr);
    mdscr |= 1u64 << 15;
    core::arch::asm!("msr mdscr_el1, {}", in(reg) mdscr);
    core::arch::asm!("isb");
}

unsafe extern "C" fn disable_wp_regs_on_cpu(_info: *mut c_void) {
    write_wb_reg(48, 0, 0); // WCR0
    write_wb_reg(32, 0, 0); // WVR0
}

unsafe extern "C" fn unregister_bp_work_func(work: *mut WorkStruct) {
    let node_offset = core::mem::offset_of!(HwbpNode, unreg_work);
    let node = (work as usize - node_offset) as *mut HwbpNode;

    if (*node).scheme == 3 {
        if let Some(on_each_cpu) = crate::sym!(on_each_cpu) {
            on_each_cpu(disable_wp_regs_on_cpu, core::ptr::null_mut(), 0);
        }
    } else if !(*node).bp.is_null() {
        if let Some(unreg_fn) = crate::sym!(unregister_hw_breakpoint) {
            unreg_fn((*node).bp);
        }
    }

    if let Some(free_fn) = crate::sym!(kfree) {
        free_fn(node as *const c_void);
    }
    IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
}

/// ARM64 处理器寄存器布局
#[repr(C)]
pub struct PtRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

// Hook callback structures for Scheme 3 watchpoint
#[repr(C, align(8))]
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
pub struct HookLocal {
    pub data: [u64; 8],
}

/// Scheme 3 watchpoint 拦截钩子回调函数（公开供 hooks 模块在卸载时使用）
pub unsafe extern "C" fn before_watchpoint_handler(args: *mut HookFargs3, _udata: *mut c_void) {
    let addr = (*args).arg0;
    let regs = (*args).arg2 as *mut PtRegs;
    let mut found_node: *mut HwbpNode = core::ptr::null_mut();

    let guard = BP_LIST_LOCK.lock();
    let bp_list_ptr = &raw mut BP_LIST;
    let mut curr = unsafe { (*bp_list_ptr).next };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        if unsafe { (*node).scheme == 3 } {
            let task = get_current();
            let pid = if let Some(pid_fn) = crate::sym!(__task_pid_nr_ns) {
                pid_fn(task, 0, core::ptr::null_mut()) as u32
            } else {
                0
            };
            if unsafe { (*node).pid == pid && (*node).active.load(Ordering::SeqCst) } {
                let hw_addr = calc_hw_addr((*node).addr, (*node).bp_type, (*node).len);
                if (addr & !7u64) == hw_addr {
                    if !(*node).is_temp_bp {
                        (*node).hit_count.fetch_add(1, Ordering::Relaxed);
                        (*node).is_temp_bp = true;
                        found_node = node;
                    }
                    break;
                }
            }
        }
        curr = unsafe { (*curr).next };
    }
    drop(guard);

    if !found_node.is_null() {
        pr_info!(
            "Scheme 3 Hooked watchpoint triggered! addr=0x{:x}, PC=0x{:x}",
            addr,
            if regs.is_null() { 0 } else { (*regs).pc }
        );

        if !regs.is_null() {
            let rec_guard = unsafe { (*found_node).hit_records_lock.lock() };
            let head = unsafe { (*found_node).hit_record_head as usize };
            let rec = unsafe { &mut (*found_node).hit_records[head] };
            if let Some(mono_ns_fn) = crate::sym!(ktime_get_mono_fast_ns) {
                rec.hit_time = mono_ns_fn();
            }
            let task = get_current();
            if let Some(pid_fn) = crate::sym!(__task_pid_nr_ns) {
                rec.task_id = pid_fn(task, 0, core::ptr::null_mut()) as u32;
            }
            rec.hit_addr = unsafe { (*found_node).addr };
            let regs_ref = unsafe { &*regs };
            rec.regs_info.pc = regs_ref.pc;
            rec.regs_info.sp = regs_ref.sp;
            rec.regs_info.pstate = regs_ref.pstate;
            rec.regs_info.regs.copy_from_slice(&regs_ref.regs[..31]);

            unsafe {
                (*found_node).hit_record_head = ((*found_node).hit_record_head + 1) % 16;
                if (*found_node).hit_record_count < 16 {
                    (*found_node).hit_record_count += 1;
                }
            }
            drop(rec_guard);
        }

        let ctrl = read_wcr(0);
        write_wcr(0, ctrl & !1u64);

        if let Some(queue_fn) = crate::sym!(queue_work_on) {
            queue_fn(0, crate::sym!(system_wq), &mut (*found_node).recovery_work as *mut _ as *mut c_void);
        }
    }
}

/// 硬件调试断点（perf_event）触发的回调函数
unsafe extern "C" fn hwbp_triggered(bp: *mut c_void, _data: *mut c_void, regs: *mut c_void) {
    let pt_regs = regs as *mut PtRegs;
    pr_info!("hwbp_triggered 触发! bp={:p}", bp);

    let mut found_node: *mut HwbpNode = core::ptr::null_mut();
    let guard = BP_LIST_LOCK.lock();
    let bp_list_ptr = &raw mut BP_LIST;
    let mut curr = unsafe { (*bp_list_ptr).next };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        if unsafe { (*node).bp == bp && (*node).active.load(Ordering::SeqCst) } {
            found_node = node;
            break;
        }
        curr = unsafe { (*curr).next };
    }
    drop(guard);

    if found_node.is_null() {
        pr_warn!("hwbp_triggered: 未找到对应的 HwbpNode，bp={:p}", bp);
        return;
    }

    if unsafe { (*found_node).scheme != 2 && (*found_node).is_temp_bp } {
        return;
    }

    unsafe { (*found_node).hit_count.fetch_add(1, Ordering::Relaxed) };

    if !pt_regs.is_null() {
        let rec_guard = unsafe { (*found_node).hit_records_lock.lock() };
        let head = unsafe { (*found_node).hit_record_head as usize };
        let rec = unsafe { &mut (*found_node).hit_records[head] };
        if let Some(mono_ns_fn) = crate::sym!(ktime_get_mono_fast_ns) {
            rec.hit_time = mono_ns_fn();
        }
        let task = unsafe { get_current() };
        if let Some(pid_fn) = crate::sym!(__task_pid_nr_ns) {
            rec.task_id = pid_fn(task, 0, core::ptr::null_mut()) as u32;
        }
        rec.hit_addr = unsafe { (*found_node).addr };
        let pt_regs_ref = unsafe { &*pt_regs };
        rec.regs_info.pc = pt_regs_ref.pc;
        rec.regs_info.sp = pt_regs_ref.sp;
        rec.regs_info.pstate = pt_regs_ref.pstate;
        rec.regs_info.regs.copy_from_slice(&pt_regs_ref.regs[..31]);

        unsafe {
            (*found_node).hit_record_head = ((*found_node).hit_record_head + 1) % 16;
            if (*found_node).hit_record_count < 16 {
                (*found_node).hit_record_count += 1;
            }
        }
        drop(rec_guard);
    }

    pr_info!("=== 硬件断点命中 ===");
    pr_info!(
        "PID: {}, 地址: 0x{:x}, 命中次数: {}",
        (*found_node).pid,
        (*found_node).addr,
        (*found_node).hit_count.load(Ordering::Relaxed)
    );
    pr_info!("PC 地址: 0x{:x}", if pt_regs.is_null() { 0 } else { (*pt_regs).pc });

    if let Some(dump_fn) = crate::sym!(dump_stack) {
        dump_fn();
    }

    match (*found_node).scheme {
        1 | 4 => {
            if let Some(disable_fn) = crate::sym!(perf_event_disable_inatomic) {
                disable_fn(bp);
            }
            (*found_node).is_temp_bp = true;
            if let Some(queue_fn) = crate::sym!(queue_work_on) {
                queue_fn(
                    0,
                    crate::sym!(system_wq),
                    &mut (*found_node).recovery_work as *mut _ as *mut c_void,
                );
            }
        }
        2 => {
            if !(*found_node).is_temp_bp {
                if !pt_regs.is_null()
                    && arm64_move_bp_to_next_instruction(
                        bp,
                        (*pt_regs).pc + 4,
                        &mut (*found_node).orig_attr,
                        &mut (*found_node).next_instruction_attr,
                    )
                {
                    (*found_node).is_temp_bp = true;
                } else {
                    pr_err!("方案 2: 转移硬件断点到下一条指令失败！");
                    if let Some(disable_fn) = crate::sym!(perf_event_disable_inatomic) {
                        disable_fn(bp);
                    }
                }
            } else {
                if arm64_recovery_bp_to_original(
                    bp,
                    &mut (*found_node).orig_attr,
                    &mut (*found_node).next_instruction_attr,
                ) {
                    (*found_node).is_temp_bp = false;
                } else {
                    pr_err!("方案 2: 恢复原始硬件断点失败！");
                    if let Some(disable_fn) = crate::sym!(perf_event_disable_inatomic) {
                        disable_fn(bp);
                    }
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
}

unsafe fn arm64_move_bp_to_next_instruction(
    bp: *mut c_void,
    next_instruction_addr: u64,
    original_attr: &mut PerfEventAttr,
    next_instruction_attr: &mut PerfEventAttr,
) -> bool {
    if bp.is_null() || next_instruction_addr == 0 {
        return false;
    }
    core::ptr::copy_nonoverlapping(
        original_attr as *const PerfEventAttr,
        next_instruction_attr as *mut PerfEventAttr,
        1,
    );
    next_instruction_attr.bp_addr = next_instruction_addr;
    next_instruction_attr.bp_len = 4;
    next_instruction_attr.bp_type = 4; // HW_BREAKPOINT_X
    next_instruction_attr.set_disabled(false);

    if let Some(modify_fn) = crate::sym!(modify_user_hw_breakpoint) {
        let ret = modify_fn(bp, next_instruction_attr);
        if ret == 0 {
            return true;
        }
    }
    next_instruction_attr.bp_addr = 0;
    false
}

unsafe fn arm64_recovery_bp_to_original(
    bp: *mut c_void,
    original_attr: &mut PerfEventAttr,
    next_instruction_attr: &mut PerfEventAttr,
) -> bool {
    if bp.is_null() {
        return false;
    }
    if let Some(modify_fn) = crate::sym!(modify_user_hw_breakpoint) {
        let ret = modify_fn(bp, original_attr);
        if ret == 0 {
            next_instruction_attr.bp_addr = 0;
            return true;
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
) -> Result<(), i32> {
    pr_info!("register_hwbp: PID={}, 地址=0x{:x}, 类型={}, 长度={}, 方案={}", pid, addr, bp_type, len, scheme);

    // 检查重复注册
    let guard = BP_LIST_LOCK.lock();
    let bp_list_ptr = &raw mut BP_LIST;
    let mut curr = unsafe { (*bp_list_ptr).next };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        if unsafe { (*node).pid == pid && (*node).addr == addr } {
            // 尽早显式释放锁以符合优化实践
            drop(guard);
            return Err(-17); // EEXIST
        }
        curr = unsafe { (*curr).next };
    }
    drop(guard);

    if scheme == 3 {
        unsafe {
            // 延迟加载 watchpoint hook （注意：该功能重构后将由 hooks 模块具体执行注册，我们直接通过 extern 动态加载）
            // 在此我们需要确保 hooks 里的 watchpoint hook 能够正常注册
            let install_fn: Option<unsafe extern "C" fn()> = crate::ffi::lookup_sym("watchpoint_handler_install_hook_helper"); 
            if let Some(install) = install_fn {
                install();
            } else {
                // 如果没有辅助全局函数，通过 watchpoint_handler 导入
                // 由于重构为 hooks/watchpoint.rs，我们只需在 hooks/watchpoint.rs 导出相应公开绑定
                // 或直接在此内部调用 hooks::watchpoint::install_wp_hook()
                crate::hooks::watchpoint::install_wp_hook(before_watchpoint_handler as *const c_void);
            }

            let malloc_fn = crate::sym!(__kmalloc).ok_or(-38)?;
            let node_ptr = malloc_fn(core::mem::size_of::<HwbpNode>(), 0x20u32) as *mut HwbpNode; // GFP_ATOMIC
            if node_ptr.is_null() {
                return Err(-12); // ENOMEM
            }
            core::ptr::write_bytes(node_ptr as *mut u8, 0, core::mem::size_of::<HwbpNode>());

            (*node_ptr).bp = core::ptr::null_mut();
            (*node_ptr).pid = pid;
            (*node_ptr).addr = addr;
            (*node_ptr).bp_type = bp_type;
            (*node_ptr).len = len;
            (*node_ptr).scheme = 3;
            (*node_ptr).hit_count = AtomicU64::new(0);
            (*node_ptr).is_temp_bp = false;
            (*node_ptr).hit_record_head = 0;
            (*node_ptr).hit_record_count = 0;
            (*node_ptr).hit_records_lock = RawSpinlock::new();
            (*node_ptr).recovery_work.init(recovery_bp_work_func);
            (*node_ptr).active = AtomicBool::new(true);

            let guard = BP_LIST_LOCK.lock();
            let bp_list_ptr = &raw mut BP_LIST;
            (*bp_list_ptr).add(&mut (*node_ptr).list);
            drop(guard);

            if let Some(on_each_cpu) = crate::sym!(on_each_cpu) {
                on_each_cpu(write_wp_regs_on_cpu, node_ptr as *mut c_void, 0);
            }
            pr_info!("register_hwbp 方案 3: 初始化启用成功");
        }
        return Ok(());
    }

    let task = unsafe {
        let find_fn = crate::sym!(find_task_by_vpid).ok_or(-3)?; // ESRCH
        let task_ptr = find_fn(pid as i32);
        if task_ptr.is_null() {
            return Err(-3);
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
        let reg_fn = crate::sym!(register_user_hw_breakpoint).ok_or(-38)?;
        let bp = reg_fn(&mut attr, hwbp_triggered, core::ptr::null_mut(), task);
        let bp_err = bp as isize;
        if bp_err < 0 && bp_err > -4096 {
            pr_err!("register_hwbp: 硬件断点注册失败, 错误码={}", bp_err);
            return Err(bp_err as i32);
        }

        let malloc_fn = crate::sym!(__kmalloc).ok_or(-38)?;
        let node_ptr = malloc_fn(core::mem::size_of::<HwbpNode>(), 0x20u32) as *mut HwbpNode;
        if node_ptr.is_null() {
            if let Some(unreg_fn) = crate::sym!(unregister_hw_breakpoint) {
                unreg_fn(bp);
            }
            return Err(-12); // ENOMEM
        }
        core::ptr::write_bytes(node_ptr as *mut u8, 0, core::mem::size_of::<HwbpNode>());

        (*node_ptr).bp = bp;
        (*node_ptr).pid = pid;
        (*node_ptr).addr = addr;
        (*node_ptr).bp_type = bp_type;
        (*node_ptr).len = len;
        (*node_ptr).scheme = scheme;
        (*node_ptr).hit_count = AtomicU64::new(0);
        (*node_ptr).orig_attr = attr;
        (*node_ptr).is_temp_bp = false;
        (*node_ptr).hit_record_head = 0;
        (*node_ptr).hit_record_count = 0;
        (*node_ptr).hit_records_lock = RawSpinlock::new();
        (*node_ptr).recovery_work.init(recovery_bp_work_func);
        (*node_ptr).active = AtomicBool::new(true);

        let guard = BP_LIST_LOCK.lock();
        let bp_list_ptr = &raw mut BP_LIST;
        (*bp_list_ptr).add(&mut (*node_ptr).list);
        drop(guard);

        if let Some(enable_fn) = crate::sym!(perf_event_enable) {
            enable_fn(bp);
        }
        pr_info!("register_hwbp: 注册成功, bp指针={:p}", bp);
    }

    Ok(())
}

/// 注销指定地址的进程硬件断点
pub fn unregister_hwbp(pid: u32, addr: u64) -> Result<(), i32> {
    let mut target_node: *mut HwbpNode = core::ptr::null_mut();

    let guard = BP_LIST_LOCK.lock();
    let bp_list_ptr = &raw mut BP_LIST;
    let mut curr = unsafe { (*bp_list_ptr).next };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        if unsafe { (*node).pid == pid && (*node).addr == addr } {
            unsafe {
                (*node).active.store(false, Ordering::SeqCst);
                (*curr).del();
            };
            target_node = node;
            break;
        }
        curr = unsafe { (*curr).next };
    }
    drop(guard);

    if target_node.is_null() {
        return Err(-2); // ENOENT
    }

    unsafe {
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        (*target_node).unreg_work.init(unregister_bp_work_func);
        if let Some(queue_fn) = crate::sym!(queue_work_on) {
            let success = queue_fn(
                0,
                crate::sym!(system_wq),
                &mut (*target_node).unreg_work as *mut _ as *mut c_void,
            );
            if success == 0 {
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                unregister_bp_work_func(&mut (*target_node).unreg_work);
            }
        } else {
            IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
            unregister_bp_work_func(&mut (*target_node).unreg_work);
        }
    }

    Ok(())
}

/// 注销所有的硬件断点
pub fn unregister_all_hwbp() -> Result<(), i32> {
    // 建立临时的链表头，用以接收全局链表脱离开来的节点
    let mut temp_list = ListHead { next: core::ptr::null_mut(), prev: core::ptr::null_mut() };
    temp_list.init();

    // 在最小锁保护范围内摘除节点并挂入临时链表
    let guard = BP_LIST_LOCK.lock();
    unsafe {
        let bp_list_ptr = &raw mut BP_LIST;
        let mut curr = (*bp_list_ptr).next;
        while curr != bp_list_ptr {
            let next = (*curr).next;
            let node_offset = core::mem::offset_of!(HwbpNode, list);
            let node = (curr as usize - node_offset) as *mut HwbpNode;
            (*node).active.store(false, Ordering::SeqCst);
            (*curr).del();
            temp_list.add(curr);
            curr = next;
        }
    }
    drop(guard);

    // 此时已经完全释放了全局自旋锁，在没有任何锁的上下文中异步挂载注销工作项
    unsafe {
        let mut curr = temp_list.next;
        while curr != &raw mut temp_list {
            let next = (*curr).next;
            let node_offset = core::mem::offset_of!(HwbpNode, list);
            let node = (curr as usize - node_offset) as *mut HwbpNode;

            IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
            (*node).unreg_work.init(unregister_bp_work_func);
            if let Some(queue_fn) = crate::sym!(queue_work_on) {
                let success = queue_fn(
                    0,
                    crate::sym!(system_wq),
                    &mut (*node).unreg_work as *mut _ as *mut c_void,
                );
                if success == 0 {
                    IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                    unregister_bp_work_func(&mut (*node).unreg_work);
                }
            } else {
                IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
                unregister_bp_work_func(&mut (*node).unreg_work);
            }
            curr = next;
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
) -> Result<(), i32> {
    if max_count == 0 || user_buf.is_null() {
        return Err(-22); // EINVAL
    }

    // 在内核栈上保留最多 16 个记录的临时缓冲
    let mut temp_records = [unsafe { core::mem::zeroed::<HwbpHitRecord>() }; 16];
    let mut count_to_copy = 0;

    let guard = BP_LIST_LOCK.lock();
    let bp_list_ptr = &raw mut BP_LIST;
    let mut curr = unsafe { (*bp_list_ptr).next };
    while curr != bp_list_ptr {
        let node_offset = core::mem::offset_of!(HwbpNode, list);
        let node = (curr as usize - node_offset) as *mut HwbpNode;
        unsafe {
            if (*node).pid == pid {
                let rec_guard = (*node).hit_records_lock.lock();
                let count = (*node).hit_record_count;
                let head = (*node).hit_record_head;

                let limit = core::cmp::min(count as usize, 16);
                let limit = core::cmp::min(limit, max_count as usize);

                for i in 0..limit {
                    let idx = (head + 16 - count + i as u32) % 16;
                    temp_records[i] = (*node).hit_records[idx as usize];
                }
                count_to_copy = limit;

                // 清空记录标志
                (*node).hit_record_count = 0;
                (*node).hit_record_head = 0;

                drop(rec_guard);
                break;
            }
        }
        curr = unsafe { (*curr).next };
    }
    drop(guard);

    // 锁已被全部安全释放，可以自由进行可能导致睡眠/缺页的拷贝
    use crate::mm::copy_to_user;
    use zerocopy::IntoBytes;
    for i in 0..count_to_copy {
        let dst = (user_buf as usize
            + i * core::mem::size_of::<HwbpHitRecord>()) as *mut c_void;
        if (dst as usize) >= 0xffff000000000000usize {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    temp_records[i].as_bytes().as_ptr(),
                    dst as *mut u8,
                    core::mem::size_of::<HwbpHitRecord>(),
                );
            }
        } else {
            let copy_res = copy_to_user(dst, temp_records[i].as_bytes());
            if copy_res.is_err() {
                return Err(-14); // EFAULT
            }
        }
    }

    *actual_count = count_to_copy as u64;
    Ok(())
}
