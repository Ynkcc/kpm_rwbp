// OBSERVE 观测 Hook：拦截 perf_event_open / ptrace 下的硬件断点行为并记录
// 设计为纯观测（OBSERVE 模式）：所有拦截均真实放行，仅记录现场信息。
// 内核侧零结构体偏移：只采集 hook 参数与 pt_regs 原生字段，
// 路径归因（path/path_offset）由用户态消费端按 /proc/<pid>/maps 补全。

use core::ffi::c_int;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::ffi::hook_fargs4_t;
use crate::ipc::protocol::{ObserveRecord, OBSERVE_EVENT_PERF, OBSERVE_EVENT_PTRACE};
use crate::sync::RawSpinlock;
use crate::utils::Error;
use crate::mm::{copy_from_user, copy_to_user};
use zerocopy::IntoBytes;

const __NR_PERF_EVENT_OPEN: c_int = 241;
const __NR_PTRACE: c_int = 117;

// uapi 常量（非内核符号，跨版本稳定）
const PTRACE_SETREGSET: u64 = 0x4205;
const NT_ARM_HW_BREAK: u64 = 0x402;
const NT_ARM_HW_WATCH: u64 = 0x403;
const PERF_TYPE_BREAKPOINT: u32 = 5;

// user_hwdebug_state 完整大小: dbg_info(4) + pad(4) + dbg_regs[16]*16
const USER_HWDEBUG_STATE_SIZE: usize = 264;
// perf_event_attr 头部解析所需大小（截至 bp_len）
const PERF_ATTR_HEAD_SIZE: usize = 72;

// 观测记录环形缓冲容量
const OBSERVE_BUF_CAP: usize = 64;

static mut RECORDS: [ObserveRecord; OBSERVE_BUF_CAP] = [zeroed_record(); OBSERVE_BUF_CAP];
static RECORDS_LOCK: RawSpinlock = RawSpinlock::new();
static RECORD_COUNT: AtomicUsize = AtomicUsize::new(0);

const fn zeroed_record() -> ObserveRecord {
    ObserveRecord {
        event_type: 0, _pad0: 0, pid: 0, tid: 0,
        bp_addr: 0, bp_type: 0, bp_len: 0,
        caller_pc: 0, caller_lr: 0, path_offset: 0,
        path_len: 0, _pad1: 0, path: [0; 64],
    }
}

// ============================================================================
// 记录缓冲
// ============================================================================

unsafe fn push_record(rec: ObserveRecord) { unsafe {
    let _guard = RECORDS_LOCK.lock();
    let count = RECORD_COUNT.load(Ordering::SeqCst);
    if count < OBSERVE_BUF_CAP {
        RECORDS[count] = rec;
        RECORD_COUNT.store(count + 1, Ordering::SeqCst);
    } else {
        // 缓冲满：丢弃最旧一条（整体前移），追加到尾部
        for i in 1..OBSERVE_BUF_CAP {
            RECORDS[i - 1] = RECORDS[i];
        }
        RECORDS[OBSERVE_BUF_CAP - 1] = rec;
    }
}}

/// 消费式拉取指定 pid 的观测记录（与 OP_READ_HW_BP_INFO 语义一致）
pub unsafe fn read_observe_records(
    pid: u32,
    max_count: u64,
    user_buf: *mut c_void,
    actual_count: &mut u64,
) -> Result<(), Error> { unsafe {
    let rec_size = core::mem::size_of::<ObserveRecord>();
    let mut matched = 0u64;
    {
        let _guard = RECORDS_LOCK.lock();
        let count = RECORD_COUNT.load(Ordering::SeqCst);
        let mut write_idx = 0usize;
        for read_idx in 0..count {
            let rec = RECORDS[read_idx];
            if rec.pid == pid && matched < max_count {
                let dest = (user_buf as usize + (matched as usize) * rec_size) as *mut c_void;
                if let Err(err) = copy_to_user(dest, rec.as_bytes()) {
                    RECORD_COUNT.store(count, Ordering::SeqCst);
                    return Err(err);
                }
                matched += 1;
            } else {
                // 不匹配或超限的记录保留（原地压缩）
                RECORDS[write_idx] = rec;
                write_idx += 1;
            }
        }
        RECORD_COUNT.store(write_idx, Ordering::SeqCst);
    }
    *actual_count = matched;
    Ok(())
}}

// ============================================================================
// 现场信息提取
// ============================================================================

// 发起者线程的用户态 pt_regs：has_syscall_wrapper 时 fargs.args[0] 即当前 task 的 pt_regs
unsafe fn caller_regs(args: *mut hook_fargs4_t) -> Option<*mut crate::hwbp::core::PtRegs> { unsafe {
    if crate::ffi::has_syscall_wrapper == 0 {
        return None;
    }
    let fargs = args as *mut crate::ffi::HookFargs0;
    let pt_regs = (*fargs).args[0] as *mut crate::hwbp::core::PtRegs;
    if pt_regs.is_null() {
        None
    } else {
        Some(pt_regs)
    }
}}

// pid/tid 经 __task_pid_nr_ns 获取（KP 的 tgid/pid 偏移在部分设备上未填充，不可直接读）
// PIDTYPE_PID=0 恒定；tgid: 4.15+ 为 PIDTYPE_TGID=1，4.14 为 __PIDTYPE_TGID=3
unsafe fn fill_caller_info(args: *mut hook_fargs4_t, rec: &mut ObserveRecord) { unsafe {
    if let Some(pt_regs) = caller_regs(args) {
        rec.caller_lr = (*pt_regs).regs[30];
        rec.caller_pc = (*pt_regs).pc;
    }
    let Some(pid_fn) = crate::sym!(__task_pid_nr_ns) else { return };
    let current = crate::ffi::get_current();
    rec.tid = pid_fn(current, 0, core::ptr::null_mut()) as u32;
    let tgid_type = if unsafe { crate::ffi::kver } >= (4 << 16) + (15 << 8) { 1 } else { 3 };
    rec.pid = pid_fn(current, tgid_type, core::ptr::null_mut()) as u32;
}}

// ============================================================================
// Hook 回调
// ============================================================================

// perf_event_open(attr, pid, cpu, group_fd, flags) before 回调
pub unsafe extern "C" fn observe_perf_hook(args: *mut hook_fargs4_t, _udata: *mut c_void) { unsafe {
    let attr_ptr = crate::hooks::syscall::get_syscall_arg(args as *mut c_void, 0);
    let target_pid = crate::hooks::syscall::get_syscall_arg(args as *mut c_void, 1) as i32;
    if attr_ptr == 0 {
        return;
    }

    // 先读 attr 头部拿 type/size，仅关心硬件断点事件
    let mut head = [0u8; 8];
    if copy_from_user(&mut head, attr_ptr as *const c_void).is_err() {
        return;
    }
    let attr_type = u32::from_ne_bytes(head[0..4].try_into().unwrap());
    if attr_type != PERF_TYPE_BREAKPOINT {
        return;
    }
    let attr_size = u32::from_ne_bytes(head[4..8].try_into().unwrap()) as usize;
    let read_size = core::cmp::min(attr_size, PERF_ATTR_HEAD_SIZE);
    if read_size < 8 {
        return;
    }

    let mut attr = [0u8; PERF_ATTR_HEAD_SIZE];
    if copy_from_user(&mut attr[..read_size], attr_ptr as *const c_void).is_err() {
        return;
    }

    let mut rec = zeroed_record();
    rec.event_type = OBSERVE_EVENT_PERF;
    rec.bp_type = u64::from(u32::from_ne_bytes(attr[52..56].try_into().unwrap()));
    rec.bp_addr = u64::from_ne_bytes(attr[56..64].try_into().unwrap());
    rec.bp_len = u64::from_ne_bytes(attr[64..72].try_into().unwrap());

    fill_caller_info(args, &mut rec);

    // pid 记为 bp_addr 归属进程：target_pid==0 表示发起者自身，>0 表示被观测目标
    if target_pid > 0 {
        rec.pid = target_pid as u32;
    }

    push_record(rec);
}}

// ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK/WATCH, data) before 回调
pub unsafe extern "C" fn observe_ptrace_hook(args: *mut hook_fargs4_t, _udata: *mut c_void) { unsafe {
    let request = crate::hooks::syscall::get_syscall_arg(args as *mut c_void, 0);
    let tracee_pid = crate::hooks::syscall::get_syscall_arg(args as *mut c_void, 1) as i32;
    let nt_type = crate::hooks::syscall::get_syscall_arg(args as *mut c_void, 2);
    let data_ptr = crate::hooks::syscall::get_syscall_arg(args as *mut c_void, 3);

    if request != PTRACE_SETREGSET || data_ptr == 0 {
        return;
    }
    if nt_type != NT_ARM_HW_BREAK && nt_type != NT_ARM_HW_WATCH {
        return;
    }

    // data 指向用户态 iovec {base, len}
    let mut iov = [0u8; 16];
    if copy_from_user(&mut iov, data_ptr as *const c_void).is_err() {
        return;
    }
    let iov_base = u64::from_ne_bytes(iov[0..8].try_into().unwrap());
    let iov_len = u64::from_ne_bytes(iov[8..16].try_into().unwrap());
    if iov_base == 0 || iov_len < 8 {
        return;
    }

    let read_size = core::cmp::min(iov_len as usize, USER_HWDEBUG_STATE_SIZE);
    let mut state = [0u8; USER_HWDEBUG_STATE_SIZE];
    if copy_from_user(&mut state[..read_size], iov_base as *const c_void).is_err() {
        return;
    }

    let mut rec = zeroed_record();
    rec.event_type = OBSERVE_EVENT_PTRACE;
    rec.bp_type = nt_type;
    rec.bp_len = iov_len;
    // user_hwdebug_state: dbg_info(4) + pad(4) 后为 dbg_regs[0].addr
    rec.bp_addr = u64::from_ne_bytes(state[8..16].try_into().unwrap());

    fill_caller_info(args, &mut rec);

    // bp_addr 属于被 trace 的目标进程
    if tracee_pid > 0 {
        rec.pid = tracee_pid as u32;
    }

    push_record(rec);
}}

// ============================================================================
// 安装 / 卸载
// ============================================================================

pub unsafe fn install_observe_hooks() -> Result<(), Error> { unsafe {
    let ret_perf = crate::ffi::hook_syscalln(
        __NR_PERF_EVENT_OPEN,
        5,
        observe_perf_hook as *const c_void,
        core::ptr::null(),
        core::ptr::null_mut(),
    );
    if ret_perf != 0 {
        pr_err!("observe: hook perf_event_open 失败: {}", ret_perf);
        return Err(Error::EINVAL);
    }

    let ret_ptrace = crate::ffi::hook_syscalln(
        __NR_PTRACE,
        4,
        observe_ptrace_hook as *const c_void,
        core::ptr::null(),
        core::ptr::null_mut(),
    );
    if ret_ptrace != 0 {
        pr_err!("observe: hook ptrace 失败: {}", ret_ptrace);
        crate::ffi::unhook_syscalln(
            __NR_PERF_EVENT_OPEN,
            observe_perf_hook as *const c_void,
            core::ptr::null(),
        );
        return Err(Error::EINVAL);
    }

    pr_info!("observe: perf_event_open/ptrace 观测 hook 已挂载");
    Ok(())
}}

pub unsafe fn remove_observe_hooks() { unsafe {
    crate::ffi::unhook_syscalln(
        __NR_PERF_EVENT_OPEN,
        observe_perf_hook as *const c_void,
        core::ptr::null(),
    );
    crate::ffi::unhook_syscalln(
        __NR_PTRACE,
        observe_ptrace_hook as *const c_void,
        core::ptr::null(),
    );
    RECORD_COUNT.store(0, Ordering::SeqCst);
}}
