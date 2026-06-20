// 内核符号声明 - 部分通过 KP 导出直接链接，部分通过运行时查找

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use crate::ffi::offsets::{TaskStructOffset, CredOffset};

/// 性能事件属性结构体
#[repr(C, align(8))]
pub struct PerfEventAttr {
    pub attr_type: u32,
    pub size: u32,
    pub config: u64,
    pub sample_period: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup_events: u32,
    pub bp_type: u32,
    pub bp_addr: u64,
    pub bp_len: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub __reserved_2: u16,
    pub __reserved_3: u32,
    pub __reserved_4: [u64; 2],
}

impl PerfEventAttr {
    pub fn new(bp_type: u32, size: u32) -> Self {
        let mut attr = unsafe { core::mem::zeroed::<Self>() };
        attr.attr_type = 5;
        attr.size = size;
        attr.bp_type = bp_type;
        attr.sample_period = 1;
        attr
    }

    pub fn set_disabled(&mut self, val: bool) {
        if val { self.flags |= 1 << 0; } else { self.flags &= !(1 << 0); }
    }

    pub fn set_exclude_kernel(&mut self, val: bool) {
        if val { self.flags |= 1 << 5; } else { self.flags &= !(1 << 5); }
    }

    pub fn set_exclude_hv(&mut self, val: bool) {
        if val { self.flags |= 1 << 6; } else { self.flags &= !(1 << 6); }
    }
}

// =============================================================================
// KP 核心导出符号 - 由 ELF 重定位自动解析，无需运行时查找
// 这些符号在 lib.rs 中直接调用
// =============================================================================

unsafe extern "C" {
    // 内核版本信息
    pub static kver: c_uint;

    // Hook 框架函数（直接调用，不通过 sym! 宏）
    pub fn hook_syscalln(
        nr: c_int,
        narg: c_int,
        before: *const c_void,
        after: *const c_void,
        udata: *mut c_void,
    ) -> i32;
    pub fn unhook_syscalln(nr: c_int, before: *const c_void, after: *const c_void);
    pub fn hook_wrap(
        func: *mut c_void,
        argno: i32,
        before: *const c_void,
        after: *const c_void,
        udata: *mut c_void,
    ) -> i32;
    pub fn hook_unwrap_remove(
        func: *mut c_void,
        before: *const c_void,
        after: *const c_void,
        remove: i32,
    );

    // 内核日志 - 注意：KP 导出的是函数指针变量的地址，需要解引用
    // 使用 static mut 来存储函数指针变量，调用时需要解引用
    #[link_name = "printk"]
    static mut printk_ptr: *mut c_void;

    // kallsyms（用于 lookup_sym） - 注意：KP 导出的是函数指针变量的地址
    #[link_name = "kallsyms_lookup_name"]
    static mut kallsyms_lookup_name_ptr: *mut c_void;

    // Task 扩展
    pub static task_ext_size: usize;
    pub fn reg_task_local(size: usize) -> isize;
    pub fn has_task_local(ext: *mut c_void, offset: isize) -> c_int;
    pub fn task_local_ptr(ext: *mut c_void, offset: isize) -> *mut c_void;

    // 结构体偏移（KP 导出）
    pub static mut task_struct_offset: TaskStructOffset;
    pub static mut cred_offset: CredOffset;
    pub static mut mm_struct_offset: super::offsets::MmStructOffset;

    // Syscall 表
    pub static sys_call_table: *mut c_void;
    pub static compat_sys_call_table: *mut c_void;
    pub static has_syscall_wrapper: c_int;
    pub static has_config_compat: c_int;

    // Raw syscall
    pub fn raw_syscall0(nr: c_int) -> i64;
    pub fn raw_syscall1(nr: c_int, a1: u64) -> i64;
    pub fn raw_syscall2(nr: c_int, a1: u64, a2: u64) -> i64;
    pub fn raw_syscall3(nr: c_int, a1: u64, a2: u64, a3: u64) -> i64;
    pub fn raw_syscall4(nr: c_int, a1: u64, a2: u64, a3: u64, a4: u64) -> i64;
    pub fn raw_syscall5(nr: c_int, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64;
    pub fn raw_syscall6(nr: c_int, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64;

    // 内核存储
    pub fn write_kstorage(
        gid: c_int,
        did: c_int,
        data: *const c_void,
        offset: usize,
        len: usize,
        is_user: c_int,
    ) -> c_int;
    pub fn read_kstorage(
        gid: c_int,
        did: c_int,
        data: *mut c_void,
        offset: usize,
        len: usize,
        is_user: c_int,
    ) -> c_int;
    pub fn get_kstorage(gid: c_int, did: c_int) -> *mut c_void;
    pub fn remove_kstorage(gid: c_int, did: c_int) -> c_int;

    // 热修补
    pub fn hotpatch(addrs: *const u64, values: *const u64, cnt: c_int) -> c_int;
    pub fn hotpatch_nosync(addr: u64, value: u64) -> c_int;

    // SU / 访问控制
    pub fn commit_su(uid: c_int, sctx: *const c_char) -> c_int;
    pub fn task_su(pid: c_int, to_uid: c_int, sctx: *const c_char) -> c_int;
    pub fn is_su_allow_uid(uid: c_int) -> c_int;
    pub fn su_add_allow_uid(uid: c_int, to_uid: c_int, sctx: *const c_char) -> c_int;
    pub fn su_remove_allow_uid(uid: c_int) -> c_int;
    pub fn su_allow_uid_nums() -> c_int;
    pub fn su_reset_path(path: *const c_char) -> c_int;
    pub fn su_get_path() -> *const c_char;
    pub fn set_ap_mod_exclude(uid: c_int, exclude: c_int) -> c_int;
    pub fn get_ap_mod_exclude(uid: c_int) -> c_int;
}

/// 调用 printk 函数（需要解引用 KP 导出的函数指针变量）
/// KP 导出的 printk 是函数指针变量的地址，不是函数地址
/// 注意：printk 是可变参数函数，我们使用 extern "C" 声明来支持可变参数
#[inline(always)]
pub unsafe fn printk(fmt: *const u8) -> c_int {
    // 解引用函数指针变量获取实际的 printk 函数地址
    let printk_addr = printk_ptr;
    // 使用函数指针类型来调用
    // 由于 printk 是可变参数函数，我们将其转换为固定参数函数指针
    // 只传递 fmt 参数，其他参数由调用者在格式化字符串中处理
    let printk_fn: extern "C" fn(*const u8) -> c_int = core::mem::transmute(printk_addr);
    printk_fn(fmt)
}

/// 调用 kallsyms_lookup_name 函数（需要解引用 KP 导出的函数指针变量）
#[inline(always)]
pub unsafe fn kallsyms_lookup_name(name: *const c_char) -> core::ffi::c_ulong {
    // 解引用函数指针变量获取实际的函数地址
    let kallsyms_addr = kallsyms_lookup_name_ptr;
    let kallsyms_fn: extern "C" fn(*const c_char) -> core::ffi::c_ulong = core::mem::transmute(kallsyms_addr);
    kallsyms_fn(name)
}

// =============================================================================
// 需要运行时查找的内核 API 符号（kfunc 或内核标准导出）
// 函数指针字段使用 Option 类型，供 sym! 宏返回后解包
// =============================================================================

/// 运行时动态查找并缓存的内核函数指针
pub struct KernelSymbols {
    // 内核时间
    pub msleep: Option<unsafe extern "C" fn(msecs: u32)>,
    pub ktime_get_real_seconds: Option<unsafe extern "C" fn() -> i64>,
    pub ktime_get_mono_fast_ns: Option<unsafe extern "C" fn() -> u64>,

    // 内存分配
    pub __kmalloc: Option<unsafe extern "C" fn(size: usize, flags: u32) -> *mut c_void>,
    pub kfree: Option<unsafe extern "C" fn(obj: *const c_void)>,

    // 进程管理
    pub mmput: Option<unsafe extern "C" fn(mm: *mut c_void) -> c_int>,
    pub get_task_mm: Option<unsafe extern "C" fn(tsk: *mut c_void) -> *mut c_void>,
    pub find_task_by_vpid: Option<unsafe extern "C" fn(pid: i32) -> *mut c_void>,
    pub __task_pid_nr_ns: Option<unsafe extern "C" fn(tsk: *mut c_void, pid_type: c_int, ns: *mut c_void) -> i32>,

    // 工作队列
    pub queue_work_on: Option<unsafe extern "C" fn(cpu: c_int, wq: *mut c_void, work: *mut c_void) -> c_int>,

    // 物理内存
    pub pfn_valid: Option<unsafe extern "C" fn(pfn: u64) -> c_int>,
    pub valid_phys_addr_range: Option<unsafe extern "C" fn(addr: u64, size: u64) -> c_int>,

    // Spinlock
    pub _raw_spin_lock_irqsave: Option<unsafe extern "C" fn(lock: *mut c_void) -> usize>,
    pub _raw_spin_unlock_irqrestore: Option<unsafe extern "C" fn(lock: *mut c_void, flags: usize)>,
    pub _raw_spin_lock_init: Option<unsafe extern "C" fn(lock: *mut c_void)>,

    // 内存拷贝
    pub __arch_copy_to_user: Option<unsafe extern "C" fn(to: *mut c_void, from: *const c_void, n: u64) -> u64>,
    pub __arch_copy_from_user: Option<unsafe extern "C" fn(to: *mut c_void, from: *const c_void, n: u64) -> u64>,
    pub copy_from_user_nofault: Option<unsafe extern "C" fn(dst: *mut c_void, src: *const c_void, size: usize) -> c_long>,
    pub copy_to_user_nofault: Option<unsafe extern "C" fn(to: *mut c_void, from: *const c_void, size: usize) -> c_long>,

    // 字符串/格式化
    pub sscanf: Option<unsafe extern "C" fn(buf: *const c_char, fmt: *const c_char, ...) -> c_int>,
    pub sprint_symbol: Option<unsafe extern "C" fn(buf: *mut c_char, addr: u64) -> c_int>,
    pub dump_stack: Option<unsafe extern "C" fn()>,

    // 进程内存访问
    pub access_process_vm: Option<unsafe extern "C" fn(
        tsk: *mut c_void,
        addr: u64,
        buf: *mut c_void,
        len: c_int,
        gup_flags: u32,
    ) -> c_int>,

    // HwBP
    pub register_user_hw_breakpoint: Option<unsafe extern "C" fn(
        attr: *mut PerfEventAttr,
        triggered: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void),
        context: *mut c_void,
        tsk: *mut c_void,
    ) -> *mut c_void>,
    pub unregister_hw_breakpoint: Option<unsafe extern "C" fn(bp: *mut c_void)>,
    pub modify_user_hw_breakpoint: Option<unsafe extern "C" fn(bp: *mut c_void, attr: *mut PerfEventAttr) -> c_int>,
    pub perf_event_disable_inatomic: Option<unsafe extern "C" fn(bp: *mut c_void)>,
    pub perf_event_enable: Option<unsafe extern "C" fn(bp: *mut c_void)>,

    // on_each_cpu
    pub on_each_cpu: Option<unsafe extern "C" fn(
        func: unsafe extern "C" fn(*mut c_void),
        info: *mut c_void,
        wait: c_int,
    )>,

    // RCU 同步
    pub synchronize_rcu: Option<unsafe extern "C" fn()>,

    // 工作队列和页信息 - 直接存储类型（不使用 Option），通过 null/0 判断
    pub system_wq: *mut c_void,
    pub page_size: i64,
    pub page_shift: i64,
    pub linear_voffset: u64,
    pub memstart_addr_val: u64,
    pub page_offset_val: u64,
}

/// 全局缓存的内核符号实例
pub static mut SYMS: KernelSymbols = KernelSymbols {
    msleep: None,
    ktime_get_real_seconds: None,
    ktime_get_mono_fast_ns: None,
    __kmalloc: None,
    kfree: None,
    mmput: None,
    get_task_mm: None,
    find_task_by_vpid: None,
    __task_pid_nr_ns: None,
    queue_work_on: None,
    pfn_valid: None,
    valid_phys_addr_range: None,
    _raw_spin_lock_irqsave: None,
    _raw_spin_unlock_irqrestore: None,
    _raw_spin_lock_init: None,
    __arch_copy_to_user: None,
    __arch_copy_from_user: None,
    copy_from_user_nofault: None,
    copy_to_user_nofault: None,
    sscanf: None,
    sprint_symbol: None,
    dump_stack: None,
    access_process_vm: None,
    register_user_hw_breakpoint: None,
    unregister_hw_breakpoint: None,
    modify_user_hw_breakpoint: None,
    perf_event_disable_inatomic: None,
    perf_event_enable: None,
    on_each_cpu: None,
    synchronize_rcu: None,
    system_wq: core::ptr::null_mut(),
    page_size: 0,
    page_shift: 0,
    linear_voffset: 0,
    memstart_addr_val: 0,
    page_offset_val: 0,
};

/// 通过内核导出的 kallsyms_lookup_name，在运行时动态解析符号地址
pub unsafe fn lookup_sym<T>(name: &str) -> Option<T> {
    let mut name_buf = [0u8; 128];
    if name.len() >= name_buf.len() {
        return None;
    }
    core::ptr::copy_nonoverlapping(name.as_ptr(), name_buf.as_mut_ptr(), name.len());
    let addr = kallsyms_lookup_name(name_buf.as_ptr() as *const c_char);
    if addr == 0 {
        None
    } else {
        Some(core::mem::transmute_copy(&addr))
    }
}

/// 初始化需要运行时查找的内核符号
/// KP 核心导出的符号已通过 extern 声明直接链接，无需此步
pub unsafe fn init_symbols() -> Result<(), i32> {
    let syms_ptr = core::ptr::addr_of_mut!(SYMS);

    // 必要符号 - 必须存在
    // __kmalloc 在新内核中可能被重命名为 kmalloc
    (*syms_ptr).__kmalloc = lookup_sym("__kmalloc")
        .or_else(|| lookup_sym("kmalloc")).ok_or(-2)?;
    (*syms_ptr).kfree = lookup_sym("kfree").ok_or(-2)?;
    (*syms_ptr).mmput = lookup_sym("mmput").ok_or(-2)?;
    (*syms_ptr).get_task_mm = lookup_sym("get_task_mm").ok_or(-2)?;
    // find_task_by_vpid 在新内核中可能被重命名为 find_vpid
    (*syms_ptr).find_task_by_vpid = lookup_sym("find_task_by_vpid")
        .or_else(|| lookup_sym("find_vpid")).ok_or(-2)?;
    (*syms_ptr).__task_pid_nr_ns = lookup_sym("__task_pid_nr_ns").ok_or(-2)?;
    
    // 尝试查找 spinlock 符号（新内核可能去掉了前缀下划线）
    (*syms_ptr)._raw_spin_lock_irqsave = lookup_sym("_raw_spin_lock_irqsave")
        .or_else(|| lookup_sym("raw_spin_lock_irqsave")).ok_or(-2)?;
    (*syms_ptr)._raw_spin_unlock_irqrestore = lookup_sym("_raw_spin_unlock_irqrestore")
        .or_else(|| lookup_sym("raw_spin_unlock_irqrestore")).ok_or(-2)?;
    (*syms_ptr)._raw_spin_lock_init = lookup_sym("_raw_spin_lock_init")
        .or_else(|| lookup_sym("raw_spin_lock_init"));
        
    // __arch_copy_to_user 在新内核中可能被重命名为 copy_to_user
    (*syms_ptr).__arch_copy_to_user = lookup_sym("__arch_copy_to_user")
        .or_else(|| lookup_sym("copy_to_user")).ok_or(-2)?;
    // __arch_copy_from_user 在新内核中可能被重命名为 copy_from_user
    (*syms_ptr).__arch_copy_from_user = lookup_sym("__arch_copy_from_user")
        .or_else(|| lookup_sym("copy_from_user")).ok_or(-2)?;
    (*syms_ptr).access_process_vm = lookup_sym("access_process_vm").ok_or(-2)?;

    // 可选符号 - 不存在时设为 None
    (*syms_ptr).msleep = lookup_sym("msleep");
    (*syms_ptr).ktime_get_real_seconds = lookup_sym("ktime_get_real_seconds");
    (*syms_ptr).ktime_get_mono_fast_ns = lookup_sym("ktime_get_mono_fast_ns");
    (*syms_ptr).queue_work_on = lookup_sym("queue_work_on");
    (*syms_ptr).pfn_valid = lookup_sym("pfn_valid");
    (*syms_ptr).valid_phys_addr_range = lookup_sym("valid_phys_addr_range");
    (*syms_ptr).copy_from_user_nofault = lookup_sym("copy_from_user_nofault");
    (*syms_ptr).copy_to_user_nofault = lookup_sym("copy_to_user_nofault");
    (*syms_ptr).sscanf = lookup_sym("sscanf");
    (*syms_ptr).sprint_symbol = lookup_sym("sprint_symbol");
    (*syms_ptr).dump_stack = lookup_sym("dump_stack");
    (*syms_ptr).register_user_hw_breakpoint = lookup_sym("register_user_hw_breakpoint");
    (*syms_ptr).unregister_hw_breakpoint = lookup_sym("unregister_hw_breakpoint");
    (*syms_ptr).modify_user_hw_breakpoint = lookup_sym("modify_user_hw_breakpoint");
    (*syms_ptr).perf_event_disable_inatomic = lookup_sym("perf_event_disable_inatomic");
    (*syms_ptr).perf_event_enable = lookup_sym("perf_event_enable");
    (*syms_ptr).on_each_cpu = lookup_sym("on_each_cpu");
    (*syms_ptr).synchronize_rcu = lookup_sym("synchronize_rcu");
    if (*syms_ptr).synchronize_rcu.is_none() {
        crate::pr_warn!("未找到 synchronize_rcu，降级为非阻塞释放可能有 UAF 风险！");
    }

    let system_wq_sym: Option<*mut *mut c_void> = lookup_sym("system_wq");
    if let Some(sym) = system_wq_sym {
        (*syms_ptr).system_wq = *sym;
    }

    let page_size_ptr: Option<*const i64> = lookup_sym("page_size");
    if let Some(ptr) = page_size_ptr {
        (*syms_ptr).page_size = *ptr;
    }
    let page_shift_ptr: Option<*const i64> = lookup_sym("page_shift");
    if let Some(ptr) = page_shift_ptr {
        (*syms_ptr).page_shift = *ptr;
    }

    let memstart_addr_ptr: Option<*const u64> = lookup_sym("memstart_addr");
    if let Some(ptr) = memstart_addr_ptr {
        (*syms_ptr).memstart_addr_val = *ptr;
        let tcr_el1: u64;
        core::arch::asm!("mrs {}, tcr_el1", out(reg) tcr_el1);
        let va_bits_local = 64 - ((tcr_el1 >> 16) & 0x1F);

        if kver < ((5 << 16) + (4 << 8) + 0) {
            (*syms_ptr).page_offset_val = !0u64 << (va_bits_local - 1);
        } else {
            (*syms_ptr).page_offset_val = !0u64 << va_bits_local;
        }
        (*syms_ptr).linear_voffset = (*syms_ptr).page_offset_val.wrapping_sub((*syms_ptr).memstart_addr_val);
    } else {
        return Err(-2);
    }

    Ok(())
}