// 共享内存 IPC 协议与数据结构定义

use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};

// 操作指令常量
pub const OP_READ_MEM: u32 = 8001;
pub const OP_WRITE_MEM: u32 = 8002;
pub const OP_SET_HW_BREAKPOINT: u32 = 8011;
pub const OP_REMOVE_HW_BREAKPOINT: u32 = 8013;
pub const OP_REMOVE_ALL_HW_BREAKPOINT: u32 = 8014;
pub const OP_READ_HW_BP_INFO: u32 = 8015;

// 共享内存标识魔数 'SHMC'
pub const SHM_MAGIC: u32 = 0x53484d43;

/// 读进程内存请求协议
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct CopyMemory {
    pub pid: u32,
    pub _pad0: u32,
    pub addr: u64,
    pub buffer: u64,
    pub size: u64,
}

/// 写进程内存请求协议
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct WriteMemory {
    pub pid: u32,
    pub _pad0: u32,
    pub addr: u64,
    pub buffer: u64,
    pub size: u64,
}

/// 硬件断点设置/移除请求协议
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct HwBreakpointCmd {
    pub pid: u32,
    pub bp_type: u32,
    pub addr: u64,
    pub len: u32,
    pub scheme: u32,
}

/// 寄存器上下文快照（主要对应 ARM64 pt_regs 部分寄存器）
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct HwbpRegsSnapshot {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// 硬件断点命中事件记录（供用户态消费）
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct HwbpHitItem {
    pub hit_time: u64,
    pub task_id: u32,
    pub _pad: u32,
    pub hit_addr: u64,
    pub regs_info: HwbpRegsSnapshot,
}

/// 读取硬件断点命中信息请求协议
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct HwbpInfoCmd {
    pub pid: u32,
    pub _pad: u32,
    pub max_count: u64,
    pub user_buf: u64,
    pub actual_count: u64,
}

/// 共享内存数据交互通道缓冲区定义
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct ShmChannel {
    pub magic: u32,
    pub cmd: u32,
    pub status: i32,
    pub retval: i32,
    pub data_size: u32,
    pub _pad: u32,
    pub payload: [u8; 3500],
}
