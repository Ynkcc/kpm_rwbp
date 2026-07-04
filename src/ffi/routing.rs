// 集中式的内核函数路由分发层 (Object-Based Routing)
// 用于屏蔽不同 Linux/Android 内核版本下，某些内核回调函数签名的 ABI 差异。

use core::ffi::{c_void, c_int};
use crate::utils::Error;
use crate::ffi::{SYMS, kver};

// ==================== apply_to_page_range 路由分发 ====================

/// 统一的页表操作接口
pub trait PteOp {
    /// 页表遍历到具体的 PTE 时触发
    /// 
    /// # 参数
    /// * `pte` - 指向内核页表项 (pte_t) 的裸指针
    /// * `addr` - 对应的虚拟地址
    unsafe fn call(&mut self, pte: *mut c_void, addr: u64) -> i32;
}

/// 避免 Rust `dyn` 胖指针在转换为 `*mut c_void` 时丢失虚表 (vtable) 信息而设计的包装桥接结构体
#[repr(C)]
struct PteOpRouter<'a> {
    op: &'a mut dyn PteOp,
}

// 内核版本 >= 5.3 的底层 C 回调
// 签名：(pte_t *pte, unsigned long addr, void *data)
unsafe extern "C" fn apply_to_page_range_cb_gte_5_3(
    pte: *mut c_void,
    addr: u64,
    data: *mut c_void,
) -> c_int {
    unsafe {
        let router = &mut *(data as *mut PteOpRouter);
        router.op.call(pte, addr)
    }
}

// 内核版本 < 5.3 的底层 C 回调
// 签名：(pte_t *pte, pgtable_t token, unsigned long addr, void *data)
unsafe extern "C" fn apply_to_page_range_cb_lt_5_3(
    pte: *mut c_void,
    _token: u64,
    addr: u64,
    data: *mut c_void,
) -> c_int {
    unsafe {
        let router = &mut *(data as *mut PteOpRouter);
        router.op.call(pte, addr)
    }
}

/// 统一的 `apply_to_page_range` 调用函数，在内部根据内核版本自动进行路由转发
/// 
/// # 参数
/// * `mm` - 目标进程的 `mm_struct` 指针
/// * `address` - 目标虚拟地址
/// * `size` - 页面区域大小
/// * `op` - 页表操作的具体实现对象 (实现了 `PteOp` trait)
pub unsafe fn apply_to_page_range(
    mm: *mut c_void,
    address: u64,
    size: u64,
    op: &mut dyn PteOp,
) -> Result<(), Error> {
    unsafe {
        let apply_fn = SYMS.apply_to_page_range.ok_or(Error::ENOSYS)?;
        let mut router = PteOpRouter { op };
        let data_ptr = &mut router as *mut PteOpRouter as *mut c_void;

        let ret = if kver >= ((5 << 16) + (3 << 8) + 0) {
            // 内核版本 >= 5.3
            let cb: unsafe extern "C" fn(*mut c_void, u64, *mut c_void) -> c_int = apply_to_page_range_cb_gte_5_3;
            apply_fn(
                mm,
                address,
                size,
                cb as *mut c_void,
                data_ptr,
            )
        } else {
            // 内核版本 < 5.3
            let cb: unsafe extern "C" fn(*mut c_void, u64, u64, *mut c_void) -> c_int = apply_to_page_range_cb_lt_5_3;
            apply_fn(
                mm,
                address,
                size,
                cb as *mut c_void,
                data_ptr,
            )
        };

        if ret != 0 {
            Err(Error::from(-ret))
        } else {
            Ok(())
        }
    }
}
