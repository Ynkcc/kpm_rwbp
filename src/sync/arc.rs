use core::sync::atomic::{AtomicI32, Ordering};
use core::ptr::NonNull;
use core::ffi::c_void;

/// 内置引用计数的容器结构体，对齐和排布为 repr(C) 以便通过成员偏移安全地反推外部指针。
#[repr(C)]
pub struct KernelArcInner<T: ?Sized> {
    pub refcnt: AtomicI32,
    pub data: T,
}

/// 针对内核动态内存分配器的引用计数智能指针。
pub struct KernelArc<T: ?Sized> {
    ptr: NonNull<KernelArcInner<T>>,
}

unsafe impl<T: ?Sized + Send + Sync> Send for KernelArc<T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for KernelArc<T> {}

impl<T> KernelArc<T> {
    /// 在内核中动态分配一个 KernelArcInner 并对其进行初始化。
    /// 引用计数初始化为 1。
    pub fn new(data: T) -> Result<Self, i32> {
        let malloc_fn = crate::sym_must!(kmalloc);
        let size = core::mem::size_of::<KernelArcInner<T>>();
        // 0x20u32 代表 GFP_ATOMIC
        let ptr = unsafe { malloc_fn(size, 0x20u32) } as *mut KernelArcInner<T>;
        if ptr.is_null() {
            return Err(crate::utils::Error::ENOMEM as i32);
        }
        unsafe {
            core::ptr::write(ptr, KernelArcInner {
                refcnt: AtomicI32::new(1),
                data,
            });
            Ok(Self {
                ptr: NonNull::new_unchecked(ptr),
            })
        }
    }

    /// 在内核中动态分配一个全零初始化的 KernelArcInner，防止内核栈溢出。
    /// 引用计数初始化为 1。
    pub fn new_zeroed() -> Result<Self, i32> {
        let malloc_fn = crate::sym_must!(kmalloc);
        let size = core::mem::size_of::<KernelArcInner<T>>();
        // 0x20u32 代表 GFP_ATOMIC
        let ptr = unsafe { malloc_fn(size, 0x20u32) } as *mut KernelArcInner<T>;
        if ptr.is_null() {
            return Err(crate::utils::Error::ENOMEM as i32);
        }
        unsafe {
            core::ptr::write_bytes(ptr as *mut u8, 0, size);
            core::ptr::write(core::ptr::addr_of_mut!((*ptr).refcnt), AtomicI32::new(1));
            Ok(Self {
                ptr: NonNull::new_unchecked(ptr),
            })
        }
    }

    /// 从内部数据的裸指针重新构造一个 KernelArc，此操作会【递增】引用计数。
    /// 
    /// # Safety
    /// 传入的指针必须是由 KernelArc 管理的内存中 data 字段的有效指针。
    pub unsafe fn from_raw(ptr: *const T) -> Self {
        let inner_ptr = Self::inner_ptr_from_data_ptr(ptr);
        let non_null = NonNull::new_unchecked(inner_ptr);
        non_null.as_ref().refcnt.fetch_add(1, Ordering::Relaxed);
        Self { ptr: non_null }
    }

    /// 从内部数据的裸指针重新构造一个 KernelArc，但是【不】递增引用计数，用于所有权的流转。
    /// 
    /// # Safety
    /// 传入的指针必须是由 KernelArc 管理的内存中 data 字段的有效指针，且调用方需要将
    /// 该上下文原本对该引用的所有权交付给返回的 KernelArc 管理。
    pub unsafe fn from_raw_transferred(ptr: *const T) -> Self {
        let inner_ptr = Self::inner_ptr_from_data_ptr(ptr);
        Self { ptr: NonNull::new_unchecked(inner_ptr) }
    }

    /// 消费当前的 KernelArc，返回内部数据的裸指针，【不】递减引用计数（所有权转移给裸指针上下文）。
    pub fn into_raw(self) -> *mut T {
        let ptr = unsafe { core::ptr::addr_of_mut!((*self.ptr.as_ptr()).data) };
        core::mem::forget(self);
        ptr
    }

    /// 获取内部数据的裸指针而不转移所有权或改变引用计数。
    pub fn as_raw(&self) -> *mut T {
        unsafe { core::ptr::addr_of_mut!((*self.ptr.as_ptr()).data) }
    }

    /// 获取当前的强引用计数。
    pub fn ref_count(&self) -> i32 {
        unsafe { self.ptr.as_ref().refcnt.load(Ordering::Acquire) }
    }

    #[inline(always)]
    unsafe fn inner_ptr_from_data_ptr(ptr: *const T) -> *mut KernelArcInner<T> {
        let offset = core::mem::offset_of!(KernelArcInner<T>, data);
        (ptr as usize - offset) as *mut KernelArcInner<T>
    }
}

impl<T: ?Sized> core::ops::Deref for KernelArc<T> {
    type Target = T;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        unsafe { &self.ptr.as_ref().data }
    }
}

impl<T: ?Sized> Clone for KernelArc<T> {
    fn clone(&self) -> Self {
        unsafe {
            self.ptr.as_ref().refcnt.fetch_add(1, Ordering::Relaxed);
        }
        Self { ptr: self.ptr }
    }
}

impl<T: ?Sized> Drop for KernelArc<T> {
    fn drop(&mut self) {
        unsafe {
            if self.ptr.as_ref().refcnt.fetch_sub(1, Ordering::Release) == 1 {
                // 析构内部数据
                core::ptr::drop_in_place(core::ptr::addr_of_mut!((*self.ptr.as_ptr()).data));
                // 物理释放整个 KernelArcInner 占用的内存
                let free_fn = crate::sym_must!(kfree);
                free_fn(self.ptr.as_ptr() as *const c_void);
            }
        }
    }
}
