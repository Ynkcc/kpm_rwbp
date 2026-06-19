// 同步原语封装

/// 自旋锁的裸结构，对齐到 8 字节并预留 64 字节的非透明空间以防内核数据结构变化
#[repr(C, align(8))]
pub struct RawSpinlock {
    opaque: [u8; 64],
}

impl RawSpinlock {
    /// 创建一个未初始化的自旋锁实例
    pub const fn new() -> Self {
        Self { opaque: [0; 64] }
    }

    /// 动态初始化自旋锁（如果内核导出了初始化函数）
    pub fn init(&self) {
        unsafe {
            if let Some(init_fn) = crate::sym!(_raw_spin_lock_init) {
                init_fn(self as *const RawSpinlock as *mut _);
            }
        }
    }

    /// 获取自旋锁，会关中断并保存当前中断标志
    pub fn lock(&self) -> SpinlockGuard<'_> {
        let mut flags = 0usize;
        unsafe {
            if let Some(lock_fn) = crate::sym!(_raw_spin_lock_irqsave) {
                flags = lock_fn(self as *const RawSpinlock as *mut _);
            }
        }
        SpinlockGuard { lock: self, flags }
    }
}

/// 自旋锁保护卫兵，在其 Drop 时自动恢复中断并释放锁
pub struct SpinlockGuard<'a> {
    lock: &'a RawSpinlock,
    flags: usize,
}

impl<'a> Drop for SpinlockGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            if let Some(unlock_fn) = crate::sym!(_raw_spin_unlock_irqrestore) {
                unlock_fn(self.lock as *const RawSpinlock as *mut _, self.flags);
            }
        }
    }
}

/// 模仿 Mutex 语义的内核互斥数据包装结构（基于 Spinlock 实现）
pub struct KernelMutex<T> {
    lock: RawSpinlock,
    data: core::cell::UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for KernelMutex<T> {}
unsafe impl<T: Send> Send for KernelMutex<T> {}

impl<T> KernelMutex<T> {
    /// 包装指定的数据
    pub const fn new(data: T) -> Self {
        Self {
            lock: RawSpinlock::new(),
            data: core::cell::UnsafeCell::new(data),
        }
    }

    /// 加锁获取内部数据的可变借用卫兵
    pub fn lock(&self) -> KernelMutexGuard<'_, T> {
        let guard = self.lock.lock();
        KernelMutexGuard {
            _raw_guard: guard,
            data: unsafe { &mut *self.data.get() },
        }
    }
}

/// 互斥数据借用卫兵
pub struct KernelMutexGuard<'a, T> {
    _raw_guard: SpinlockGuard<'a>,
    data: &'a mut T,
}

impl<'a, T> core::ops::Deref for KernelMutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T> core::ops::DerefMut for KernelMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}
