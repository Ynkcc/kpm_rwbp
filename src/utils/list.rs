// RCU 双向链表辅助结构，模仿 Linux 内核 list_head

use core::sync::atomic::{AtomicPtr, Ordering};

#[repr(C)]
pub struct ListHead {
    pub next: *mut ListHead,
    pub prev: *mut ListHead,
}

impl ListHead {
    /// 初始化哨兵节点，使其前后指针均指向自身
    pub fn init(&mut self) {
        self.next = self as *mut _;
        self.prev = self as *mut _;
    }

    /// 在当前节点之后插入一个新节点
    pub unsafe fn add(&mut self, new: *mut ListHead) {
        let next = self.next;
        (*new).next = next;
        (*new).prev = self as *mut _;
        (*next).prev = new;
        self.next = new;
    }

    /// RCU 安全的插入节点 (`list_add_rcu`)
    /// 保证 new 节点的内部初始化完成后，再将其暴露给读者
    pub unsafe fn add_rcu(&mut self, new: *mut ListHead) {
        let next = self.next;
        (*new).next = next;
        (*new).prev = self as *mut _;
        
        // 使用 Release 语义将 new 写入 self.next，确保此前对 new 节点数据的修改全部可见
        let self_next_atomic = &mut self.next as *mut *mut ListHead as *const AtomicPtr<ListHead>;
        (*self_next_atomic).store(new, Ordering::Release);
        
        (*next).prev = new;
    }

    /// 从双向链表中删除当前节点
    pub unsafe fn del(&mut self) {
        let next = self.next;
        let prev = self.prev;
        (*next).prev = prev;
        (*prev).next = next;
        self.next = core::ptr::null_mut();
        self.prev = core::ptr::null_mut();
    }

    /// RCU 安全的删除节点 (`list_del_rcu`)
    pub unsafe fn del_rcu(&mut self) {
        let next = self.next;
        let prev = self.prev;
        
        // RCU 删除时，前驱节点的 next 指向当前节点的 next。使用 Release 屏障。
        let prev_next_atomic = &mut (*prev).next as *mut *mut ListHead as *const AtomicPtr<ListHead>;
        (*prev_next_atomic).store(next, Ordering::Release);
        
        (*next).prev = prev;
        
        // 【注意】RCU 删除时绝对不能像常规 del 那样清理自己的 next/prev 指针（毒化），
        // 因为并行的无锁 Reader 可能正在通过当前节点的 next 继续往下遍历。
    }

    /// RCU 安全的获取下一个节点 (`list_next_or_null_rcu`)
    pub unsafe fn next_rcu(&self) -> *mut ListHead {
        let next_atomic = &self.next as *const *mut ListHead as *const AtomicPtr<ListHead>;
        // 使用 Acquire 语义读取下一个节点，确保获取到最新版本且不发生指令重排
        (*next_atomic).load(Ordering::Acquire)
    }
}

