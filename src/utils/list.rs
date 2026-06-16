// RCU 双向链表辅助结构，模仿 Linux 内核 list_head

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

    /// 从双向链表中删除当前节点
    pub unsafe fn del(&mut self) {
        let next = self.next;
        let prev = self.prev;
        (*next).prev = prev;
        (*prev).next = next;
        self.next = core::ptr::null_mut();
        self.prev = core::ptr::null_mut();
    }
}
