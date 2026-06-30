// 基础内存操作库函数替代实现，避免直接依赖标准 C 库

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 { unsafe {
    for i in 0..n {
        core::ptr::write_volatile(s.add(i), c as u8);
    }
    s
}}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 { unsafe {
    for i in 0..n {
        let val = core::ptr::read_volatile(src.add(i));
        core::ptr::write_volatile(dest.add(i), val);
    }
    dest
}}
