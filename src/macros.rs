// 日志与内核符号宏
use core::fmt;

/// 辅助宏：从 SYMS 缓存中获取符号（用于仍需运行时查找的内核 API）
#[allow(unused_unsafe)]
#[macro_export]
macro_rules! sym {
    ($field:ident) => {
        unsafe { (*core::ptr::addr_of!($crate::ffi::SYMS)).$field }
    };
}

/// 辅助宏：直接获取绝对存在的必要符号，无需运行时 Option 解包分支
#[allow(unused_unsafe)]
#[macro_export]
macro_rules! sym_must {
    ($field:ident) => {
        unsafe {
            (*$crate::ffi::M_SYMS.0.get()).as_ref().unwrap_unchecked().$field
        }
    };
}

/// 栈上日志缓冲区，安全转换 Rust 格式化与 C 字符串
pub struct KernelBufWriter {
    pub buf: [u8; 512],
    pub len: usize,
}

impl fmt::Write for KernelBufWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let remain = 511 - self.len; // 保留 1 字节给末尾的 '\0'
        let copy_len = core::cmp::min(bytes.len(), remain);
        if copy_len > 0 {
            self.buf[self.len..self.len + copy_len].copy_from_slice(&bytes[..copy_len]);
            self.len += copy_len;
        }
        Ok(())
    }
}

#[inline(always)]
pub fn kprint(level_prefix: &str, args: fmt::Arguments) {
    let mut writer = KernelBufWriter { buf: [0; 512], len: 0 };
    let _ = fmt::Write::write_str(&mut writer, level_prefix);
    let _ = fmt::write(&mut writer, args);
    let _ = fmt::Write::write_str(&mut writer, "\n\0");
    unsafe {
        crate::ffi::printk(writer.buf.as_ptr());
    }
}

/// 打印普通信息日志
#[macro_export]
macro_rules! pr_info {
    ($($arg:tt)*) => {
        $crate::macros::kprint("[kpm_RWBP] ", core::format_args!($($arg)*));
    };
}

/// 打印错误日志
#[macro_export]
macro_rules! pr_err {
    ($($arg:tt)*) => {
        $crate::macros::kprint("[kpm_RWBP] ERROR: ", core::format_args!($($arg)*));
    };
}

/// 打印警告日志
#[macro_export]
macro_rules! pr_warn {
    ($($arg:tt)*) => {
        $crate::macros::kprint("[kpm_RWBP] WARNING: ", core::format_args!($($arg)*));
    };
}