// IPC 通信子模块

pub mod protocol;
pub mod dispatcher;

pub use protocol::*;
pub use dispatcher::rwbp_dispatch;
