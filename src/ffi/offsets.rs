// 进程及凭证结构偏移定义（用于适配不同 Linux 内核版本的字段位置）

use zerocopy::{FromBytes, IntoBytes, Immutable, KnownLayout};

/// 对应内核中 task_struct 的关键字段偏移
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct TaskStructOffset {
    pub pid_offset: i16,
    pub tgid_offset: i16,
    pub thread_pid_offset: i16,
    pub ptracer_cred_offset: i16,
    pub real_cred_offset: i16,
    pub cred_offset: i16,
    pub comm_offset: i16,
    pub fs_offset: i16,
    pub files_offset: i16,
    pub loginuid_offset: i16,
    pub sessionid_offset: i16,
    pub seccomp_offset: i16,
    pub security_offset: i16,
    pub stack_offset: i16,
    pub tasks_offset: i16,
    pub mm_offset: i16,
    pub active_mm_offset: i16,
}

/// 对应内核中 cred 结构的关键字段偏移
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct CredOffset {
    pub usage_offset: i16,
    pub subscribers_offset: i16,
    pub magic_offset: i16,
    pub uid_offset: i16,
    pub gid_offset: i16,
    pub suid_offset: i16,
    pub sgid_offset: i16,
    pub euid_offset: i16,
    pub egid_offset: i16,
    pub fsuid_offset: i16,
    pub fsgid_offset: i16,
    pub securebits_offset: i16,
    pub cap_inheritable_offset: i16,
    pub cap_permitted_offset: i16,
    pub cap_effective_offset: i16,
    pub cap_bset_offset: i16,
    pub cap_ambient_offset: i16,
    pub user_offset: i16,
    pub user_ns_offset: i16,
    pub ucounts_offset: i16,
    pub group_info_offset: i16,
    pub session_keyring_offset: i16,
    pub process_keyring_offset: i16,
    pub thread_keyring_offset: i16,
    pub request_key_auth_offset: i16,
    pub security_offset: i16,
    pub rcu_offset: i16,
}

/// 对应内核中 mm_struct 的关键字段偏移
#[repr(C)]
#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Clone, Copy)]
pub struct MmStructOffset {
    pub mmap_base_offset: i16,
    pub task_size_offset: i16,
    pub pgd_offset: i16,
    pub map_count_offset: i16,
    pub total_vm_offset: i16,
    pub locked_vm_offset: i16,
    pub pinned_vm_offset: i16,
    pub data_vm_offset: i16,
    pub exec_vm_offset: i16,
    pub stack_vm_offset: i16,
    pub start_code_offset: i16,
    pub end_code_offset: i16,
    pub start_data_offset: i16,
    pub end_data_offset: i16,
    pub start_brk_offset: i16,
    pub brk_offset: i16,
    pub start_stack_offset: i16,
    pub arg_start_offset: i16,
    pub arg_end_offset: i16,
    pub env_start_offset: i16,
    pub env_end_offset: i16,
}
