// Msg flags
#[allow(dead_code)]
pub mod msg_flags {
    use crate::vmlinux::__u64;

    pub const EVENT_UNKNOWN: __u64 = 0x00;
    pub const EVENT_EXECVE: __u64 = 0x01;
    pub const EVENT_EXECVEAT: __u64 = 0x02;
    pub const EVENT_PROCFS: __u64 = 0x04;
    pub const EVENT_TRUNC_FILENAME: __u64 = 0x08;
    pub const EVENT_TRUNC_ARGS: __u64 = 0x10;
    pub const EVENT_TASK_WALK: __u64 = 0x20;
    pub const EVENT_MISS: __u64 = 0x40;
    pub const EVENT_NEEDS_AUID: __u64 = 0x80;
    pub const EVENT_ERROR_FILENAME: __u64 = 0x100;
    pub const EVENT_ERROR_ARGS: __u64 = 0x200;
    pub const EVENT_NEEDS_CWD: __u64 = 0x400;
    pub const EVENT_NO_CWD_SUPPORT: __u64 = 0x800;
    pub const EVENT_ROOT_CWD: __u64 = 0x1000;
    pub const EVENT_ERROR_CWD: __u64 = 0x2000;
    pub const EVENT_CLONE: __u64 = 0x4000;
    pub const EVENT_ERROR_SOCK: __u64 = 0x8000;
    pub const EVENT_ERROR_CGROUP_NAME: __u64 = 0x010000;
    pub const EVENT_ERROR_CGROUP_KN: __u64 = 0x020000;
    pub const EVENT_ERROR_CGROUP_SUBSYSCGRP: __u64 = 0x040000;
    pub const EVENT_ERROR_CGROUP_SUBSYS: __u64 = 0x080000;
    pub const EVENT_ERROR_CGROUPS: __u64 = 0x100000;
    pub const EVENT_ERROR_CGROUP_ID: __u64 = 0x200000;
    pub const EVENT_ERROR_PATH_COMPONENTS: __u64 = 0x400000;
    pub const EVENT_DATA_FILENAME: __u64 = 0x800000;
    pub const EVENT_DATA_ARGS: __u64 = 0x1000000;

    pub const EVENT_COMMON_FLAG_CLONE: __u64 = 0x01;
}
