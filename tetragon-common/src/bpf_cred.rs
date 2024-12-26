use crate::vmlinux::*;
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgCapabilities {
    pub permitted: __u64,
    pub effective: __u64,
    pub inheritable: __u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgCred {
    pub uid: __u32,
    pub gid: __u32,
    pub suid: __u32,
    pub sgid: __u32,
    pub euid: __u32,
    pub egid: __u32,
    pub fsuid: __u32,
    pub fsgid: __u32,
    pub securebits: __u32,
    pub pad: __u32,
    pub caps: MsgCapabilities,
    pub user_ns: MsgUserNamespace,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgUserNamespace {
    pub level: __s32,
    pub uid: __u32,
    pub gid: __u32,
    pub ns_inum: __u32,
}
