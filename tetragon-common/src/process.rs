use core::convert::TryFrom;
use core::mem;

use crate::bpf_cred::{MsgCapabilities, MsgCred};
use crate::common::{MsgCommon, EVENT_SIZE};
use crate::msg_types::MsgOps;
use crate::vmlinux::*;

// In Linux, it's 4096, but simplified to 256 for easier debugging.
pub const BINARY_PATH_MAX_LEN: usize = 256;
// Usually 2MiB in most kernels, but simplified to 512 for easier debugging.
pub const ARGS_MAX_LEN: usize = 512;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessEvent {
    pub msg_ops: MsgOps,
    pub uid: u32,
    pub pid: i32,
    pub filename: [u8; BINARY_PATH_MAX_LEN],
    pub filename_len: usize,
}

impl Default for ProcessEvent {
    fn default() -> Self {
        Self {
            msg_ops: MsgOps::default(),
            uid: u32::default(),
            pid: i32::default(),
            filename: [u8::default(); BINARY_PATH_MAX_LEN],
            filename_len: usize::default(),
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ExecveMapValue {
    pub key: MsgExecveKey,
    pub pkey: MsgExecveKey,
    pub flags: __u32,
    pub nspid: __u32,
    pub ns: MsgNs,
    pub caps: MsgCapabilities,
    pub bin: Binary,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ExecveMapValue {}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgExecveKey {
    pub pid: __u32, // Process TGID
    pub pad: [__u8; 4],
    pub ktime: __u64,
}

impl MsgExecveKey {
    pub fn copy(to: &mut Self, from: &Self) {
        to.pid = from.pid;
        to.pad.copy_from_slice(&from.pad);
        to.ktime = from.ktime;
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgNs {
    pub uts_inum: u32,
    pub ipc_inum: u32,
    pub mnt_inum: u32,
    pub pid_inum: u32,
    pub pid_for_children_inum: u32,
    pub net_inum: u32,
    pub time_inum: u32,
    pub time_for_children_inum: u32,
    pub cgroup_inum: u32,
    pub user_inum: u32,
}

impl MsgNs {
    pub fn copy(to: &mut Self, from: &Self) {
        to.uts_inum = from.uts_inum;
        to.ipc_inum = from.ipc_inum;
        to.mnt_inum = from.mnt_inum;
        to.pid_inum = from.pid_inum;
        to.pid_for_children_inum = from.pid_for_children_inum;
        to.net_inum = from.net_inum;
        to.time_inum = from.time_inum;
        to.time_for_children_inum = from.time_for_children_inum;
        to.cgroup_inum = from.cgroup_inum;
        to.user_inum = from.user_inum;
    }
}

const DOCKER_ID_LENGTH: usize = 128;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MsgK8s {
    pub net_ns: __u32,
    pub cid: __u32,
    pub cgrpid: __u64,
    pub docker_id: [u8; DOCKER_ID_LENGTH],
}

impl Default for MsgK8s {
    fn default() -> Self {
        Self {
            net_ns: __u32::default(),
            cid: __u32::default(),
            cgrpid: __u64::default(),
            docker_id: [0; DOCKER_ID_LENGTH],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct HeapExe {
    pub filename: [u8; BINARY_PATH_MAX_LEN],
    pub args: [u8; ARGS_MAX_LEN],
    pub off: u8,
    pub len: __u32,
    pub error: __u32,
}

impl Default for HeapExe {
    fn default() -> Self {
        Self {
            filename: [0; BINARY_PATH_MAX_LEN],
            args: [0; ARGS_MAX_LEN],
            off: u8::default(),
            len: __u32::default(),
            error: __u32::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Binary {
    pub path_length: __s64,
    pub path: [u8; BINARY_PATH_MAX_LEN],
}

impl Default for Binary {
    fn default() -> Self {
        Self {
            path_length: __s64::default(),
            path: [0; BINARY_PATH_MAX_LEN],
        }
    }
}

impl Binary {
    pub fn copy(to: &mut Self, from: &Self) {
        to.path_length = from.path_length;
        to.path.copy_from_slice(&from.path);
    }
}

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgCloneEvent {
    pub common: MsgCommon,
    pub parent: MsgExecveKey,
    pub tgid: __u32,
    pub tid: __u32,
    pub nspid: __u32,
    pub flags: __u32,
    pub ktime: __u64,
}

impl TryFrom<[u8; EVENT_SIZE]> for MsgCloneEvent {
    type Error = &'static str;

    fn try_from(bytes: [u8; EVENT_SIZE]) -> Result<Self, Self::Error> {
        if bytes.len() < mem::size_of::<MsgCloneEvent>() {
            return Err("Byte array is too small for MsgCloneEvent");
        }

        unsafe {
            let ptr = bytes.as_ptr() as *const MsgCloneEvent;
            Ok(ptr.read_unaligned())
        }
    }
}

impl TryInto<[u8; EVENT_SIZE]> for MsgCloneEvent {
    type Error = &'static str;

    fn try_into(self) -> Result<[u8; EVENT_SIZE], Self::Error> {
        let mut result = [0u8; EVENT_SIZE];
        let size = mem::size_of::<MsgCloneEvent>();

        if size > EVENT_SIZE {
            return Err("MsgCloneEvent is too large for [u8; EVENT_SIZE]");
        }

        unsafe {
            let src_ptr = &self as *const MsgCloneEvent as *const u8;
            let dst_ptr = result.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size);
        }

        Ok(result)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgExit {
    pub common: MsgCommon,
    pub current: MsgExecveKey,
    pub info: ExitInfo,
}

impl TryFrom<[u8; EVENT_SIZE]> for MsgExit {
    type Error = &'static str;

    fn try_from(bytes: [u8; EVENT_SIZE]) -> Result<Self, Self::Error> {
        if bytes.len() < mem::size_of::<MsgExit>() {
            return Err("Byte array is too small for MsgExit");
        }

        unsafe {
            let ptr = bytes.as_ptr() as *const MsgExit;
            Ok(ptr.read_unaligned())
        }
    }
}

impl TryInto<[u8; EVENT_SIZE]> for MsgExit {
    type Error = &'static str;

    fn try_into(self) -> Result<[u8; EVENT_SIZE], Self::Error> {
        let mut result = [0u8; EVENT_SIZE];
        let size = mem::size_of::<MsgExit>();

        if size > EVENT_SIZE {
            return Err("MsgExit is too large for [u8; EVENT_SIZE]");
        }

        unsafe {
            let src_ptr = &self as *const MsgExit as *const u8;
            let dst_ptr = result.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size);
        }

        Ok(result)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ExitInfo {
    pub code: __u32,
    pub tid: __u32, // Thread ID
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MsgExecveEvent {
    pub common: MsgCommon,
    pub kube: MsgK8s,
    pub parent: MsgExecveKey,
    pub parent_flags: __u64,
    pub creds: MsgCred,
    pub ns: MsgNs,
    pub cleanup_key: MsgExecveKey,
    pub process: MsgProcess,
    pub exe: HeapExe,
}

impl TryFrom<[u8; EVENT_SIZE]> for MsgExecveEvent {
    type Error = &'static str;

    fn try_from(bytes: [u8; EVENT_SIZE]) -> Result<Self, Self::Error> {
        if bytes.len() < mem::size_of::<MsgExecveEvent>() {
            return Err("Byte array is too small for MsgExecveEvent");
        }

        unsafe {
            let ptr = bytes.as_ptr() as *const MsgExecveEvent;
            Ok(ptr.read_unaligned())
        }
    }
}

impl TryInto<[u8; EVENT_SIZE]> for MsgExecveEvent {
    type Error = &'static str;

    fn try_into(self) -> Result<[u8; EVENT_SIZE], Self::Error> {
        let mut result = [0u8; EVENT_SIZE];
        let size = mem::size_of::<MsgExecveEvent>();

        if size > EVENT_SIZE {
            return Err("MsgExecveEvent is too large for [u8; EVENT_SIZE]");
        }

        unsafe {
            let src_ptr = &self as *const MsgExecveEvent as *const u8;
            let dst_ptr = result.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size);
        }

        Ok(result)
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EventBytes {
    pub bytes: [u8; EVENT_SIZE],
}

#[inline]
pub fn init_bytes(event: &mut EventBytes) {
    event.bytes = [0; EVENT_SIZE];
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EventBytes {}

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ExecveInfo {
    pub secureexec: __u32,
    pub i_nlink: __u32, /* inode links */
    pub i_ino: __u64,   /* inode number */
}

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgProcess {
    pub size: __u32,
    pub pid: __u32, // Process TGID
    pub tid: __u32, // Process thread
    pub nspid: __u32,
    pub secureexec: __u32,
    pub uid: __u32,
    pub auid: __u32,
    pub flags: __u32,
    pub i_nlink: __u32,
    pub pad: __u32,
    pub i_ino: __u64,
    pub ktime: __u64,
    pub args: u8,
}
