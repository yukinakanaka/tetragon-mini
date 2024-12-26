use core::mem;

use crate::vmlinux::*;

pub const EVENT_SIZE: usize = 904;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct MsgCommon {
    pub op: __u8,
    pub flags: __u8, // internal flags not exported
    pub pad: [__u8; 2],
    pub size: __u32,
    pub ktime: __u64,
}

impl TryInto<[u8; EVENT_SIZE]> for MsgCommon {
    type Error = &'static str;

    fn try_into(self) -> Result<[u8; EVENT_SIZE], Self::Error> {
        let mut result = [0u8; EVENT_SIZE];
        let size = mem::size_of::<MsgCommon>();

        if size > EVENT_SIZE {
            return Err("MsgCommon is too large for [u8; EVENT_SIZE]");
        }

        unsafe {
            let src_ptr = &self as *const MsgCommon as *const u8;
            let dst_ptr = result.as_mut_ptr();
            core::ptr::copy_nonoverlapping(src_ptr, dst_ptr, size);
        }

        Ok(result)
    }
}

impl TryFrom<[u8; EVENT_SIZE]> for MsgCommon {
    type Error = &'static str;

    fn try_from(bytes: [u8; EVENT_SIZE]) -> Result<Self, Self::Error> {
        if bytes.len() < mem::size_of::<MsgCommon>() {
            return Err("Byte array is too small for MsgCommon");
        }

        unsafe {
            let ptr = bytes.as_ptr() as *const MsgCommon;
            Ok(ptr.read_unaligned())
        }
    }
}
