use tetragon_common::common::MsgCommon;
use tetragon_common::vmlinux::*;

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DataEventId {
    pub pid: __u64,
    pub time: __u64,
}

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DataEventDesc {
    pub error: __s32,
    pub pad: __u32,
    pub leftover: __u32,
    pub size: __u32,
    pub id: DataEventId,
}

const MSG_DATA_ARG_LEN: usize = 32736;

#[repr(C)]
#[repr(packed)]
#[derive(Copy, Clone, Debug)]
pub struct MsgData {
    pub common: MsgCommon,
    pub id: DataEventId,
    pub arg: [u8; MSG_DATA_ARG_LEN],
}

impl Default for MsgData {
    fn default() -> Self {
        Self {
            common: MsgCommon::default(),
            id: DataEventId::default(),
            arg: [0; MSG_DATA_ARG_LEN],
        }
    }
}
