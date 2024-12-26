#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub enum MsgOps {
    #[default]
    MsgOpUndef = 0,
    MsgOpExecve = 5,
    MsgOpExit = 7,

    MsgOpGenericKprobe = 13,
    MsgOpGenericTracepoint = 14,
    MsgOpGenericUprobe = 15,

    MsgOpClone = 23,
    MsgOpData = 24,
    MsgOpCgroup = 25,
    MsgOpLoader = 26,
}

impl From<u8> for MsgOps {
    fn from(value: u8) -> Self {
        match value {
            0 => MsgOps::MsgOpUndef,
            5 => MsgOps::MsgOpExecve,
            7 => MsgOps::MsgOpExit,
            13 => MsgOps::MsgOpGenericKprobe,
            14 => MsgOps::MsgOpGenericTracepoint,
            15 => MsgOps::MsgOpGenericUprobe,
            23 => MsgOps::MsgOpClone,
            24 => MsgOps::MsgOpData,
            25 => MsgOps::MsgOpCgroup,
            26 => MsgOps::MsgOpLoader,
            _ => MsgOps::MsgOpUndef,
        }
    }
}
