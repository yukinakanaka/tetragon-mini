use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, PerCpuArray, PerfEventArray, ProgramArray},
};

use crate::lib_data_msg::MsgData;
use tetragon_common::process::{EventBytes, ExecveInfo, ExecveMapValue, ProcessEvent};
use tetragon_common::vmlinux::{__u32, __u64};

#[repr(C)]
pub struct ProcessEventBuf {
    pub p: ProcessEvent,
}

#[map(name = "DATA_HEAP_CUSTOM")]
pub static mut DATA_HEAP_CUSTOM: PerCpuArray<ProcessEventBuf> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "PROCESS_EVENTS")]
pub static PROCESS_EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

#[map(name = "EXECVE_MAP")]
pub static EXECVE_MAP: HashMap<__u32, ExecveMapValue> = HashMap::with_max_entries(32768, 0);

#[repr(C)]
pub struct ExecveMapValueBuf {
    pub value: ExecveMapValue,
}

#[map(name = "EXECVE_VAL")]
pub static mut EXECVE_VAL: PerCpuArray<ExecveMapValueBuf> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "TCPMON_MAP")]
pub static TCPMON_MAP: PerfEventArray<EventBytes> = PerfEventArray::new(0);

// BPF_MAP_TYPE_PROG_ARRAY's primary use is as a jump table for the tail_call feature
#[map(name = "EXECVE_CALLS")]
pub static EXECVE_CALLS: ProgramArray = ProgramArray::with_max_entries(2, 0);

#[map(name = "DATA_HEAP")]
pub static mut DATA_HEAP: PerCpuArray<MsgData> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "EXECVE_MSG_HEAP_MAP")]
pub static mut EXECVE_MSG_HEAP_MAP: PerCpuArray<EventBytes> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "CLONE_HEAP_MAP")]
pub static mut CLONE_HEAP_MAP: PerCpuArray<EventBytes> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "EXIT_HEAP_MAP")]
pub static mut EXIT_HEAP_MAP: PerCpuArray<EventBytes> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "TG_EXECVE_JOINED_INFO_MAP")]
pub static mut TG_EXECVE_JOINED_INFO_MAP: LruHashMap<__u64, ExecveInfo> =
    LruHashMap::with_max_entries(8192, 0);
