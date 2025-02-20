use crate::lib_process;
use crate::maps;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::*;
use core::mem;
use tetragon_common::msg_types::MsgOps;
use tetragon_common::process::{init_bytes, EventBytes, MsgExit};
use tetragon_common::vmlinux::{__u32, task_struct};

#[kprobe(function = "acct_process")]
pub fn exit_acct_process(ctx: ProbeContext) -> u32 {
    match unsafe { try_exit_acct_process(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_exit_acct_process(ctx: ProbeContext) -> Result<u32, i64> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = event_exit_send(&ctx, tgid);
    debug!(&ctx, "exit_acct_process: {}", tgid);
    Ok(0)
}

#[inline]
pub unsafe fn event_exit_send(ctx: &ProbeContext, tgid: __u32) -> Result<u32, i64> {
    let enter = maps::EXECVE_MAP.get(&tgid).ok_or(1)?;
    if enter.key.ktime != 0 {
        let task = bpf_get_current_task() as *const task_struct;
        let size = mem::size_of::<MsgExit>();

        let event_bytes = {
            let ptr = maps::EXIT_HEAP_MAP.get_ptr_mut(0).ok_or(1)?;
            &mut *ptr
        };
        init_bytes(event_bytes);
        let exit: &mut MsgExit = unsafe { &mut *(event_bytes as *mut EventBytes as *mut MsgExit) };

        exit.common.op = MsgOps::MsgOpExit as u8;
        exit.common.flags = 0;
        exit.common.pad[0] = 0;
        exit.common.pad[1] = 0;
        exit.common.size = size as u32;

        exit.current.pid = tgid;
        exit.current.pad[0] = 0;
        exit.current.pad[1] = 0;
        exit.current.pad[2] = 0;
        exit.current.pad[3] = 0;
        exit.current.ktime = enter.key.ktime;

        exit.info.tid = tgid;
        let exit_code = bpf_probe_read_kernel(&(*task).exit_code).unwrap_or(1);
        exit.info.code = exit_code.unsigned_abs();

        maps::TCPMON_MAP.output(ctx, event_bytes, 0);
    }

    lib_process::execve_map_delete(tgid);
    debug!(ctx, "event_exit_send: {}", tgid);
    Ok(0)
}
