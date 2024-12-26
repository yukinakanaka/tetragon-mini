use crate::lib_process::execve_map_get;
use crate::maps::{CLONE_HEAP_MAP, TCPMON_MAP};
use crate::process_bpf_process_event::get_current_subj_caps;
use crate::process_bpf_task::{event_find_parent, get_task_pid_vnr};
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::*;
use tetragon_common::flags::msg_flags;
use tetragon_common::msg_types::MsgOps;
use tetragon_common::process::{Binary, EventBytes, MsgCloneEvent, MsgExecveKey};
use tetragon_common::vmlinux::{__u32, pid_t, task_struct};

#[kprobe(function = "wake_up_new_task")]
pub fn wake_up_new_task(ctx: ProbeContext) -> u32 {
    match unsafe { try_wake_up_new_task(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_wake_up_new_task(ctx: ProbeContext) -> Result<u32, i64> {
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    trace!(&ctx, "Start wake_up_new_task. caller: {}", caller_tgid);

    let task: *const task_struct = ctx.arg(0).ok_or(1)?;
    let tgid = bpf_probe_read_kernel(&(*task).tgid as *const pid_t)?.unsigned_abs();
    let tid = bpf_probe_read_kernel(&(*task).pid as *const pid_t)?.unsigned_abs();

    if tgid == tid {
        trace!(
            &ctx,
            "Start MainThread:, caller: {}, tgid: {}, tid: {}",
            caller_tgid,
            tgid,
            tid
        );
    } else {
        trace!(
            &ctx,
            "Start SubThread:,  caller: {}, tgid: {}, tid: {}",
            caller_tgid,
            tgid,
            tid
        );
    }

    let Some(parent) = event_find_parent(&ctx, &*task, tgid) else {
        warn!(
            &ctx,
            "There is no parent. caller: {}, tgid: {}, tid: {}", caller_tgid, tgid, tid
        );
        return Ok(0);
    };

    let Some(curr) = execve_map_get(&tgid) else {
        warn!(
            &ctx,
            "The execve_map doesn't have tgid. caller: {}, tgid: {}, tid: {}",
            caller_tgid,
            tgid,
            tid
        );
        return Ok(0);
    };

    let curr = &mut *curr;
    if curr.key.ktime != 0 {
        trace!(
            &ctx,
            "Current(tgid={}) ktime is already set. caller: {}, tgid: {}, tid: {}",
            tgid,
            caller_tgid,
            tgid,
            tid
        );
        return Ok(0);
    }

    curr.flags = msg_flags::EVENT_COMMON_FLAG_CLONE as __u32;
    curr.key.pid = tgid;
    curr.key.ktime = bpf_ktime_get_ns();
    curr.nspid = get_task_pid_vnr(&ctx, tgid);

    Binary::copy(&mut curr.bin, &parent.bin);
    MsgExecveKey::copy(&mut curr.pkey, &parent.key);

    let caps = get_current_subj_caps(task);
    curr.caps.permitted = caps.permitted;
    curr.caps.effective = caps.effective;
    curr.caps.inheritable = caps.inheritable;

    let event_bytes = {
        let ptr = CLONE_HEAP_MAP.get_ptr_mut(0).ok_or(1)?;
        &mut *ptr
    };
    event_bytes.initialize();
    let msg: &mut MsgCloneEvent =
        unsafe { &mut *(event_bytes as *mut EventBytes as *mut MsgCloneEvent) };

    msg.common.op = MsgOps::MsgOpClone as u8;
    msg.common.ktime = curr.key.ktime;

    let mut parent_copy = msg.parent;
    MsgExecveKey::copy(&mut parent_copy, &curr.pkey);
    msg.parent = parent_copy;

    msg.tgid = curr.key.pid;

    if tgid == tid {
        trace!(
            &ctx,
            "End MainThread:, caller: {}, tgid: {}, tid: {}",
            caller_tgid,
            tgid,
            tid
        );
    } else {
        trace!(
            &ctx,
            "End SubThread:,  caller: {}, tgid: {}, tid: {}",
            caller_tgid,
            tgid,
            tid
        );
    }

    msg.tid = tid;
    msg.ktime = curr.key.ktime;
    msg.nspid = curr.nspid;
    msg.flags = curr.flags;

    TCPMON_MAP.output(&ctx, event_bytes, 0);

    debug!(
        &ctx,
        "wake_up_new_task. caller: {}, tgid: {}, tid: {}", caller_tgid, tgid, tid
    );
    Ok(0)
}
