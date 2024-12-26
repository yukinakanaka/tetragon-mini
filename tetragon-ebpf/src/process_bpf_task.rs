use crate::maps;
use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::EbpfContext;
use aya_log_ebpf::*;
use tetragon_common::flags::msg_flags;
use tetragon_common::process::{ExecveMapValue, MsgExecveEvent};
use tetragon_common::vmlinux::{pid_t, task_struct};
#[inline]
pub unsafe fn event_find_parent<C: EbpfContext>(
    ctx: &C,
    task: *const task_struct,
    tgid: u32,
) -> Option<&ExecveMapValue> {
    let mut current = task;
    for _ in 0..4 {
        let Ok(parent) = bpf_probe_read_kernel(&(*current).real_parent as &*mut task_struct) else {
            warn!(ctx, "No parent. tgid: {}", tgid);
            return None;
        };
        current = parent;

        let Ok(parent_tgid) = bpf_probe_read_kernel(&(*parent).tgid as *const pid_t) else {
            warn!(ctx, "No parent_tgid. tgid: {}", tgid);
            return None;
        };

        let value = maps::EXECVE_MAP
            .get(&parent_tgid.unsigned_abs())
            .inspect(|&value| {
                if value.key.ktime == 0 {
                    trace!(
                        ctx,
                        "Found value with ktime == 0. parent_tgid: {}, tgid: {}",
                        parent_tgid,
                        tgid
                    )
                }
            })
            .filter(|&value| value.key.ktime != 0);
        if value.is_some() {
            trace!(
                ctx,
                "Found parent in map. parent_tgid: {}, tgid: {}",
                parent_tgid,
                tgid
            );
            return value;
        }
        warn!(
            ctx,
            "Didn't find parent in map. parent_tgid: {}, tgid: {}", parent_tgid, tgid
        );
    }
    warn!(ctx, "Didn't find parent in map for times. {}", tgid);
    None
}

#[inline]
pub unsafe fn get_task_pid_vnr<C: EbpfContext>(ctx: &C, tgid: u32) -> u32 {
    let task = bpf_get_current_task() as *const task_struct;

    let thread_pid = match bpf_probe_read_kernel(&(*task).thread_pid) {
        Ok(pid) => pid,
        Err(_) => return 0,
    };

    let upid = match bpf_probe_read_kernel(&(*thread_pid).numbers) {
        Ok(upid) => upid.as_slice(1)[0],
        Err(_) => return 0,
    };

    trace!(
        ctx,
        "get_task_pid_vnr. upid.nr: {}, tgid: {}",
        upid.nr,
        tgid
    );
    upid.nr.unsigned_abs()
}

#[inline]
pub unsafe fn event_minimal_parent(event: &mut MsgExecveEvent, task: *const task_struct) {
    event.parent.pid = bpf_probe_read_kernel(&(*task).real_parent as &*mut task_struct)
        .and_then(|parent| bpf_probe_read_kernel(&(*parent).tgid as *const pid_t))
        .map(|tgid| tgid.unsigned_abs())
        .unwrap_or(0);

    event.parent.ktime = 0;
    event.parent_flags = msg_flags::EVENT_MISS;
}
