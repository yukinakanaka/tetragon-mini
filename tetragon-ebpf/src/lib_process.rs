use crate::maps;
use tetragon_common::{msg_types::MsgOps, process::*, vmlinux::*};

#[inline]
pub unsafe fn execve_map_get(pid: &__u32) -> Option<*mut ExecveMapValue> {
    if let Some(value) = maps::EXECVE_MAP.get_ptr_mut(pid) {
        return Some(value);
    }

    let buf = {
        if let Some(ptr) = maps::EXECVE_VAL.get_ptr_mut(0) {
            &mut *ptr
        } else {
            return None;
        }
    };

    match maps::EXECVE_MAP.insert(pid, &buf, 0) {
        Ok(_) => {
            if let Some(count) = maps::EXECVE_MAP_STATS.get_ptr_mut(maps::MAP_STATS_COUNT) {
                *count = *count + 1;
            }
        }
        Err(_) => execve_map_error(),
    }
    maps::EXECVE_MAP.get_ptr_mut(pid)
}

#[inline]
pub unsafe fn execve_map_error() {
    if let Some(count) = maps::EXECVE_MAP_STATS.get_ptr_mut(maps::MAP_STATS_ERROR) {
        *count = *count + 1;
    }
}

#[inline]
pub unsafe fn execve_map_delete(pid: __u32) {
    match maps::EXECVE_MAP.remove(&pid) {
        Ok(_) => {
            if let Some(count) = maps::EXECVE_MAP_STATS.get_ptr_mut(maps::MAP_STATS_COUNT) {
                *count = *count - 1;
            }
        }
        Err(_) => execve_map_error(),
    }
}

pub const _MAXARGS: usize = 20;
pub const _MAXARGLENGTH: usize = 256;

#[inline]
pub unsafe fn perf_event_output_metric<C: aya_ebpf::EbpfContext>(
    ctx: &C,
    _msg_op: MsgOps,
    event_bytes: &EventBytes,
    _flags: u32,
) {
    maps::TCPMON_MAP.output(ctx, event_bytes, 0);
    // Currently, fn output doesn't return bpf_perf_event_output's return value.
    // https://github.com/aya-rs/aya/blob/a43e40ae1d1441ab4aea6a1a5d9ea36b56d62ff8/ebpf/aya-ebpf/src/maps/perf/perf_event_array.rs#L53C5-L63C10
    // let err = maps::TCPMON_MAP.output(ctx, event_bytes, 0);
    // if err < 0 {
    //     update_error_metric(msg_op, err as i32);
    // }
}

#[inline]
#[allow(dead_code)]
pub unsafe fn update_error_metric(msg_op: MsgOps, err: i32) {
    if let Some(kernel_stats) = maps::TG_STATS_MAP.get_ptr_mut(0) {
        let error_index = match err {
            -2 => SENT_FAILED_ENOENT,  // ENOENT
            -7 => SENT_FAILED_E2BIG,   // E2BIG
            -16 => SENT_FAILED_EBUSY,  // EBUSY
            -22 => SENT_FAILED_EINVAL, // EINVAL
            -28 => SENT_FAILED_ENOSPC, // ENOSPC
            _ => SENT_FAILED_UNKNOWN,  // UNKOWN ERROR
        };

        // TODO: __sync_fetch_and_add
        (&mut *kernel_stats).sent_failed[msg_op as usize][error_index] += 1;
    }
}
