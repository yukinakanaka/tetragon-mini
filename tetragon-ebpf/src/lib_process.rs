use crate::maps;
use tetragon_common::{process::ExecveMapValue, vmlinux::*};

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
