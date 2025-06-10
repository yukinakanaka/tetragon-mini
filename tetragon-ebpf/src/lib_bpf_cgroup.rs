use aya_ebpf::helpers::{bpf_get_current_cgroup_id, bpf_probe_read_kernel};
use tetragon_common::vmlinux::*;

#[inline]
#[allow(dead_code)]
pub unsafe fn get_task_cgroup(
    task: *const task_struct,
    _cgrpfs_ver: __u64,
    _subsys_idx: __u32,
    _error_flags: &mut __u32,
) -> Option<*const cgroup> {
    // Now support only Cgroup v2

    let cgroups_ptr: *const css_set = match bpf_probe_read_kernel(&(*task).cgroups) {
        Ok(ptr) => ptr as *const css_set,
        Err(_) => return None,
    };

    let dfl_cgrp: *const cgroup = match bpf_probe_read_kernel(&(*cgroups_ptr).dfl_cgrp) {
        Ok(ptr) => ptr as *const cgroup,
        Err(_) => return None,
    };

    Some(dfl_cgrp)
}

#[inline]
#[allow(dead_code)]
pub unsafe fn __tg_get_current_cgroup_id(_cgrp: *const cgroup, _cgrpfs_ver: __u64) -> __u64 {
    // Now support only Cgroup v2
    bpf_get_current_cgroup_id()
}

/**
 * get_cgroup_name() Returns a pointer to the cgroup name
 * @cgrp: target cgroup
 *
 * Returns a pointer to the cgroup node name on success that can
 * be read with probe_read_kernel(). NULL on failures.
 */
#[inline]
pub unsafe fn get_cgroup_name(cgrp: *const cgroup) -> Option<*const u8> {
    let kn_ptr: *const kernfs_node = match bpf_probe_read_kernel(&(*cgrp).kn) {
        Ok(ptr) => ptr as *const kernfs_node,
        Err(_) => return None,
    };

    let name_ptr = match bpf_probe_read_kernel(&(*kn_ptr).name) {
        Ok(ptr) => ptr as *const u8,
        Err(_) => return None,
    };

    Some(name_ptr)
}
