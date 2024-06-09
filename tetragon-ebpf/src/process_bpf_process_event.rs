use crate::lib_bpf_cgroup::{__tg_get_current_cgroup_id, get_cgroup_name, get_task_cgroup};
use aya_ebpf::helpers::{
    bpf_get_current_task, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
};
use tetragon_common::bpf_cred::{MsgCapabilities, MsgCred};
use tetragon_common::process::{MsgK8s, MsgNs, MsgProcess};
use tetragon_common::vmlinux::*;

use tetragon_common::flags::msg_flags::EVENT_CLONE;

#[inline]
pub unsafe fn get_current_subj_caps(task: *const task_struct) -> MsgCapabilities {
    let Ok(cred) = bpf_probe_read_kernel(&(*task).cred as &*const cred) else {
        return MsgCapabilities {
            ..Default::default()
        };
    };
    let Ok(permitted) = bpf_probe_read_kernel(&(*cred).cap_permitted as *const kernel_cap_t) else {
        return MsgCapabilities {
            ..Default::default()
        };
    };
    let Ok(effective) = bpf_probe_read_kernel(&(*cred).cap_effective as *const kernel_cap_t) else {
        return MsgCapabilities {
            ..Default::default()
        };
    };
    let Ok(inheritable) = bpf_probe_read_kernel(&(*cred).cap_inheritable as *const kernel_cap_t)
    else {
        return MsgCapabilities {
            ..Default::default()
        };
    };
    MsgCapabilities {
        permitted: permitted.val,
        effective: effective.val,
        inheritable: inheritable.val,
    }
}

#[inline]
pub unsafe fn get_auid() -> __u64 {
    let task = bpf_get_current_task() as *const task_struct;
    task.as_ref()
        .and_then(|t| bpf_probe_read_kernel(&t.loginuid).ok())
        .map(|loginuid| loginuid.val as __u64)
        .unwrap_or(0)
}

#[inline]
pub unsafe fn get_current_subj_creds(info: &mut MsgCred, task: *const task_struct) {
    let Ok(cred) = bpf_probe_read_kernel((*task).cred) else {
        return;
    };

    info.uid = cred.uid.val;
    info.gid = cred.gid.val;
    info.euid = cred.euid.val;
    info.egid = cred.egid.val;
    info.suid = cred.suid.val;
    info.sgid = cred.sgid.val;
    info.fsuid = cred.fsuid.val;
    info.fsgid = cred.fsgid.val;
    info.securebits = cred.securebits;
}

#[inline]
pub unsafe fn __get_caps(msg: &mut MsgCapabilities, cred: &cred) {
    msg.effective = cred.cap_effective.val;
    msg.inheritable = cred.cap_inheritable.val;
    msg.permitted = cred.cap_permitted.val;
}

#[inline]
pub unsafe fn get_namespaces(msg: &mut MsgNs, task: *const task_struct) {
    let Ok(nsp) = bpf_probe_read_kernel(&(*task).nsproxy) else {
        return;
    };
    let Ok(uts_ns) = bpf_probe_read_kernel(&(*nsp).uts_ns) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*uts_ns).ns) else {
        return;
    };
    msg.uts_inum = ns.inum;

    let Ok(ipc_ns) = bpf_probe_read_kernel(&(*nsp).ipc_ns) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*ipc_ns).ns) else {
        return;
    };
    msg.ipc_inum = ns.inum;

    let Ok(mnt_ns) = bpf_probe_read_kernel(&(*nsp).mnt_ns) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*mnt_ns).ns) else {
        return;
    };
    msg.mnt_inum = ns.inum;

    {
        msg.pid_inum = 0;
        if let Ok(p) = bpf_probe_read_kernel(&(*task).thread_pid) {
            let level = (*p).level as usize;

            if let Ok(numbers) = bpf_probe_read_kernel(&(*p).numbers) {
                let up = numbers.as_slice(level + 1)[level];
                if let Ok(pid_ns) = bpf_probe_read_kernel(up.ns) {
                    msg.pid_inum = pid_ns.ns.inum;
                }
            }
        }
    }

    let Ok(pid_for_children_inum) = bpf_probe_read_kernel(&(*nsp).pid_ns_for_children) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*pid_for_children_inum).ns) else {
        return;
    };
    msg.pid_for_children_inum = ns.inum;

    let Ok(net_ns) = bpf_probe_read_kernel(&(*nsp).net_ns) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*net_ns).ns) else {
        return;
    };
    msg.net_inum = ns.inum;

    let Ok(time_ns) = bpf_probe_read_kernel(&(*nsp).time_ns) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*time_ns).ns) else {
        return;
    };
    msg.time_inum = ns.inum;

    let Ok(time_ns_for_children) = bpf_probe_read_kernel(&(*nsp).time_ns_for_children) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*time_ns_for_children).ns) else {
        return;
    };
    msg.time_for_children_inum = ns.inum;

    let Ok(cgroup_ns) = bpf_probe_read_kernel(&(*nsp).cgroup_ns) else {
        return;
    };
    let Ok(ns) = bpf_probe_read_kernel(&(*cgroup_ns).ns) else {
        return;
    };
    msg.cgroup_inum = ns.inum;

    {
        let Ok(mm) = bpf_probe_read_kernel(&(*task).mm) else {
            return;
        };

        let Ok(user_ns) = bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.user_ns) else {
            return;
        };
        let Ok(ns) = bpf_probe_read_kernel(&(*user_ns).ns) else {
            return;
        };
        msg.user_inum = ns.inum;
    }
}

#[inline]
pub unsafe fn __event_get_cgroup_info(task: *const task_struct, kube: &mut MsgK8s) -> __u32 {
    // Now support only Cgroup v2

    let cgrpfs_magic: __u64 = 0;
    let subsys_idx: __u32 = 0;
    // struct cgroup *cgrp;
    // struct tetragon_conf *conf;
    let mut flags: __u32 = 0;

    // conf = map_lookup_elem(&tg_conf_map, &zero);
    // if (conf) {
    // 	/* Select which cgroup version */
    // 	cgrpfs_magic = conf->cgrp_fs_magic;
    // 	subsys_idx = conf->tg_cgrpv1_subsys_idx;
    // }

    let Some(cgrp) = get_task_cgroup(task, cgrpfs_magic, subsys_idx, &mut flags) else {
        return 1;
    };

    // /* Collect event cgroup ID */
    kube.cgrpid = __tg_get_current_cgroup_id(cgrp, cgrpfs_magic);
    // if (kube->cgrpid)
    // 	kube->cgrp_tracker_id = cgrp_get_tracker_id(kube->cgrpid);
    // else
    // 	flags |= EVENT_ERROR_CGROUP_ID;

    // /* Get the cgroup name of this event. */
    // flags |= __event_get_current_cgroup_name(cgrp, kube);
    __event_get_current_cgroup_name(cgrp, kube);
    // return flags;
    return 0;
}

#[inline]
pub unsafe fn event_set_clone(pid: &mut MsgProcess) {
    pid.flags = (pid.flags as u64 | EVENT_CLONE) as u32;
}

/* Gather current task cgroup name */
#[inline]
pub unsafe fn __event_get_current_cgroup_name(cgrp: *const cgroup, kube: &mut MsgK8s) -> __u32 {
    let Some(name) = get_cgroup_name(cgrp) else {
        return 1;
    };

    let _ = bpf_probe_read_kernel_str_bytes(name as *const u8, &mut kube.docker_id);
    return 0;
}
