use crate::lib_helper::offset_of;
use crate::maps;
use crate::process_bpf_process_event::{
    event_set_clone, get_auid, get_current_subj_creds, get_namespaces,
};
use crate::process_bpf_rate::cgroup_rate;
use crate::process_bpf_task::{event_find_parent, event_minimal_parent, get_task_pid_vnr};
use aya_ebpf::helpers::{
    bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
    gen::{bpf_get_current_pid_tgid, bpf_probe_read_str, bpf_probe_read_user},
};
use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::btf_tracepoint,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::*;
use tetragon_common::flags::msg_flags;
use tetragon_common::msg_types::MsgOps;
use tetragon_common::process::{
    init_bytes, Binary, EventBytes, MsgExecveEvent, MsgExecveKey, MsgNs, MsgProcess, ARGS_MAX_LEN,
    BINARY_PATH_MAX_LEN,
};
use tetragon_common::vmlinux::{__u32, __u64, linux_binprm, mm_struct, pid_t, task_struct};

#[btf_tracepoint(function = "sched_process_exec")]
pub fn sched_process_exec(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_sched_process_exec(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_sched_process_exec(ctx: BtfTracePointContext) -> Result<u32, i64> {
    let event_bytes = {
        let ptr = maps::EXECVE_MSG_HEAP_MAP.get_ptr_mut(0).ok_or(1)?;
        &mut *ptr
    };
    init_bytes(event_bytes);

    let event: &mut MsgExecveEvent =
        unsafe { &mut *(event_bytes as *mut EventBytes as *mut MsgExecveEvent) };
    event.parent_flags = 1;

    let task: *const task_struct = ctx.arg(0);

    let tgid = bpf_probe_read_kernel(&(*task).tgid as *const pid_t).unwrap_or(0);
    let pid = bpf_probe_read_kernel(&(*task).pid as *const pid_t).unwrap_or(0);

    let parent = event_find_parent(&ctx, task, tgid.unsigned_abs());
    match parent {
        Some(parent) => {
            let mut parent_copy = event.parent;
            MsgExecveKey::copy(&mut parent_copy, &parent.key);
            event.parent = parent_copy;
        }
        None => event_minimal_parent(event, task),
    }

    event.process.flags = msg_flags::EVENT_EXECVE as __u32;

    event.process.pid = tgid.unsigned_abs();
    event.process.tid = pid.unsigned_abs();
    event.process.nspid = get_task_pid_vnr(&ctx, tgid.unsigned_abs());
    event.process.ktime = bpf_ktime_get_ns();

    event.process.size = offset_of::<MsgProcess>(|p| unsafe { &(*p).args as *const _ }) as u32;
    event.process.auid = get_auid() as u32;

    read_execve_shared_info(&mut event.process, pid as u64);

    event.common.op = MsgOps::MsgOpExecve as u8;
    event.common.ktime = event.process.ktime;

    event.common.size =
        offset_of::<MsgExecveEvent>(|p| unsafe { &(*p).process as *const _ as *const u8 }) as u32
            + event.process.size;

    let nsproxy = bpf_probe_read_kernel(&(*task).nsproxy)?;
    let net_ns = bpf_probe_read_kernel(&(*nsproxy).net_ns)?;
    let ns = bpf_probe_read_kernel(&(*net_ns).ns)?;
    event.kube.net_ns = ns.inum;

    get_current_subj_creds(&mut event.creds, task);

    event.process.uid = event.creds.euid;

    get_namespaces(&mut event.ns, task);

    let linux_binprm: *const linux_binprm = ctx.arg(2);
    let linux_binprm: &linux_binprm = &*linux_binprm;
    let filename_ptr = linux_binprm.filename;
    bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.exe.filename)
        .map(|s| core::str::from_utf8_unchecked(s))?;

    let _ = read_args(task, event);

    let res = maps::EXECVE_CALLS.tail_call(&ctx, 0);
    if res.is_err() {
        debug!(&ctx, "tail_call failed sched_process_exec");
    }

    debug!(&ctx, "sched_process_exec. tgid: {}, tid: {}", tgid, pid);
    Ok(0)
}

#[btf_tracepoint(function = "execve_rate")]
pub fn execve_rate(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_execve_rate(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_execve_rate(ctx: BtfTracePointContext) -> Result<u32, i64> {
    let event_bytes = {
        let ptr = maps::EXECVE_MSG_HEAP_MAP.get_ptr_mut(0).ok_or(1)?;
        &mut *ptr
    };
    let msg: &mut MsgExecveEvent =
        unsafe { &mut *(event_bytes as *mut EventBytes as *mut MsgExecveEvent) };

    if cgroup_rate(&ctx, &mut msg.kube, msg.common.ktime) {
        let _ = maps::EXECVE_CALLS.tail_call(&ctx, 1);
    }

    Ok(0)
}

#[btf_tracepoint(function = "execve_send")]
pub fn execve_send(ctx: BtfTracePointContext) -> u32 {
    match unsafe { try_execve_send(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap(),
    }
}

unsafe fn try_execve_send(ctx: BtfTracePointContext) -> Result<u32, i64> {
    let event_bytes = {
        let ptr = maps::EXECVE_MSG_HEAP_MAP.get_ptr_mut(0).ok_or(1)?;
        &mut *ptr
    };

    let event: &mut MsgExecveEvent =
        unsafe { &mut *(event_bytes as *mut EventBytes as *mut MsgExecveEvent) };

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let curr = maps::EXECVE_MAP.get_ptr_mut(&pid);

    let mut init_curr: bool = false;

    if let Some(curr) = curr {
        let curr = &mut *curr;
        MsgExecveKey::copy(&mut event.cleanup_key, &curr.key);

        if curr.flags as u64 == msg_flags::EVENT_COMMON_FLAG_CLONE {
            init_curr = true;
        }

        curr.key.pid = event.process.pid;
        curr.key.ktime = event.process.ktime;
        curr.nspid = event.process.nspid;
        MsgExecveKey::copy(&mut curr.pkey, &event.parent);

        if curr.flags as u64 & msg_flags::EVENT_COMMON_FLAG_CLONE != 0 {
            event_set_clone(&mut event.process);
        }

        curr.flags = 0;
        if init_curr {
            MsgNs::copy(&mut curr.ns, &event.ns);
            curr.caps.permitted = event.creds.caps.permitted;
            curr.caps.effective = event.creds.caps.effective;
            curr.caps.inheritable = event.creds.caps.inheritable;
        }

        curr.bin = Binary::default();

        curr.bin.path_length = bpf_probe_read_str(
            curr.bin.path.as_mut_ptr() as *mut aya_ebpf_cty::c_void,
            BINARY_PATH_MAX_LEN as u32,
            event.process.args as *const aya_ebpf_cty::c_void,
        );

        if curr.bin.path_length > 1 {
            curr.bin.path_length -= 1;
        }
    }

    maps::TCPMON_MAP.output(&ctx, event_bytes, 0);

    Ok(0)
}

#[inline]
unsafe fn read_execve_shared_info(p: &mut MsgProcess, pid: __u64) {
    let info = maps::TG_EXECVE_JOINED_INFO_MAP.get(&pid);
    match info {
        None => {
            p.secureexec = 0;
            p.i_ino = 0;
            p.i_nlink = 0;
        }
        Some(info) => {
            p.secureexec = info.secureexec;
            p.i_ino = info.i_ino;
            p.i_nlink = info.i_nlink;
            let _ = maps::TG_EXECVE_JOINED_INFO_MAP.remove(&pid);
        }
    }
}

#[inline]
unsafe fn read_args(task: *const task_struct, event: &mut MsgExecveEvent) -> Result<u32, i64> {
    let mm: *mut mm_struct = bpf_probe_read_kernel(&(*task).mm)?;
    let arg_start = bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.arg_start)?;
    let arg_end = bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.arg_end)?;

    // First argument is binary path, and ignore it
    let heap = unsafe {
        let ptr = maps::GARBAGE_HEAP.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    let binary_path = bpf_probe_read_user_str_bytes(arg_start as *const u8, &mut heap.heap)?;

    let arg_start = arg_start + binary_path.len() as u64 + 1;

    let args_len = (arg_end - arg_start) as u32;
    // This is needed to pass verifier check
    let args_len = args_len.min(ARGS_MAX_LEN as u32);

    bpf_probe_read_user(
        event.exe.args.as_mut_ptr() as *mut aya_ebpf_cty::c_void,
        args_len,
        arg_start as *const aya_ebpf_cty::c_void,
    );
    Ok(0)
}
