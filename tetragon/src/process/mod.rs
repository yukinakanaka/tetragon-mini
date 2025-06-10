pub mod args;
pub mod cache;
pub mod podinfo;
pub mod procfs;

use crate::api::{
    BinaryProperties, Capabilities, FileProperties, InodeProperties, Namespaces,
    Process as ApiProcess, ProcessCredentials,
};
use crate::ktime::to_proto_opt;
use crate::process::args::args_decoder;
use crate::process::cache::{cache_add, cache_get};
use crate::process::podinfo::get_pod_info;
use crate::reader::caps::{
    get_msg_capabilities, get_privileges_changed_reasons, get_secure_bits_types, EXECVE_SETGID,
    EXECVE_SETUID,
};
use crate::reader::namespace::get_msg_namespaces;
use crate::reader::proc::INVALID_UID;
use crate::watcher::PodStore;
use anyhow;
use base64::{engine::general_purpose, Engine as _};
use core::mem;
use tetragon_common::flags::msg_flags;
use tetragon_common::process::{MsgCloneEvent, MsgExecveEvent, MsgExecveKey, MsgExit, MsgProcess};
use tracing::*;

#[derive(Debug, Default, Clone)]
pub struct ProcessInternal {
    pub process: ApiProcess,
    pub capabilities: Capabilities,
    pub api_creds: ProcessCredentials,
    pub namespaces: Namespaces,
    pub api_binary_prop: BinaryProperties,
    pub refcnt: u32,
}

pub fn get_process_id(pid: u32, ktime: u64) -> String {
    let formatted_string = format!("{}:{}:{}", "nodename", ktime, pid);
    general_purpose::STANDARD.encode(formatted_string)
}

pub fn get_exec_id(proc: &MsgProcess) -> String {
    get_process_id(proc.pid, proc.ktime)
}

pub fn get_exec_id_from_key(key: &MsgExecveKey) -> String {
    get_process_id(key.pid, key.ktime)
}

pub fn init_process_internal_clone(
    event: &MsgCloneEvent,
    mut parent: ProcessInternal,
    parent_exec_id: String,
    store: PodStore,
) -> anyhow::Result<ProcessInternal> {
    parent.process.parent_exec_id = parent_exec_id;
    parent.process.exec_id = get_process_id(event.tgid, event.ktime);
    parent.process.pid = Some(event.tgid);

    if event.tgid != event.tid {
        debug!("CloneEvent: Process PID and TID mismatch.");
        return Err(anyhow::anyhow!("CloneEvent: Process PID and TID mismatch."));
    }

    parent.process.tid = Some(event.tid);
    parent.process.start_time = Some(to_proto_opt(event.ktime));
    parent.process.refcnt = 1;

    // let pod_info = get_pod_info(
    //     &parent.process.docker,
    //     parent.process.binary.as_str(),
    //     &parent.process.arguments,
    //     event.nspid,
    //     store.clone(),
    // );
    // parent.process.pod = pod_info;

    Ok(parent)
}

pub async fn add_clone_event(event: &MsgCloneEvent, store: PodStore) -> anyhow::Result<()> {
    let pid = event.parent.pid;
    let tid = event.tid;
    let parent_exec_id = get_process_id(pid, event.parent.ktime);

    let Some(parent) = cache_get(&parent_exec_id).await else {
        return Err(anyhow::anyhow!(
            "CloneEvent: parent process not found in cache: parent: {}, pid: {}",
            pid,
            tid
        ));
    };

    let proc = init_process_internal_clone(event, parent, parent_exec_id, store.clone())?;

    cache_add(proc).await?;

    Ok(())
}

pub fn init_process_internal_exec(
    event: &mut MsgExecveEvent,
    parent: &MsgExecveKey,
    store: PodStore,
) -> anyhow::Result<ProcessInternal> {
    let mut process = event.process;
    let container_id = std::str::from_utf8(&event.kube.docker_id)
        .map(|valid_str| valid_str.trim_end_matches('\0').to_string())
        .map_err(|_| anyhow::anyhow!("Error converting container_id to String"))?;

    let (args, cwd) = args_decoder(&event.exe.args, process.flags);

    let parent_exec_id = if parent.pid != 0 {
        get_exec_id_from_key(parent)
    } else {
        get_process_id(0, 1)
    };

    let creds = event.creds;
    let exec_id = get_exec_id(&process);

    let proto_pod = get_pod_info(
        event.kube.cgrpid,
        "filename",
        &args,
        process.nspid,
        store.clone(),
    );

    let api_caps = get_msg_capabilities(&event.creds.caps);

    let len = event
        .exe
        .filename
        .iter()
        .position(|&x| x == 0)
        .unwrap_or(event.exe.filename.len());
    let binary = std::str::from_utf8(&event.exe.filename[..len])
        .unwrap()
        .to_string();

    let api_ns = get_msg_namespaces(event.ns)?;

    let api_creds = ProcessCredentials {
        uid: Some(creds.uid),
        gid: Some(creds.gid),
        euid: Some(creds.euid),
        egid: Some(creds.egid),
        suid: Some(creds.suid),
        sgid: Some(creds.sgid),
        fsuid: Some(creds.fsuid),
        fsgid: Some(creds.fsgid),
        securebits: get_secure_bits_types(creds.securebits),
        caps: None,
        user_ns: None,
    };

    let mut api_binary_prop = BinaryProperties {
        setuid: Some(INVALID_UID),
        setgid: Some(INVALID_UID),
        file: None,
        privileges_changed: vec![],
    };
    if process.secureexec & EXECVE_SETUID != 0 {
        api_binary_prop.setuid = Some(creds.euid);
    }
    if process.secureexec & EXECVE_SETGID != 0 {
        api_binary_prop.setuid = Some(creds.egid);
    }
    api_binary_prop.privileges_changed = get_privileges_changed_reasons(process.secureexec);

    if process.i_ino != 0 && process.i_nlink == 0 {
        let inode = InodeProperties {
            number: process.i_ino,
            links: Some(process.i_nlink),
        };
        api_binary_prop.file = Some(FileProperties {
            inode: Some(inode),
            ..Default::default()
        })
    }

    if process.pid != process.tid {
        warn!("ExecveEvent: process PID and TID mismatch");
        // Explicitly reset TID to be PID
        process.tid = process.pid;
    }

    let flags = process.flags;

    Ok(ProcessInternal {
        process: ApiProcess {
            pid: Some(process.pid),
            tid: Some(process.tid),
            uid: Some(process.uid),
            cwd,
            binary,
            arguments: args,
            flags: flags.to_string(),
            start_time: Some(to_proto_opt(process.ktime)),
            auid: Some(process.auid),
            pod: proto_pod,
            exec_id,
            docker: container_id,
            parent_exec_id,
            refcnt: 0,
            cap: None,
            ns: None,
            binary_properties: None,
            process_credentials: None,
            user: None,
            in_init_tree: None,
        },
        capabilities: api_caps,
        api_creds,
        api_binary_prop,
        namespaces: api_ns,
        refcnt: 1,
    })
}

pub async fn add_exec_event(
    event: &mut MsgExecveEvent,
    store: PodStore,
) -> anyhow::Result<ProcessInternal> {
    let proc: ProcessInternal = if event.cleanup_key.ktime == 0
        || (event.process.flags as u64 & msg_flags::EVENT_CLONE) != 0
    {
        // there is a case where we cannot find this entry in execve_map
        // in that case we use as parent what Linux knows
        init_process_internal_exec(event, &event.parent.clone(), store)?
    } else {
        init_process_internal_exec(event, &event.cleanup_key.clone(), store)?
    };

    cache_add(proc.clone()).await?;

    Ok(proc)
}

pub fn print_struct_size() {
    info!("Struct size:");
    info!("MsgCloneEvent size: {}", mem::size_of::<MsgCloneEvent>());
    info!("MsgExecveEvent size: {}", mem::size_of::<MsgExecveEvent>());
    info!("MsgExit size: {}", mem::size_of::<MsgExit>());
}
