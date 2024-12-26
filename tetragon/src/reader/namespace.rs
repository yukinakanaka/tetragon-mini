use crate::api::{Namespace, Namespaces};
use crate::util::NamespaceType;
use anyhow::Ok;
use std::ffi::OsString;
use tetragon_common::process::MsgNs;

use std::sync::LazyLock;
static HOST_NS: LazyLock<Namespaces> = LazyLock::new(init_host_namespace);

pub fn get_msg_namespaces(ns: MsgNs) -> anyhow::Result<Namespaces> {
    let host_ns = &HOST_NS;

    let host_time_inum = host_ns.time.as_ref().unwrap().inum;
    let host_time_for_children_inum = host_ns.time_for_children.as_ref().unwrap().inum;
    let mut ret = Namespaces {
        uts: Some(Namespace {
            inum: ns.uts_inum,
            is_host: ns.uts_inum == host_ns.uts.as_ref().unwrap().inum,
        }),
        ipc: Some(Namespace {
            inum: ns.ipc_inum,
            is_host: ns.ipc_inum == host_ns.ipc.as_ref().unwrap().inum,
        }),
        mnt: Some(Namespace {
            inum: ns.mnt_inum,
            is_host: ns.mnt_inum == host_ns.mnt.as_ref().unwrap().inum,
        }),
        pid: Some(Namespace {
            inum: ns.pid_inum,
            is_host: ns.pid_inum == host_ns.pid.as_ref().unwrap().inum,
        }),
        pid_for_children: Some(Namespace {
            inum: ns.pid_for_children_inum,
            is_host: ns.pid_for_children_inum == host_ns.pid_for_children.as_ref().unwrap().inum,
        }),
        net: Some(Namespace {
            inum: ns.net_inum,
            is_host: ns.net_inum == host_ns.net.as_ref().unwrap().inum,
        }),
        time: Some(Namespace {
            inum: ns.time_inum,
            is_host: host_time_inum != 0 && ns.time_inum == host_time_inum,
        }),
        time_for_children: Some(Namespace {
            inum: ns.time_for_children_inum,
            is_host: host_time_for_children_inum != 0
                && ns.time_for_children_inum == host_ns.time_for_children.as_ref().unwrap().inum,
        }),
        cgroup: Some(Namespace {
            inum: ns.cgroup_inum,
            is_host: ns.cgroup_inum == host_ns.cgroup.as_ref().unwrap().inum,
        }),
        user: Some(Namespace {
            inum: ns.user_inum,
            is_host: ns.user_inum == host_ns.user.as_ref().unwrap().inum,
        }),
    };

    // This kernel does not support time namespace, so we explicitly set them to nil
    if let Some(ref time) = ret.time {
        if time.inum == 0 {
            ret.time = None;
            ret.time_for_children = None;
        }
    }
    Ok(ret)
}

fn init_host_namespace() -> Namespaces {
    let namespaces = procfs::process::Process::new(1)
        .expect("fail to get pid 1")
        .namespaces()
        .expect("fail to get pid 1 namespaces");

    Namespaces {
        uts: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::Uts.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        ipc: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::Ipc.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        mnt: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::Mnt.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        pid: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::Pid.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        pid_for_children: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::PidForChildren.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        net: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::Net.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        time: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::Time.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        time_for_children: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::TimeForChildren.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        cgroup: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::Cgroup.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
        user: Some(Namespace {
            inum: namespaces
                .0
                .get(&OsString::from(NamespaceType::User.as_str()))
                .map_or(0, |ns| ns.identifier as u32),
            is_host: true,
        }),
    }
}
