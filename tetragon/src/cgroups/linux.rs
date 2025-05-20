#![allow(dead_code)]
use super::CgroupModeCode;
use crate::cgroups::{DeploymentCode, DeploymentEnv};
use std::fs::File;
use std::io::Error;
use std::mem;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use std::sync::{LazyLock, OnceLock};
use tracing::*;

#[derive(Debug, Clone)]
pub struct CgroupController {
    id: u32,      // Hierarchy unique ID
    idx: u32,     // Cgroup SubSys index
    name: String, // Controller name
    active: bool, // Will be set to true if controller is set and active
}

// Path where default cgroupfs is mounted
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";

/* Cgroup controllers that we are interested in
 * are usually the ones that are setup by systemd
 * or other init programs.
 */
pub(crate) static CGROUP_CONTROLLERS: LazyLock<Vec<CgroupController>> = LazyLock::new(|| {
    vec![
        // Memory first
        CgroupController {
            id: 0,
            idx: 0,
            name: "memory".to_string(),
            active: false,
        },
        // pids second
        CgroupController {
            id: 0,
            idx: 0,
            name: "pids".to_string(),
            active: false,
        },
        // fallback
        CgroupController {
            id: 0,
            idx: 0,
            name: "cpuset".to_string(),
            active: false,
        },
    ]
});

// TODO: cgroupv2Hierarchy = "0::"

/* Ordered from nested to top cgroup parents
 * For k8s we check also config k8s flags.
 */
pub(crate) static DEPLOYMENTS: LazyLock<Vec<DeploymentEnv>> = LazyLock::new(|| {
    vec![
        DeploymentEnv {
            id: DeploymentCode::Kubernetes,
            str: Some("kube".to_string()),
            ends_with: None,
        },
        DeploymentEnv {
            id: DeploymentCode::Container,
            str: Some("docker".to_string()),
            ends_with: None,
        },
        DeploymentEnv {
            id: DeploymentCode::Container,
            str: Some("podman".to_string()),
            ends_with: None,
        },
        DeploymentEnv {
            id: DeploymentCode::Container,
            str: Some("libpod".to_string()),
            ends_with: None,
        },
        // If Tetragon is running as a systemd service, its cgroup path will end with .service
        DeploymentEnv {
            id: DeploymentCode::SystemdService,
            str: None,
            ends_with: Some(".service".to_string()),
        },
        DeploymentEnv {
            id: DeploymentCode::SystemdUserSession,
            str: Some("user.slice".to_string()),
            ends_with: None,
        },
    ]
});

static DEPLOYMENT_MODE: OnceLock<DeploymentCode> = OnceLock::new();

static CGROUP_MODE: OnceLock<CgroupModeCode> = OnceLock::new();

// detectCgroupFSOnce sync.Once
// cgroupFSPath       string
// cgroupFSMagic      uint64

static CGRP_MIGRATION_PATH: OnceLock<String> = OnceLock::new();

fn _detect_deployment_mode() -> anyhow::Result<DeploymentCode> {
    let mode = get_deployment_mode();
    if mode != DeploymentCode::Unknown {
        return Ok(mode);
    }

    // TODO
    // Parse own cgroup paths and detect the deployment mode
    // let pid = std::process::id();

    // find_migration_path(pid)?;
    // Ok(get_deployment_mode())

    Ok(DeploymentCode::Unknown)
}

pub fn detect_deployment_mode() -> anyhow::Result<DeploymentCode> {
    DEPLOYMENT_MODE.get_or_init(|| match detect_deployment_mode() {
        Ok(mode) => mode,
        Err(e) => {
            // TODO: return an error using get_or_try_init
            warn!("Failed to detect deployment mode: {}", e);
            DeploymentCode::Unknown
        }
    });

    let mode = get_deployment_mode();
    if mode == DeploymentCode::Unknown {
        warn!("Deployment mode detection failed");
    } else {
        info!("Deployment mode detection succeeded: {}", mode);
    }

    Ok(mode)
}

pub fn get_deployment_mode() -> DeploymentCode {
    *DEPLOYMENT_MODE.get().unwrap_or(&DeploymentCode::Unknown)
}

pub fn host_cgroup_root() -> Result<String, std::io::Error> {
    // TODO: implement
    Ok(DEFAULT_CGROUP_ROOT.to_string())
}

#[repr(C)]
struct FileHandle {
    id: u64,
}

fn get_cgroup_id_from_path(cgroup_path: &str) -> Result<u64, Error> {
    debug!("get_cgroup_id_from_path: {}", cgroup_path);
    let path = Path::new(cgroup_path);
    let file = File::open(path)?;

    // This is a simplified approach as Rust doesn't have a direct equivalent to NameToHandleAt
    // In a real implementation, you would need to use libc or nix crate to make the syscall

    unsafe {
        let mut file_handle = FileHandle { id: 0 };

        // This would be replaced with the actual syscall to name_to_handle_at
        // Using something like libc::name_to_handle_at or nix equivalent

        // For demonstration purposes, we're assuming the file's inode number is equivalent
        // to the cgroup ID, which is a simplification
        let fd = file.as_raw_fd();
        let stat: libc::stat = mem::zeroed();
        if libc::fstat(fd, &stat as *const _ as *mut libc::stat) != 0 {
            return Err(Error::last_os_error());
        }

        file_handle.id = stat.st_ino as u64;

        Ok(file_handle.id)
    }
}

/// GetCgroupIDFromSubCgroup deals with some idiosyncrancies of container runtimes
///
/// Typically, the container processes run in the cgroup path specified in the OCI spec under
/// cgroupsPath. crun, however, is an exception because it uses another directory (called subgroup)
/// under the cgroupsPath:
/// https://github.com/containers/crun/blob/main/crun.1.md#runocisystemdsubgroupsubgroup.
///
/// This function deals with this by checking for a child directory. If it finds one (and only one)
/// it uses the cgroup id from the child.
pub fn get_cgroup_id_from_sub_cgroup(p: &str) -> Result<u64, std::io::Error> {
    debug!("get_cgroup_id_from_sub_cgroup: arg: {}", p);
    let get_single_dir_child = || -> Option<String> {
        let entries = match std::fs::read_dir(p) {
            Ok(entries) => entries,
            Err(_) => return None,
        };

        let mut ret = None;

        for entry_result in entries {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };

            if !file_type.is_dir() {
                continue;
            }

            let name = entry.file_name().to_string_lossy().to_string();

            if ret.is_none() {
                ret = Some(name);
            } else {
                // NB: there are more than one directories :( nothing reasonable we
                // can do at this point bail out
                return None;
            }
        }

        ret
    };

    let path = match get_single_dir_child() {
        Some(child) => format!("{}/{}", p, child),
        None => p.to_string(),
    };
    debug!("get_cgroup_id_from_sub_cgroup: res: {}", path);
    get_cgroup_id_from_path(&path)
}
