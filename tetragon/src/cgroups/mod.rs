pub mod linux;

pub const CGROUP_UNSET_VALUE: u64 = 0;

/// Max cgroup subsystems count that is used from BPF side
/// to define a max index for the default controllers on tasks.
/// For further documentation check BPF part.
pub const CGROUP_SUBSYS_COUNT: usize = 15;

/// The default hierarchy for cgroupv2
pub const CGROUP_DEFAULT_HIERARCHY: u64 = 0;

/// Cgroup Mode:
/// https://systemd.io/CGROUP_DELEGATION/
/// But this should work also for non-systemd environments: where
/// only legacy or unified are available by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum CgroupModeCode {
    Undefined = 0,
    Legacy = 1,
    Hybrid = 2,
    Unified = 3,
}

impl Default for CgroupModeCode {
    fn default() -> Self {
        Self::Undefined
    }
}

/// Deployment modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum DeploymentCode {
    Unknown = 0,
    Kubernetes = 1,
    Container = 2,
    SystemdService = 10,
    SystemdUserSession = 11,
}

impl Default for DeploymentCode {
    fn default() -> Self {
        Self::Unknown
    }
}

impl std::fmt::Display for DeploymentCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DeploymentCode::Unknown => "unknown",
            DeploymentCode::Kubernetes => "Kubernetes",
            DeploymentCode::Container => "Container",
            DeploymentCode::SystemdService => "systemd service",
            DeploymentCode::SystemdUserSession => "systemd user session",
        };
        write!(f, "{}", s)
    }
}

#[allow(dead_code)]
pub struct DeploymentEnv {
    id: DeploymentCode,
    str: Option<String>,
    ends_with: Option<String>,
}

/// Returns a Rust string from the passed C language format byte array.
pub fn cgroup_name_from_c_str(cstr: &[u8]) -> String {
    match cstr.iter().position(|&b| b == 0) {
        Some(i) => String::from_utf8_lossy(&cstr[..i]).to_string(),
        None => String::from_utf8_lossy(cstr).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_name_from_c_str() {
        let c_str = b"test\0more";
        assert_eq!(cgroup_name_from_c_str(c_str), "test");

        let no_null = b"test";
        assert_eq!(cgroup_name_from_c_str(no_null), "test");
    }

    #[test]
    fn test_deployment_code_display() {
        assert_eq!(DeploymentCode::Unknown.to_string(), "unknown");
        assert_eq!(DeploymentCode::Kubernetes.to_string(), "Kubernetes");
        assert_eq!(DeploymentCode::Container.to_string(), "Container");
        assert_eq!(
            DeploymentCode::SystemdService.to_string(),
            "systemd service"
        );
        assert_eq!(
            DeploymentCode::SystemdUserSession.to_string(),
            "systemd user session"
        );
    }
}
