use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher;
use std::collections::HashSet;
use tracing::*;

// This ContainerID is the Kubernetes containerId without the runtime prefix.
// Example: "containerd://xyz789" becomes "xyz789"
type ContainerID = String;

pub fn extract_container_ids_from_event(
    event: &watcher::Event<Pod>,
) -> Option<(HashSet<ContainerID>, HashSet<ContainerID>)> {
    let p = match event {
        watcher::Event::Apply(pod) => pod.clone(),
        watcher::Event::Delete(pod) => pod.clone(),
        watcher::Event::Init => return None,
        watcher::Event::InitApply(pod) => pod.clone(),
        watcher::Event::InitDone => return None,
    };
    extract_container_ids(&p)
}

pub fn extract_container_ids(pod: &Pod) -> Option<(HashSet<ContainerID>, HashSet<ContainerID>)> {
    let Some(status) = &pod.status else {
        return None;
    };

    let container_status_lists = [
        &status.container_statuses,
        &status.ephemeral_container_statuses,
        &status.init_container_statuses,
    ];

    let running_container_id: HashSet<ContainerID> = container_status_lists
        .iter()
        .filter_map(|&statuses| statuses.as_ref())
        .flat_map(|statuses| statuses.iter())
        .filter(|cs| {
            cs.state
                .as_ref()
                .is_some_and(|state| state.running.is_some())
        })
        .filter_map(|cs| cs.container_id.as_deref().map(strip_runtime_prefix))
        .collect();

    let terminated_container_id: HashSet<ContainerID> = container_status_lists
        .iter()
        .filter_map(|&statuses| statuses.as_ref())
        .flat_map(|statuses| statuses.iter())
        .filter(|cs| {
            cs.state
                .as_ref()
                .is_some_and(|state| state.terminated.is_some())
        })
        .filter_map(|cs| cs.container_id.as_deref().map(strip_runtime_prefix))
        .collect();

    trace!(
        "Extracted running containers: {:?}, terminated containers: {:?}",
        running_container_id,
        terminated_container_id
    );

    Some((running_container_id, terminated_container_id))
}

pub fn parse_uuid(pod: &Pod) -> Option<uuid::Uuid> {
    pod.metadata
        .uid
        .as_ref()
        .and_then(|uid| uuid::Uuid::parse_str(uid).ok())
}

fn strip_runtime_prefix(container_id: &str) -> String {
    if let Some(idx) = container_id.find("://") {
        return container_id[idx + 3..].to_string();
    }
    container_id.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_runtime_prefix_containerd() {
        let input = "containerd://xyz789";
        let expected = "xyz789";
        assert_eq!(strip_runtime_prefix(input), expected);
    }

    #[test]
    fn test_strip_runtime_prefix_crio() {
        let input = "cri-o://9e56ce";
        let expected = "9e56ce";
        assert_eq!(strip_runtime_prefix(input), expected);
    }
}
