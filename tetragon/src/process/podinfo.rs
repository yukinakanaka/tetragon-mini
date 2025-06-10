use crate::api::{Container, Image, Pod};
use crate::cgidmap;
use crate::watcher::PodStore;
use regex::Regex;
use std::collections::HashMap;
use tracing::*;
pub fn get_pod_info(
    cgrpid: u64,
    _binary: &str,
    _args: &str,
    _nspid: u32,
    store: PodStore,
) -> Option<Pod> {
    debug!(
        "get_pod_info: Retrieving pod info for cgroup id: {}",
        cgrpid
    );

    let Some(container_id) = cgidmap::get(cgrpid) else {
        debug!(
            "get_pod_info: No container ID found for cgroup ID: {}",
            cgrpid
        );
        return None;
    };

    let Some(pod) = store.get_with_retry(&container_id, 20) else {
        debug!(
            "get_pod_info: No pod found for container ID: {}",
            container_id
        );
        return None;
    };

    // TODO: Populate fieds like workload, workload_kind, and pod_labels
    Some(Pod {
        namespace: pod.metadata.namespace.clone().unwrap_or_default(),
        workload: "".to_string(),
        workload_kind: "".to_string(),
        name: pod.metadata.name.clone().unwrap_or_default(),
        pod_labels: HashMap::new(),
        container: Some(Container {
            id: "".to_string(),
            pid: Some(0),
            name: "".to_string(),
            image: Some(Image {
                id: "".to_string(),
                name: "".to_string(),
            }),
            start_time: None,
            maybe_exec_probe: false,
        }),
    })
}

fn extract_hash(input: &str) -> Option<String> {
    // TODO: Support containerd
    let re = Regex::new(r"^crio-conmon-([0-9a-fA-F]{64})\.scope$").unwrap();

    re.captures(input)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_hash() {
        let input =
            "crio-conmon-dc77e3758c764db61efd00260a92d34cc221e88ff46920b4bb616c4f17f734e1.scope";
        let expected = "dc77e3758c764db61efd00260a92d34cc221e88ff46920b4bb616c4f17f734e1";

        assert_eq!(extract_hash(input), Some(expected.to_string()));
    }
}
