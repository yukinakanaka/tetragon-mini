use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher;
use std::collections::HashSet;
use tracing::*;

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
        .filter_map(|cs| cs.container_id.clone())
        .collect();

    let terminated_container_id: HashSet<ContainerID> = container_status_lists
        .iter()
        .filter_map(|&statuses| statuses.as_ref())
        .flat_map(|statuses| statuses.iter())
        .filter(|cs| {
            cs.state
                .as_ref()
                .is_some_and(|state| state.running.is_some())
        })
        .filter_map(|cs| cs.container_id.clone())
        .collect();

    info!(
        "Extracted running containers: {:?}, terminated containers: {:?}",
        running_container_id, terminated_container_id
    );

    Some((running_container_id, terminated_container_id))
}
