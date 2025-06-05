use crate::cgidmap;
use crate::podhelpers::{extract_container_ids, parse_uuid};
use k8s_openapi::api::core::v1::Pod;
use kube::runtime::watcher;
use tokio::sync::broadcast;
use tracing::*;

pub async fn run(
    mut receiver: broadcast::Receiver<watcher::Event<Pod>>,
    stop: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    futures::pin_mut!(stop);
    loop {
        tokio::select! {
            Ok(event) = receiver.recv() => {
                match event {
                    watcher::Event::InitApply(pod) => update_pod_handler(&pod),
                    watcher::Event::Apply(pod) => update_pod_handler(&pod),
                    watcher::Event::Delete(pod) => delete_pod_handler(&pod),
                    _ => continue,
                }
            }
            _ = &mut stop => {
                info!("Stopping PodInformer");
                break;
            }
        }
    }

    Ok(())
}

fn update_pod_handler(pod: &Pod) {
    let Some(pod_id) = parse_uuid(pod) else {
        warn!("Failed to parse pod UUID");
        return;
    };

    if let Some((mut running, _)) = extract_container_ids(pod) {
        cgidmap::update(pod_id, &mut running);
    } else {
        debug!("The pod {} has no running containers", pod_id);
    }
}

fn delete_pod_handler(pod: &Pod) {
    let Some(pod_id) = parse_uuid(pod) else {
        warn!("Failed to parse pod UUID");
        return;
    };
    // When a pod is deleted, we remove all entries for that pod
    cgidmap::update(pod_id, &mut std::collections::HashSet::new());
}
