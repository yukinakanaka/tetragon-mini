use crate::cgidmap::add;
use crate::rthooks::{
    args::CreateContainerArg, register_callbacks_at_init, Callbacks, RtHookError,
};
use tracing::*;
use uuid::Uuid;

pub fn register_callback() {
    register_callbacks_at_init(Callbacks {
        create_container: Box::new(create_container_hook),
    });
}

fn create_container_hook(arg: &mut CreateContainerArg) -> Result<(), RtHookError> {
    info!("cgidmap::create_container_hook called");
    // TODO: support option
    // if !option::Config::enable_cg_idmap() {
    //     return Ok(());
    // }

    let pod_id_str = arg.pod_id();

    let pod_id = match Uuid::parse_str(&pod_id_str) {
        Ok(id) => id,
        Err(e) => {
            warn!("failed to parse uuid, aborting hook: {}", e);
            return Err(RtHookError::CreateContainerError(format!(
                "failed to parse uuid: {}",
                e
            )));
        }
    };

    let container_id = arg.container_id();

    let cg_id = 9999;

    // TODO: Test on k8s
    // let cg_id = match arg.cgroup_id() {
    //     Ok(id) => id,
    //     Err(e) => {
    //         warn!("failed to retrieve cgroup id, aborting hook: {}", e);
    //         return Err(RtHookError::CreateContainerError(format!(
    //             "failed to retrieve cgroup id: {}",
    //             e
    //         )));
    //     }
    // };

    // TODO: cgtracker
    // match arg.host_cgroup_path() {
    //     Ok(cg_path) => {
    //         if let Err(err) = cgtracker::add_cgroup_tracker_path(&cg_path) {
    //             warn!("failed to add path to cgroup tracker");
    //         }
    //     }
    //     Err(err) => {
    //         warn!("could not retrieve host cgroup path, will not add path to cgroup tracker");
    //     }
    // }

    add(pod_id, container_id, cg_id);
    Ok(())
}
