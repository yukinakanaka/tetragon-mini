use crate::api::Pod;
pub fn get_pod_info(_container_id: &str, _binary: &str, _args: &str, _nspid: u32) -> Pod {
    // TODO
    Pod {
        ..Default::default()
    }
}
