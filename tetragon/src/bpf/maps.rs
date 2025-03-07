use anyhow::Ok;
use aya::maps::perf::AsyncPerfEventArray;
use aya::{maps::HashMap, Ebpf};
use std::convert::TryFrom;
use tetragon_common::process::ExecveMapValue;
use tetragon_common::vmlinux::*;
use tracing::*;

const EXECVE_MAP: &str = "EXECVE_MAP";
pub(crate) const PROCESS_EVENTS_MAP: &str = "TCPMON_MAP";
pub(crate) const EXECVE_CALLS: &str = "EXECVE_CALLS";

pub async fn write_execve_map(bpf: &mut Ebpf, values: Vec<ExecveMapValue>) -> anyhow::Result<()> {
    let mut execve_map: HashMap<_, __u32, ExecveMapValue> =
        HashMap::try_from(bpf.map_mut(EXECVE_MAP).unwrap())?;
    values.into_iter().for_each(|value| {
        let _ = execve_map
            .insert(value.key.pid, value, 0)
            .map_err(|e| warn!("failed write value to map: {:?}, {}", value, e));
    });

    info!("Wrote execve_map_value into map.");
    Ok(())
}

pub fn get_process_events_map(
    bpf: &mut Ebpf,
) -> anyhow::Result<AsyncPerfEventArray<aya::maps::MapData>> {
    Ok(AsyncPerfEventArray::try_from(
        bpf.take_map(PROCESS_EVENTS_MAP).unwrap(),
    )?)
}
