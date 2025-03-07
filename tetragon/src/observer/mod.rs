use crate::api::{get_events_response::Event, ProcessExec, ProcessExit};
use crate::process;
use crate::process::cache::cache_get;
use aya::{
    maps::{perf::AsyncPerfEventArray, MapData},
    util::online_cpus,
};
use bytes::BytesMut;
use prost_types::Timestamp;
use std::convert::TryInto;
use tetragon_common::common::MsgCommon;
use tetragon_common::msg_types::MsgOps;
use tetragon_common::process::{EventBytes, MsgCloneEvent, MsgExecveEvent, MsgExit};

use tracing::*;

pub async fn run_events(
    mut process_events_map: AsyncPerfEventArray<MapData>,
    tx: tokio::sync::broadcast::Sender<Event>,
    stop: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    let Ok(cpus) = online_cpus() else {
        return Err(anyhow::anyhow!("Failed get cpu info."));
    };
    let num_cpus = cpus.len();

    for cpu in cpus {
        let mut buf = process_events_map.open(cpu, None)?;
        let tx = tx.clone();

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const EventBytes;
                    let event = unsafe { ptr.read_unaligned() };
                    let msg_common: MsgCommon = match event.bytes.try_into() {
                        Ok(m) => m,
                        Err(e) => {
                            eprintln!("Error converting event to MsgCommon: {}", e);
                            return;
                        }
                    };
                    let ops: MsgOps = msg_common.op.into();

                    match ops {
                        MsgOps::MsgOpUndef => {
                            unimplemented!()
                        }
                        MsgOps::MsgOpExecve => {
                            let mut event: MsgExecveEvent = match event.bytes.try_into() {
                                Ok(e) => e,
                                Err(e) => {
                                    eprintln!("Error converting event to MsgExecveEvent: {}", e);
                                    return;
                                }
                            };
                            info!("MsgOpExecve: {event:?}");

                            match process::add_exec_event(&mut event).await {
                                Ok(internal) => {
                                    let event = Event::ProcessExec(ProcessExec {
                                        process: Some(internal.process),
                                        parent: None,
                                        ancestors: Vec::new(),
                                    });
                                    let _ = tx.send(event);
                                    info!("SENT EVENT");
                                }
                                Err(e) => {
                                    warn!("Failed add_exec_event: {}", e);
                                }
                            }
                        }
                        MsgOps::MsgOpExit => {
                            let event: MsgExit = match event.bytes.try_into() {
                                Ok(e) => e,
                                Err(e) => {
                                    eprintln!("Error converting event to MsgExit: {}", e);
                                    return;
                                }
                            };
                            info!("MsgExit: {event:?}");
                            let pid = event.current.pid;
                            let exec_id = process::get_exec_id_from_key(&event.current);
                            if let Some(internal) = cache_get(&exec_id).await {
                                let event = Event::ProcessExit(ProcessExit {
                                    process: Some(internal.process),
                                    parent: None,
                                    signal: "".to_string(),
                                    status: event.info.code,
                                    time: Some(Timestamp {
                                        seconds: event.current.ktime as i64,
                                        nanos: 0,
                                    }),
                                });
                                let _ = tx.send(event);
                            } else {
                                warn!("MsgExit Not Found process in the cache: pid: {}", pid)
                            };
                        }
                        MsgOps::MsgOpGenericKprobe => {
                            unimplemented!()
                        }
                        MsgOps::MsgOpGenericTracepoint => {
                            unimplemented!()
                        }
                        MsgOps::MsgOpGenericUprobe => {
                            unimplemented!()
                        }
                        MsgOps::MsgOpClone => {
                            let event: MsgCloneEvent = match event.bytes.try_into() {
                                Ok(e) => e,
                                Err(e) => {
                                    warn!("Error converting event to MsgCloneEvent: {}", e);
                                    return;
                                }
                            };
                            info!("MsgOpClone: {event:?}");
                            if let Err(e) = process::add_clone_event(&event).await {
                                info!("Failed add_clone_event: {}", e);
                                continue;
                            }
                        }
                        MsgOps::MsgOpData => {
                            unimplemented!()
                        }
                        MsgOps::MsgOpCgroup => {
                            unimplemented!()
                        }
                        MsgOps::MsgOpLoader => {
                            unimplemented!()
                        }
                    };
                }
            }
        });
    }

    stop.await;

    info!("bpf loader terminated");
    Ok(())
}
