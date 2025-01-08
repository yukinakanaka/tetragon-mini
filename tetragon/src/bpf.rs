use crate::api::{get_events_response::Event, ProcessExec, ProcessExit};
use crate::process;
use crate::process::cache::cache_get;
use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, HashMap, MapData, ProgramArray},
    programs::{BtfTracePoint, KProbe},
    util::online_cpus,
    Btf, Ebpf,
};
use prost_types::Timestamp;
use std::sync::Arc;
use tokio::sync::Mutex;

use aya_log::EbpfLogger;
use bytes::BytesMut;
use std::convert::{TryFrom, TryInto};
use tetragon_common::common::MsgCommon;
use tetragon_common::msg_types::MsgOps;
use tetragon_common::process::{
    EventBytes, ExecveMapValue, MsgCloneEvent, MsgExecveEvent, MsgExit,
};
use tetragon_common::vmlinux::*;

use tracing::*;

pub const PROCESS_EVENTS_MAP: &str = "TCPMON_MAP";
pub const EXECVE_MAP: &str = "EXECVE_MAP";

pub struct EbpfManager {
    pub bpf: Arc<Mutex<Ebpf>>,
    pub execve_calls: ProgramArray<MapData>,
    pub process_events_map: AsyncPerfEventArray<MapData>,
}

impl EbpfManager {
    pub fn new() -> anyhow::Result<Self> {
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };

        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/debug/tetragon"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/tetragon"
        ))?;
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            warn!("failed to initialize eBPF logger: {}", e);
        }

        let btf = Btf::from_sys_fs()?;
        let mut execve_calls: ProgramArray<aya::maps::MapData> =
            ProgramArray::try_from(bpf.take_map("EXECVE_CALLS").unwrap())?;

        attach_programs(&mut bpf, &btf, &mut execve_calls)?;
        let process_events_map =
            AsyncPerfEventArray::try_from(bpf.take_map(PROCESS_EVENTS_MAP).unwrap())?;
        let bpf = Arc::new(Mutex::new(bpf));

        Ok(Self {
            bpf,
            execve_calls,
            process_events_map,
        })
    }

    pub async fn write_execve_map(&mut self, values: Vec<ExecveMapValue>) -> anyhow::Result<()> {
        let bpf = Arc::clone(&self.bpf);
        let mut bpf = bpf.lock().await;
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

    pub async fn observe_event_map(
        &mut self,
        tx: tokio::sync::broadcast::Sender<Event>,
        stop: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<()> {
        let Ok(cpus) = online_cpus() else {
            return Err(anyhow::anyhow!("Failed get cpu info."));
        };
        let num_cpus = cpus.len();

        for cpu in cpus {
            let mut buf = self.process_events_map.open(cpu, None)?;
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
                                        eprintln!(
                                            "Error converting event to MsgExecveEvent: {}",
                                            e
                                        );
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
}

pub fn attach_programs(
    bpf: &mut Ebpf,
    btf: &Btf,
    execve_calls: &mut ProgramArray<MapData>,
) -> anyhow::Result<()> {
    let program: &mut KProbe = bpf.program_mut("exit_acct_process").unwrap().try_into()?;
    program.load()?;
    program.attach("acct_process", 0)?;

    let program: &mut KProbe = bpf.program_mut("wake_up_new_task").unwrap().try_into()?;
    program.load()?;
    program.attach("wake_up_new_task", 0)?;

    let flags = 0;

    let execve_rate: &mut BtfTracePoint = bpf.program_mut("execve_rate").unwrap().try_into()?;
    execve_rate.load("sched_process_exec", btf)?;
    let execve_rate_fd = execve_rate.fd().unwrap();
    info!("execve_rate_fd: {:?}", execve_rate_fd);
    if let Err(e) = execve_calls.set(0, execve_rate_fd, flags) {
        eprintln!("Failed to set execve_rate in ProgramArray: {:?}", e);
    } else {
        println!("Successfully set execve_rate in ProgramArray.");
    }

    let execve_send: &mut BtfTracePoint = bpf.program_mut("execve_send").unwrap().try_into()?;
    execve_send.load("sched_process_exec", btf)?;
    let execve_send_fd = execve_send.fd().unwrap();
    info!("execve_send_fd: {:?}", execve_send_fd);
    if let Err(e) = execve_calls.set(1, execve_send_fd, flags) {
        eprintln!("Failed to set execve_send in ProgramArray: {:?}", e);
    } else {
        println!("Successfully set execve_send in ProgramArray.");
    }

    let program: &mut BtfTracePoint = bpf.program_mut("sched_process_exec").unwrap().try_into()?;
    program.load("sched_process_exec", btf)?;
    program.attach()?;

    Ok(())
}

pub async fn read_execve_map(bpf: &Ebpf, pid: &u32) -> anyhow::Result<()> {
    let execve_map: HashMap<_, __u32, ExecveMapValue> =
        HashMap::try_from(bpf.map(EXECVE_MAP).unwrap())
            .context("no execve_map")
            .unwrap();
    let _ = execve_map.get(pid, 0);

    info!("Wrote execve_map_value into map.");
    Ok(())
}
