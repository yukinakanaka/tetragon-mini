pub mod maps;

use aya::{
    include_bytes_aligned,
    maps::{MapData, ProgramArray},
    programs::{BtfTracePoint, KProbe},
    Btf, Ebpf,
};
use aya_log::EbpfLogger;
use std::convert::{TryFrom, TryInto};
use tracing::*;

type ExecveCallsMap = ProgramArray<MapData>;

pub fn init_ebpf() -> anyhow::Result<(Ebpf, ExecveCallsMap)> {
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
        "../../../target/bpfel-unknown-none/debug/tetragon"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../../target/bpfel-unknown-none/release/tetragon"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let btf = Btf::from_sys_fs()?;

    let execve_calls_map_guard = attach_programs(&mut bpf, &btf)?;

    Ok((bpf, execve_calls_map_guard))
}

fn attach_programs(bpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<ProgramArray<aya::maps::MapData>> {
    let program: &mut KProbe = bpf.program_mut("exit_acct_process").unwrap().try_into()?;
    program.load()?;
    program.attach("acct_process", 0)?;

    let program: &mut KProbe = bpf.program_mut("wake_up_new_task").unwrap().try_into()?;
    program.load()?;
    program.attach("wake_up_new_task", 0)?;

    let flags = 0;

    let mut execve_calls_map: ProgramArray<aya::maps::MapData> =
        ProgramArray::try_from(bpf.take_map(maps::EXECVE_CALLS).unwrap())?;

    let execve_rate: &mut BtfTracePoint = bpf.program_mut("execve_rate").unwrap().try_into()?;
    execve_rate.load("sched_process_exec", btf)?;
    let execve_rate_fd = execve_rate.fd().unwrap();
    info!("execve_rate_fd: {:?}", execve_rate_fd);
    if let Err(e) = execve_calls_map.set(0, execve_rate_fd, flags) {
        eprintln!("Failed to set execve_rate in ProgramArray: {:?}", e);
    } else {
        println!("Successfully set execve_rate in ProgramArray.");
    }

    let execve_send: &mut BtfTracePoint = bpf.program_mut("execve_send").unwrap().try_into()?;
    execve_send.load("sched_process_exec", btf)?;
    let execve_send_fd = execve_send.fd().unwrap();
    info!("execve_send_fd: {:?}", execve_send_fd);
    if let Err(e) = execve_calls_map.set(1, execve_send_fd, flags) {
        eprintln!("Failed to set execve_send in ProgramArray: {:?}", e);
    } else {
        println!("Successfully set execve_send in ProgramArray.");
    }

    let program: &mut BtfTracePoint = bpf.program_mut("sched_process_exec").unwrap().try_into()?;
    program.load("sched_process_exec", btf)?;
    program.attach()?;

    Ok(execve_calls_map)
}
