use crate::util::NamespaceType;
use procfs::process::{Process, Task};
use procfs::WithCurrentSystemInfo;
use std::ffi::OsString;
use tetragon_common::bpf_cred::MsgCapabilities;
use tetragon_common::process::{Binary, ExecveMapValue, MsgExecveKey, MsgNs, BINARY_PATH_MAX_LEN};
use tracing::*;

pub struct ProcessWrapper(Process);

impl TryFrom<ProcessWrapper> for ExecveMapValue {
    type Error = anyhow::Error;
    fn try_from(p: ProcessWrapper) -> Result<Self, Self::Error> {
        let p = p.0;
        let namespaces = p.namespaces();
        let binary = if let Ok(path) = p.exe() {
            let path_str = path.to_string_lossy();
            let bytes = path_str.as_bytes();
            let len = std::cmp::min(bytes.len(), 256);
            let mut chars = [0u8; 256];
            chars[..len].copy_from_slice(&bytes[..len]);

            Binary {
                path_length: chars.len() as i64,
                path: chars,
            }
        } else {
            Binary {
                path_length: 0,
                path: [0; BINARY_PATH_MAX_LEN],
            }
        };

        Ok(ExecveMapValue {
            key: MsgExecveKey {
                pid: p.pid as u32,
                pad: [0; 4],
                ktime: p.stat().map_or(0, |stat| {
                    stat.starttime().get().unwrap_or_default().timestamp() as u64
                }),
            },
            pkey: MsgExecveKey {
                pid: p.stat().map_or(0, |stat| stat.ppid as u32),
                pad: [0; 4],
                ktime: Process::new(p.pid)?.stat().map_or(0, |stat| {
                    stat.starttime().get().unwrap_or_default().timestamp() as u64
                }),
            },
            flags: 0,
            nspid: p
                .status()
                .ok()
                .and_then(|status| status.nspgid.clone())
                .and_then(|nspgid| nspgid.last().copied())
                .map(|pid| pid as u32)
                .unwrap_or(0),
            ns: MsgNs {
                uts_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Uts.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                ipc_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Ipc.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                mnt_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Mnt.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                pid_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Pid.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                pid_for_children_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::PidForChildren.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                net_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Net.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                time_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Time.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                time_for_children_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::TimeForChildren.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                cgroup_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Cgroup.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                user_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::User.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
            },
            caps: MsgCapabilities {
                permitted: p.status().ok().as_ref().map_or(0, |status| status.capprm),
                effective: p.status().ok().as_ref().map_or(0, |status| status.capeff),
                inheritable: p.status().ok().as_ref().map_or(0, |status| status.capinh),
            },
            bin: binary,
        })
    }
}

pub type Thread = Task;
pub struct ThreadWrapper(Thread);

impl TryFrom<ThreadWrapper> for ExecveMapValue {
    type Error = anyhow::Error;
    fn try_from(t: ThreadWrapper) -> Result<Self, Self::Error> {
        let t = t.0;
        let p = Process::new(t.pid)?;
        let namespaces = p.namespaces();
        let binary = if let Ok(path) = p.exe() {
            let path_str = path.to_string_lossy();
            let bytes = path_str.as_bytes();
            let len = std::cmp::min(bytes.len(), 256);
            let mut chars = [0u8; 256];
            chars[..len].copy_from_slice(&bytes[..len]);

            Binary {
                path_length: chars.len() as i64,
                path: chars,
            }
        } else {
            Binary {
                path_length: 0,
                path: [0; BINARY_PATH_MAX_LEN],
            }
        };

        Ok(ExecveMapValue {
            key: MsgExecveKey {
                pid: t.tid as u32,
                pad: [0; 4],
                ktime: t.stat().map_or(0, |stat| {
                    stat.starttime().get().unwrap_or_default().timestamp() as u64
                }),
            },
            pkey: MsgExecveKey {
                pid: t.pid as u32,
                pad: [0; 4],
                ktime: p.stat().map_or(0, |stat| {
                    stat.starttime().get().unwrap_or_default().timestamp() as u64
                }),
            },
            flags: 0,
            nspid: t
                .status()
                .ok()
                .and_then(|status| status.nspgid.clone())
                .and_then(|nspgid| nspgid.last().copied())
                .map(|pid| pid as u32)
                .unwrap_or(0),
            ns: MsgNs {
                uts_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Uts.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                ipc_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Ipc.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                mnt_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Mnt.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                pid_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Pid.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                pid_for_children_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::PidForChildren.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                net_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Net.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                time_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Time.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                time_for_children_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::TimeForChildren.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                cgroup_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::Cgroup.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
                user_inum: namespaces.as_ref().map_or(0, |namespace| {
                    namespace
                        .0
                        .get(&OsString::from(NamespaceType::User.as_str()))
                        .map_or(0, |ns| ns.identifier as u32)
                }),
            },
            caps: MsgCapabilities {
                permitted: t.status().ok().as_ref().map_or(0, |status| status.capprm),
                effective: t.status().ok().as_ref().map_or(0, |status| status.capeff),
                inheritable: t.status().ok().as_ref().map_or(0, |status| status.capinh),
            },
            bin: binary,
        })
    }
}

pub fn collect_threads_with_processes() -> anyhow::Result<(Vec<Thread>, Vec<Process>)> {
    collect_processes_threads_with_filter(|_, _| true)
}

pub fn collect_non_main_threads_with_processes() -> anyhow::Result<(Vec<Thread>, Vec<Process>)> {
    collect_processes_threads_with_filter(|thread, _| thread.pid != thread.tid)
}

fn collect_processes_threads_with_filter<F>(
    thread_filter: F,
) -> anyhow::Result<(Vec<Thread>, Vec<Process>)>
where
    F: Fn(&Thread, &Process) -> bool,
{
    let mut res_procs = Vec::new();
    let mut res_threads = Vec::new();

    for proc in procfs::process::all_processes()? {
        let proc = proc?;

        for thread in proc.tasks()? {
            let thread = thread?;
            if thread_filter(&thread, &proc) {
                res_threads.push(thread);
            }
        }
        res_procs.push(proc);
    }

    Ok((res_threads, res_procs))
}

fn collect_processes() -> anyhow::Result<Vec<Process>> {
    let mut res_procs = Vec::new();

    for proc in procfs::process::all_processes()? {
        let proc = proc?;
        res_procs.push(proc);
    }

    Ok(res_procs)
}

pub fn collect_execve_map_values() -> anyhow::Result<Vec<ExecveMapValue>> {
    let procs = collect_processes()?;
    info!("Collected. procs: {}", procs.len());

    let execve_maps: Vec<ExecveMapValue> = procs
        .into_iter()
        .filter_map(|process| {
            ProcessWrapper(process)
                .try_into()
                .inspect_err(|e| eprintln!("Error converting process: {}", e))
                .ok()
        })
        .collect();

    info!("Converted. execve_maps: {}", execve_maps.len());

    Ok(execve_maps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_collect_processes_threads_exclude_main() -> anyhow::Result<()> {
        let me = Process::myself().unwrap();
        let pid = me.pid;

        let mut handles = vec![];
        for _ in 0..3 {
            let handle = thread::spawn(|| {
                thread::sleep(Duration::from_secs(5));
            });

            handles.push(handle);
        }

        let (threads, procs) = collect_non_main_threads_with_processes()?;
        println!("threads: {}, procs: {}", threads.len(), procs.len());

        let res_proc = procs.iter().find(|p| p.pid == pid);
        assert!(res_proc.is_some());
        println!("proc: {:?}", res_proc);

        let res_threads: Vec<&Thread> = threads.iter().filter(|t| t.pid == pid).collect();
        assert!(!res_threads.is_empty());
        println!("thread: {:?}", res_threads);

        for handle in handles {
            handle.join().unwrap();
        }

        Ok(())
    }

    #[test]
    fn test_collect_threads_with_processes() -> anyhow::Result<()> {
        let me = Process::myself().unwrap();
        let pid = me.pid;

        let (threads, procs) = collect_threads_with_processes()?;
        println!("threads: {}, procs: {}", threads.len(), procs.len());

        let res_proc = procs.iter().find(|p| p.pid == pid);
        assert!(res_proc.is_some());
        println!("proc: {:?}", res_proc);

        let res_threads: Vec<&Thread> = threads.iter().filter(|t| t.pid == pid).collect();
        assert!(!res_threads.is_empty());
        println!("thread: {:?}", res_threads);

        Ok(())
    }

    #[test]
    fn test_process_try_from() -> anyhow::Result<()> {
        let me = Process::myself().unwrap();
        let pid = me.pid;
        println!("process: {:#?}", me);

        let execve_map_value: ExecveMapValue = ProcessWrapper(me).try_into()?;
        assert_eq!(execve_map_value.key.pid, pid as u32);

        println!("execve_map_value: {:?}", execve_map_value);

        Ok(())
    }

    #[test]
    fn test_thread_try_from() -> anyhow::Result<()> {
        let mut handles = vec![];

        for _ in 0..3 {
            let handle = thread::spawn(|| {
                thread::sleep(Duration::from_secs(5));
            });

            handles.push(handle);
        }

        let me = Process::myself().unwrap();
        let pid = me.pid;

        let threads = me.tasks()?;
        for thread in threads {
            let thread = thread.ok().unwrap();
            let tid = thread.tid;
            let execve_map_value: ExecveMapValue = ThreadWrapper(thread).try_into()?;
            assert_eq!(execve_map_value.key.pid, tid as u32);
            assert_eq!(execve_map_value.pkey.pid, pid as u32);
            println!("execve_map_value: {:?}", execve_map_value);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        Ok(())
    }
}
