use anyhow::Context as _;
use std::future::Future;
use tracing::*;

pub fn shutdown_signals() -> anyhow::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut quit = signal(SignalKind::quit()).context("failed to create quit signal")?;
    let mut terminate =
        signal(SignalKind::terminate()).context("failed to create terminate signal")?;
    let mut interrupt =
        signal(SignalKind::interrupt()).context("failed to create interrupt signal")?;
    let signals = async move {
        tokio::select! {
            _ = quit.recv() => {}
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    };

    Ok(signals)
}

pub async fn stop_signal(mut rx: tokio::sync::broadcast::Receiver<()>) {
    if let Err(e) = rx.recv().await {
        error!("stop receiver returned error: {:#}", e);
    }
}

pub enum NamespaceType {
    Uts,
    Ipc,
    Mnt,
    Pid,
    PidForChildren,
    Net,
    Time,
    TimeForChildren,
    Cgroup,
    User,
}

impl NamespaceType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Uts => "uts",
            Self::Ipc => "ipc",
            Self::Mnt => "mnt",
            Self::Pid => "pid",
            Self::PidForChildren => "pid_for_children",
            Self::Net => "net",
            Self::Time => "time",
            Self::TimeForChildren => "time_for_children",
            Self::Cgroup => "cgroup",
            Self::User => "user",
        }
    }
}

pub fn translate_uid(uid: u32) -> String {
    match passwd::Passwd::from_uid(uid) {
        Some(user) => user.name,
        None => uid.to_string(),
    }
}
