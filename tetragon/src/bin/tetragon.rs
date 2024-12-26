use core::mem;
use futures::future::{FutureExt, TryFutureExt};
use tetragon_common::process::{ExecveMapValue, MsgExecveKey};
use tracing::*;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

use tetragon::api::get_events_response::Event;
use tetragon::bpf::EbpfManager;
use tetragon::process::procfs::collect_execve_map_values;
use tetragon::server::FineGuidanceSensorsService;
use tetragon::util::{shutdown_signals, stop_signal};
use tetragon_common::process::{MsgCloneEvent, MsgExecveEvent, MsgExit};

async fn app_main() -> anyhow::Result<()> {
    let (stop_tx, _stop_rx) = tokio::sync::broadcast::channel::<()>(1);
    let (event_tx, event_rx) = tokio::sync::broadcast::channel::<Event>(1);

    let mut bpf = EbpfManager::new()?;

    let mut execve_map_values = collect_execve_map_values()?;

    let zero_execve_map_value = ExecveMapValue {
        pkey: MsgExecveKey {
            pid: 0,
            ktime: 1,
            ..Default::default()
        },
        key: MsgExecveKey {
            pid: 0,
            ktime: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    execve_map_values.push(zero_execve_map_value);
    bpf.write_execve_map(execve_map_values).await?;

    let ebpf_thread = tokio::spawn({
        let stop = stop_signal(stop_tx.subscribe());
        async move { bpf.observe_event_map(event_tx, stop).await }
    });

    let server = FineGuidanceSensorsService { rx: event_rx };
    let server_thread = tokio::spawn({
        let stop = stop_signal(stop_tx.subscribe());
        async move { server.run(stop).await }
    });

    let tasks = {
        fn flatten<V, E>(r: Result<Result<V, E>, E>) -> Result<V, E> {
            match r {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(e),
            }
        }

        futures::future::select_all([
            ebpf_thread
                .map_err(anyhow::Error::new)
                .map(flatten)
                .map(|r| ("observer", r))
                .boxed(),
            server_thread
                .map_err(anyhow::Error::new)
                .map(flatten)
                .map(|r| ("demo_server_thread", r))
                .boxed(),
        ])
    };

    futures::pin_mut!(tasks);

    let results = tokio::select! {
        () = shutdown_signals()? => {
            info!("Shutdown signal received");

            if stop_tx.send(()).is_err() {
                error!("Failed to send stop signal");
            }
            let (task_result, _, tasks) = tasks.await;

            let mut results = futures::future::join_all(tasks).await;
            results.push(task_result);
            results
        }
        (task_result, _, tasks) = &mut tasks => {
            error!("{} returned early: {:?}", task_result.0, task_result.1);

            if stop_tx.send(()).is_err() {
                error!("Failed to send stop signal");
            }

            let mut results = futures::future::join_all(tasks).await;
            results.push(task_result);
            results
        }
    };

    let mut failed = false;
    for result in results {
        if let (name, Err(e)) = result {
            error!("{} failed: {:#}", name, e);
            failed = true;
        }
    }

    if failed {
        return Err(anyhow::anyhow!("Tetragon terminated with error"));
    }

    info!("Tetragon terminated");
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    print_struct_size();
    app_main().await.map_err(|e| {
        error!("{e:#}");
        e
    })
}

fn print_struct_size() {
    info!("Struct size:");
    info!("MsgCloneEvent size: {}", mem::size_of::<MsgCloneEvent>());
    info!("MsgExecveEvent size: {}", mem::size_of::<MsgExecveEvent>());
    info!("MsgExit size: {}", mem::size_of::<MsgExit>());
}
