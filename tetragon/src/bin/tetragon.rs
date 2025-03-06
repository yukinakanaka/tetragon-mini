use futures::future::{FutureExt, TryFutureExt};
use tetragon::api::get_events_response::Event;
use tetragon::bpf::{
    init_ebpf,
    maps::{get_process_events_map, write_execve_map},
};
use tetragon::metrics::*;
use tetragon::observer::run_events;
use tetragon::process::{print_struct_size, procfs::initial_execve_map_valuses};
use tetragon::server::FineGuidanceSensorsService;
use tetragon::util::{shutdown_signals, stop_signal};
use tracing::*;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

async fn app_main() -> anyhow::Result<()> {
    let meter_provider = init_metrics();
    let trace_provider = init_traces();

    let (stop_tx, _stop_rx) = tokio::sync::broadcast::channel::<()>(1);
    let (event_tx, event_rx) = tokio::sync::broadcast::channel::<Event>(1);

    let (mut bpf, _execve_calls_map_guard) = init_ebpf()?;

    let execve_map_values = initial_execve_map_valuses()?;
    write_execve_map(&mut bpf, execve_map_values).await?;

    let ebpf_thread = tokio::spawn({
        let stop = stop_signal(stop_tx.subscribe());
        async move { run_events(get_process_events_map(&mut bpf)?, event_tx, stop).await }
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

    let _ = meter_provider.shutdown();
    let _ = trace_provider.shutdown();

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
