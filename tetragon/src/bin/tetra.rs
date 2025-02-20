use tetragon::api::fine_guidance_sensors_client::FineGuidanceSensorsClient;
use tetragon::api::{
    get_events_response::Event, GetEventsRequest, GetHealthStatusRequest, HealthStatusType,
};
use tetragon::util::translate_uid;

use tonic::Request;

use tracing::*;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let mut sensor_client = FineGuidanceSensorsClient::connect("http://[::1]:10001").await?;
    let response = sensor_client
        .get_health(Request::new(GetHealthStatusRequest {
            event_set: vec![HealthStatusType::Status.into()],
        }))
        .await?;
    debug!("RESPONSE = {:?}", response);

    let mut stream = sensor_client
        .get_events(Request::new(GetEventsRequest::default()))
        .await?
        .into_inner();

    while let Some(response) = stream.message().await? {
        let event = response.event.unwrap();
        match &event {
            Event::ProcessExec(process_exec) => {
                debug!("process_exec: {:?}", process_exec);
                println!(
                    "🚀 process\t{}: {}: {} {}",
                    process_exec.process.as_ref().unwrap().pid.unwrap(),
                    translate_uid(process_exec.process.as_ref().unwrap().uid.unwrap()),
                    process_exec.process.as_ref().unwrap().binary,
                    process_exec.process.as_ref().unwrap().arguments,
                );
            }
            Event::ProcessExit(process_exit) => {
                debug!("process_exit: {:?}", process_exit);
                println!(
                    "💥 exit\t\t{}: {}: {} {}",
                    process_exit.process.as_ref().unwrap().pid.unwrap(),
                    translate_uid(process_exit.process.as_ref().unwrap().uid.unwrap()),
                    process_exit.process.as_ref().unwrap().binary,
                    process_exit.process.as_ref().unwrap().arguments,
                );
            }
            _ => {
                unimplemented!()
            }
        }
    }

    Ok(())
}
