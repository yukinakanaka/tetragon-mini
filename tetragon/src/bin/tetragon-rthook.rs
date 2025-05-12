// TODO: Support all options defined in Tetragon: https://github.com/cilium/tetragon/tree/41b2405f3689ea0179af30f29a048ca3a3c55566/contrib/tetragon-rthooks
use std::collections::HashMap;

use tetragon::api::fine_guidance_sensors_client::FineGuidanceSensorsClient;
use tetragon::api::runtime_hook_request::Event;
use tetragon::api::{CreateContainer, RuntimeHookRequest};
use tetragon::api::{GetHealthStatusRequest, HealthStatusType};

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
    debug!("get_health | RESPONSE = {:?}", response);

    let annotations_data = [
        ("org.opencontainers.image.os", "os value"),
        ("org.opencontainers.image.os.version", "os.version value"),
        ("org.opencontainers.image.os.features", "os.features value"),
        (
            "org.opencontainers.image.architecture",
            "architecture value",
        ),
        ("org.opencontainers.image.variant", "variant value"),
        ("org.opencontainers.image.author", "author value"),
        ("org.opencontainers.image.created", "created value"),
        ("org.opencontainers.image.stopSignal", "stopSignal value"),
    ];
    let annotations = annotations_data
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let response = sensor_client
        .runtime_hook(Request::new(RuntimeHookRequest {
            event: Some(Event::CreateContainer(CreateContainer {
                cgroups_path: "cgroups_path".to_string(),
                root_dir: "root_dir".to_string(),
                container_name: "container_name".to_string(),
                annotations,
            })),
        }))
        .await?;

    info!("runtime_hook | RESPONSE = {:?}", response);

    Ok(())
}
