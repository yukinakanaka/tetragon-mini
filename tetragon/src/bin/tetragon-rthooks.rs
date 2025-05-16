// TODO: Support all options defined in Tetragon: https://github.com/cilium/tetragon/tree/41b2405f3689ea0179af30f29a048ca3a3c55566/contrib/tetragon-rthooks
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
                cgroups_path: "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod3b673e1d_289e_4210_8ceb_5a253b48d390.slice/cri-containerd-5da35096936fefa0c7a7280a439fb8c680568820a20d410c7b9e30955d88a147.scope".to_string(),
                root_dir: "root_dir".to_string(),
                container_name: "nginx_container".to_string(),
                container_id: "".to_string(),
                pod_name: "nginx-pod".to_string(),
                pod_uid: "3b673e1d-289e-4210-8ceb-5a253b48d390".to_string(),
                pod_namespace: "default".to_string(),
                annotations,
            })),
        }))
        .await?;

    info!("runtime_hook | RESPONSE = {:?}", response);

    Ok(())
}
