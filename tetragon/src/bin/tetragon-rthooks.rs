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
                cgroups_path: "0::/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod7e90425a_c5f4_4fdc_859c_7911cdcb282e.slice/cri-containerd-a8998a9c39b697bb4bdae4d24af0381266b4ec47350b58146ffe8fa523b471c3.scope".to_string(),
                root_dir: "root_dir".to_string(),
                container_name: "nginx_container".to_string(),
                container_id:
                    "containerd://a8998a9c39b697bb4bdae4d24af0381266b4ec47350b58146ffe8fa523b471c3"
                        .to_string(),
                pod_name: "nginx_pod".to_string(),
                pod_uid: "7e90425a-c5f4-4fdc-859c-7911cdcb282e".to_string(),
                pod_namespace: "default".to_string(),
                annotations,
            })),
        }))
        .await?;

    info!("runtime_hook | RESPONSE = {:?}", response);

    Ok(())
}
