use crate::api::fine_guidance_sensors_server::{FineGuidanceSensors, FineGuidanceSensorsServer};
use crate::api::{
    AddTracingPolicyRequest, AddTracingPolicyResponse, DeleteTracingPolicyRequest,
    DeleteTracingPolicyResponse, DisableSensorRequest, DisableSensorResponse,
    DisableTracingPolicyRequest, DisableTracingPolicyResponse, EnableSensorRequest,
    EnableSensorResponse, EnableTracingPolicyRequest, EnableTracingPolicyResponse, GetDebugRequest,
    GetDebugResponse, GetEventsRequest, GetEventsResponse, GetHealthStatusRequest,
    GetHealthStatusResponse, GetStackTraceTreeRequest, GetStackTraceTreeResponse,
    GetVersionRequest, GetVersionResponse, HealthStatus, HealthStatusResult, HealthStatusType,
    ListSensorsRequest, ListSensorsResponse, ListTracingPoliciesRequest,
    ListTracingPoliciesResponse, RemoveSensorRequest, RemoveSensorResponse, RuntimeHookRequest,
    RuntimeHookResponse, SetDebugRequest, SetDebugResponse,
};
use std::time::SystemTime;
use tracing::*;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::api::get_events_response::Event;

#[derive(Debug)]
pub struct FineGuidanceSensorsService {
    pub rx: tokio::sync::broadcast::Receiver<Event>,
}

#[tonic::async_trait]
impl FineGuidanceSensors for FineGuidanceSensorsService {
    type GetEventsStream = ReceiverStream<Result<GetEventsResponse, Status>>;
    async fn get_events(
        &self,
        request: Request<GetEventsRequest>,
    ) -> std::result::Result<Response<Self::GetEventsStream>, Status> {
        debug!("get_events: {:?}", request);
        let (tx, rx) = mpsc::channel(4);

        let mut event_rx = self.rx.resubscribe();
        tokio::spawn(async move {
            loop {
                debug! {"Waiting events..."};
                let res = event_rx.recv().await;
                let Ok(event) = res else {
                    warn!("recieving event error: ${:#?}", res);
                    continue;
                };

                if let Err(e) = tx
                    .send(Ok(GetEventsResponse {
                        node_name: "node".to_string(),
                        time: Some(SystemTime::now().into()),
                        aggregation_info: None,
                        event: Some(event),
                        cluster_name: "cluster".to_string(),
                    }))
                    .await
                {
                    warn!("Sending event error: ${:#?}", e);
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_health(
        &self,
        _request: Request<GetHealthStatusRequest>,
    ) -> std::result::Result<Response<GetHealthStatusResponse>, Status> {
        Ok(Response::new(GetHealthStatusResponse {
            health_status: vec![HealthStatus {
                event: HealthStatusType::Status.into(),
                status: HealthStatusResult::HealthStatusRunning.into(),
                details: "running".to_string(),
            }],
        }))
    }

    async fn add_tracing_policy(
        &self,
        _request: tonic::Request<AddTracingPolicyRequest>,
    ) -> std::result::Result<Response<AddTracingPolicyResponse>, Status> {
        unimplemented!()
    }
    async fn delete_tracing_policy(
        &self,
        _request: Request<DeleteTracingPolicyRequest>,
    ) -> std::result::Result<Response<DeleteTracingPolicyResponse>, Status> {
        unimplemented!()
    }
    async fn list_tracing_policies(
        &self,
        _request: Request<ListTracingPoliciesRequest>,
    ) -> std::result::Result<Response<ListTracingPoliciesResponse>, Status> {
        unimplemented!()
    }
    async fn enable_tracing_policy(
        &self,
        _request: Request<EnableTracingPolicyRequest>,
    ) -> std::result::Result<Response<EnableTracingPolicyResponse>, Status> {
        unimplemented!()
    }
    async fn disable_tracing_policy(
        &self,
        _request: Request<DisableTracingPolicyRequest>,
    ) -> std::result::Result<Response<DisableTracingPolicyResponse>, Status> {
        unimplemented!()
    }
    async fn list_sensors(
        &self,
        _request: Request<ListSensorsRequest>,
    ) -> std::result::Result<Response<ListSensorsResponse>, Status> {
        unimplemented!()
    }
    async fn enable_sensor(
        &self,
        _request: Request<EnableSensorRequest>,
    ) -> std::result::Result<Response<EnableSensorResponse>, Status> {
        unimplemented!()
    }
    async fn disable_sensor(
        &self,
        _request: Request<DisableSensorRequest>,
    ) -> std::result::Result<Response<DisableSensorResponse>, Status> {
        unimplemented!()
    }
    async fn remove_sensor(
        &self,
        _request: Request<RemoveSensorRequest>,
    ) -> std::result::Result<Response<RemoveSensorResponse>, Status> {
        unimplemented!()
    }
    async fn get_stack_trace_tree(
        &self,
        _request: Request<GetStackTraceTreeRequest>,
    ) -> std::result::Result<Response<GetStackTraceTreeResponse>, Status> {
        unimplemented!()
    }
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> std::result::Result<Response<GetVersionResponse>, Status> {
        unimplemented!()
    }
    async fn runtime_hook(
        &self,
        _request: Request<RuntimeHookRequest>,
    ) -> std::result::Result<Response<RuntimeHookResponse>, Status> {
        info!("runtime_hook: {:?}", _request);
        Ok(Response::new(RuntimeHookResponse {}))
    }
    async fn get_debug(
        &self,
        _request: Request<GetDebugRequest>,
    ) -> std::result::Result<Response<GetDebugResponse>, Status> {
        unimplemented!()
    }
    async fn set_debug(
        &self,
        _request: Request<SetDebugRequest>,
    ) -> std::result::Result<Response<SetDebugResponse>, Status> {
        unimplemented!()
    }
}

impl FineGuidanceSensorsService {
    pub async fn run(self, stop: impl std::future::Future<Output = ()>) -> anyhow::Result<()> {
        let addr = "[::1]:10001".parse().unwrap();

        let svc = FineGuidanceSensorsServer::new(self);

        Server::builder()
            .add_service(svc)
            .serve_with_shutdown(addr, stop)
            .await?;

        info!("server terminated");

        Ok(())
    }
}
