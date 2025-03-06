use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry_otlp::MetricExporter;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;

fn get_resource() -> Resource {
    static RESOURCE: OnceLock<Resource> = OnceLock::new();

    RESOURCE
        .get_or_init(|| Resource::builder().with_service_name("tetragon").build())
        .clone()
}

pub fn init_metrics() -> SdkMeterProvider {
    let exporter = MetricExporter::builder()
        .with_tonic()
        .build()
        .expect("Failed to create exporter");

    let provider = SdkMeterProvider::builder()
        .with_resource(get_resource())
        .with_reader(
            PeriodicReader::builder(exporter)
                .with_interval(Duration::from_secs(10))
                .build(),
        )
        .build();

    global::set_meter_provider(provider.clone());

    provider
}

pub fn init_traces() -> SdkTracerProvider {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .build()
        .expect("Failed to create exporter");

    let provider = SdkTracerProvider::builder()
        .with_resource(get_resource())
        .with_batch_exporter(exporter)
        .build();

    global::set_tracer_provider(provider.clone());

    provider
}
