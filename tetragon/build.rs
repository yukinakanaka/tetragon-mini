fn main() {
    tonic_build::configure()
        .build_server(true)
        .compile(
            &["proto/route_guide.proto", "proto/sensors.proto"],
            &["proto"],
        )
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));
}
