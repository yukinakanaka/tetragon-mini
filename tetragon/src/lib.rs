pub mod bpf;
pub mod process;
pub mod reader;
pub mod server;
pub mod util;
pub mod api {
    tonic::include_proto!("tetragon");
}
