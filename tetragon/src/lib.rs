pub mod bpf;
pub mod cgidmap;
pub mod process;
pub mod reader;
pub mod server;
pub mod util;
pub mod api {
    #![allow(clippy::all)]
    tonic::include_proto!("tetragon");
}
pub mod ktime;
pub mod metrics;
pub mod observer;
pub mod rthooks;
