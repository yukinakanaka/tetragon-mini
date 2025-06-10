# Tetragon-mini
- Rewriting [Tetragon](https://github.com/cilium/tetragon) in Rust.🦀
- Security Observation Tool written in Rust aya framework.🐝

<img src="docs/images/architecture.png" width="600">

## Why "mini"?
- It has fewer features compared to Tetragon.
- Compared to Tetragon, it has a smaller binary size (because it's written in Rust)

## Progress
![](https://geps.dev/progress/15)

### Done
- Simple Process Lifecycle Monitoring
- Integration with Kubernetes API
- Integration with CRI-O

## Process Lifecycle Monitoring
Tetragon-mini can monitor process lifecycle like bellow:
```
🚀 process      1781470: root: /usr/bin/bash  default/nginx
💥 exit         1781560: root: /usr/bin/bash  default/nginx
💥 exit         1781470: root: /usr/bin/bash  default/nginx
🚀 process      1781659: root: /usr/bin/bash  default/nginx
💥 exit         1781727: root: /usr/bin/date  default/nginx
🚀 process      1781740: root: /usr/bin/ls -la default/nginx
💥 exit         1781740: root: /usr/bin/ls -la default/nginx
```

### TODO
-   Process LifeCycle Monitoring
    - Support containerd
    - Cgroup Tracker
-	Tracing Policies
-	Add more Tetra commands and options
-	Support multiple kernel versions
-	Enable running on Docker, Kubernetes
-	And more…


## How to run
### Prerequisites
- Linux
- Rust nightly
- [bpf-linker](https://github.com/aya-rs/bpf-linker)
- [bindgen-cli](https://rust-lang.github.io/rust-bindgen/command-line-usage.html)

### Set up Lima VM on MacOS
If you're using MacOS, you can quickly set it up with lima and my template.
```
lima start lima/tetragon-mini-crio.yaml
```

### Installing ContainerRuntimeHook
tetragon-mini does not support dynamic configuration of the ContainerRuntimeHook. Please configure it manually according to your container runtime:
- CRI-O: Follow the instructions in [OCI Hook in CRI-O](./contrib/tetragon-rthooks/README.md)
- containerd: Not supported

### Build and Run
- Run the next command to generate the necessary Struct codes
```
cargo xtask codegen
```
- Build and Run eBPF Programs and Agent
```
cargo xtask run
```
- Build and Run client
```
cargo run --bin tetra
```

## Blog Posts
- [Tetragon-mini by Rust: eBPF-based process monitoring](https://yuki-nakamura.com/2024/12/27/tetragon-mini-by-rust-ebpf-based-process-monitoring/)
