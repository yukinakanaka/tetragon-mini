//! Configuration management for Tetragon
//!
//! This module provides configuration structures and loading functionality
//! equivalent to the Go pkg/option package.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow;
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

pub mod defaults;
pub mod loader;
pub mod metrics;
pub mod validation;

/// Username metadata collection modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum UsernameMetadata {
    Disabled,
    Unix,
}

impl Default for UsernameMetadata {
    fn default() -> Self {
        Self::Disabled
    }
}

impl FromStr for UsernameMetadata {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" => Ok(Self::Disabled),
            "unix" => Ok(Self::Unix),
            _ => Err(format!("Invalid username metadata mode: {}", s)),
        }
    }
}

/// Cgroup rate limiting configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CgroupRate {
    pub events: u64,
    pub interval: u64,
}

impl CgroupRate {
    pub fn is_enabled(&self) -> bool {
        self.events != 0 && self.interval != 0
    }
}

/// Main configuration structure for Tetragon
#[derive(Debug, Clone, Serialize, Deserialize, Parser)]
#[clap(
    name = "tetragon",
    about = "eBPF-based Security Observability and Runtime Enforcement"
)]
#[serde(default)]
pub struct Config {
    /// Configuration directory that contains a file for each option
    #[clap(long = "config-dir")]
    pub config_dir: Option<String>,

    /// Enable debug messages. Equivalent to '--log-level=debug'
    #[clap(short = 'd', long = "debug")]
    pub debug: bool,

    /// Location of procfs to consume existing PIDs
    #[clap(long = "procfs", default_value = defaults::DEFAULT_PROCFS)]
    #[serde(default = "defaults::default_procfs")]
    pub procfs: String,

    /// Kernel version
    #[clap(long = "kernel")]
    pub kernel_version: Option<String>,

    /// Location of Tetragon libs (btf and bpf files)
    #[clap(long = "bpf-lib", default_value = defaults::DEFAULT_TETRAGON_LIB)]
    #[serde(default = "defaults::default_tetragon_lib")]
    pub hubble_lib: String,

    /// Location of btf
    #[clap(long = "btf", default_value = defaults::DEFAULT_BTF_FILE)]
    #[serde(default = "defaults::default_btf_file")]
    pub btf: String,

    /// Set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump
    #[clap(long = "verbose", default_value = "0")]
    pub verbosity: i32,

    /// Force loading small programs, even in kernels with >= 5.3 versions
    #[clap(long = "force-small-progs")]
    pub force_small_progs: bool,

    /// Force loading large programs, even in kernels with < 5.3 versions
    #[clap(long = "force-large-progs")]
    pub force_large_progs: bool,

    /// Name of the cluster where Tetragon is installed
    #[clap(long = "cluster-name")]
    pub cluster_name: Option<String>,

    /// Enable namespace information in process_exec and process_kprobe events
    #[clap(long = "enable-process-ns")]
    pub enable_process_ns: bool,

    /// Enable process_cred events
    #[clap(long = "enable-process-cred")]
    pub enable_process_cred: bool,

    /// Access Kubernetes API to associate Tetragon events with Kubernetes pods
    #[clap(long = "enable-k8s-api")]
    pub enable_k8s: bool,

    /// Absolute path of the kubernetes kubeconfig file
    #[clap(long = "k8s-kubeconfig-path")]
    pub k8s_kubeconfig_path: Option<String>,

    /// Allow to disable kprobe multi interface
    #[clap(long = "disable-kprobe-multi")]
    pub disable_kprobe_multi: bool,

    /// Set tetragon bpf directory (default 'tetragon')
    #[clap(long = "bpf-dir", default_value = defaults::DEFAULT_MAP_PREFIX)]
    #[serde(default = "defaults::default_map_prefix")]
    pub bpf_dir: String,

    /// Logger parameters
    #[clap(skip)]
    pub log_opts: HashMap<String, String>,

    /// Set perf ring buffer size for single cpu (default 65k, allows K/M/G suffix)
    #[clap(long = "rb-size", default_value = "0")]
    pub rb_size: String,

    /// Set perf ring buffer size in total for all cpus (default 65k per cpu, allows K/M/G suffix)
    #[clap(long = "rb-size-total", default_value = "0")]
    pub rb_size_total: String,

    /// Set size of channel between ring buffer and sensor service (default 65k, allows K/M/G suffix)
    #[clap(long = "rb-queue-size", default_value = defaults::DEFAULT_RB_QUEUE_SIZE)]
    #[serde(default = "defaults::default_rb_queue_size")]
    pub rb_queue_size: String,

    /// Size of the process cache
    #[clap(long = "process-cache-size", default_value_t = defaults::DEFAULT_PROCESS_CACHE_SIZE)]
    #[serde(default = "defaults::default_process_cache_size")]
    pub process_cache_size: i32,

    /// Size of the data events cache
    #[clap(long = "data-cache-size", default_value_t = defaults::DEFAULT_DATA_CACHE_SIZE)]
    #[serde(default = "defaults::default_data_cache_size")]
    pub data_cache_size: i32,

    /// Metrics server address (e.g. ':2112'). Disabled by default
    #[clap(long = "metrics-server")]
    pub metrics_server: Option<String>,

    /// Comma-separated list of enabled metrics labels. Unknown labels will be ignored.
    #[clap(
        long = "metrics-label-filter",
        default_value = defaults::DEFAULT_METRICS_LABEL_FILTER
    )]
    #[serde(default = "defaults::default_metrics_label_filter")]
    pub metrics_label_filter: String,

    /// gRPC server address (e.g. 'localhost:54321' or 'unix:///var/run/tetragon/tetragon.sock'). An empty address disables the gRPC server
    #[clap(long = "server-address", default_value = defaults::DEFAULT_SERVER_ADDRESS)]
    #[serde(default = "defaults::default_server_address")]
    pub server_address: String,

    /// Tracing policy file to load at startup
    #[clap(long = "tracing-policy")]
    pub tracing_policy: Option<String>,

    /// Directory from where to load Tracing Policies
    #[clap(
        long = "tracing-policy-dir",
        default_value = defaults::DEFAULT_TP_DIR
    )]
    #[serde(default = "defaults::default_tp_dir")]
    pub tracing_policy_dir: String,

    /// Filename for JSON export. Disabled by default
    #[clap(long = "export-filename")]
    pub export_filename: Option<String>,

    /// Size in MB for rotating JSON export files
    #[clap(long = "export-file-max-size-mb", default_value_t = defaults::DEFAULT_EXPORT_FILE_MAX_SIZE_MB)]
    #[serde(default = "defaults::default_export_file_max_size_mb")]
    pub export_file_max_size_mb: i32,

    /// Interval at which to rotate JSON export files in addition to rotating them by size
    #[clap(long = "export-file-rotation-interval", value_parser = parse_duration)]
    pub export_file_rotation_interval: Option<Duration>,

    /// Number of rotated JSON export files to retain
    #[clap(long = "export-file-max-backups", default_value_t = defaults::DEFAULT_EXPORT_FILE_MAX_BACKUPS)]
    #[serde(default = "defaults::default_export_file_max_backups")]
    pub export_file_max_backups: i32,

    /// Compress rotated JSON export files
    #[clap(long = "export-file-compress")]
    pub export_file_compress: bool,

    /// Rate limit (per minute) for event export. Set to -1 to disable
    #[clap(long = "export-rate-limit", default_value_t = defaults::DEFAULT_EXPORT_RATE_LIMIT)]
    #[serde(default = "defaults::default_export_rate_limit")]
    pub export_rate_limit: i32,

    /// Access permissions on JSON export files
    #[clap(long = "export-file-perm", default_value = defaults::DEFAULT_LOGS_PERMISSION)]
    #[serde(default = "defaults::default_logs_permission")]
    pub export_file_perm: String,

    /// Enable JSON export aggregation
    #[clap(long = "enable-export-aggregation")]
    pub enable_export_aggregation: bool,

    /// JSON export aggregation time window
    #[clap(long = "export-aggregation-window-size", default_value = "15s", value_parser = parse_duration_required)]
    #[serde(default = "defaults::default_export_aggregation_window_size")]
    pub export_aggregation_window_size: Duration,

    /// Aggregator channel buffer size
    #[clap(long = "export-aggregation-buffer-size", default_value_t = defaults::DEFAULT_EXPORT_AGGREGATION_BUFFER_SIZE)]
    #[serde(default = "defaults::default_export_aggregation_buffer_size")]
    pub export_aggregation_buffer_size: u64,

    /// Store CPU profile into provided file
    #[clap(long = "cpuprofile", hide = true)]
    pub cpu_profile: Option<String>,

    /// Store MEM profile into provided file
    #[clap(long = "memprofile", hide = true)]
    pub mem_profile: Option<String>,

    /// Serves runtime profile data via HTTP (e.g. 'localhost:6060'). Disabled by default
    #[clap(long = "pprof-address")]
    pub pprof_addr: Option<String>,

    /// Set the size of the internal event queue.
    #[clap(long = "event-queue-size", default_value_t = defaults::DEFAULT_EVENT_QUEUE_SIZE)]
    #[serde(default = "defaults::default_event_queue_size")]
    pub event_queue_size: u32,

    /// Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable
    #[clap(long = "release-pinned-bpf", default_value = "true")]
    #[serde(default = "defaults::default_release_pinned")]
    pub release_pinned: bool,

    /// Enable policy filter code
    #[clap(long = "enable-policy-filter")]
    pub enable_policy_filter: bool,

    /// Enable policy filter debug messages
    #[clap(long = "enable-policy-filter-debug")]
    pub enable_policy_filter_debug: bool,

    /// Enable pidSet export filters. Not recommended for production use
    #[clap(long = "enable-pid-set-filter")]
    pub enable_pid_set_filter: bool,

    /// Enable metrics for message handling latency
    #[clap(long = "enable-msg-handling-latency")]
    pub enable_msg_handling_latency: bool,

    /// Enable PodInfo custom resource
    #[clap(long = "enable-pod-info")]
    pub enable_pod_info: bool,

    /// Enable TracingPolicy and TracingPolicyNamespaced custom resources
    #[clap(long = "enable-tracing-policy-crd", default_value = "true")]
    #[serde(default = "defaults::default_enable_tracing_policy_crd")]
    pub enable_tracing_policy_crd: bool,

    /// Expose real linear addresses in events stack traces
    #[clap(long = "expose-stack-addresses")]
    pub expose_stack_addresses: bool,

    /// Base sensor events cgroup rate <events,interval> disabled by default ('1000,1s' means rate 1000 events per second)
    #[clap(long = "cgroup-rate")]
    pub cgroup_rate: Option<String>,

    /// Resolve UIDs to user names for processes running in host namespace
    #[clap(long = "username-metadata", default_value = "disabled")]
    pub username_metadata: UsernameMetadata,

    /// Health server address (e.g. ':6789')(use '' to disabled it)
    #[clap(long = "health-server-address", default_value = defaults::DEFAULT_HEALTH_SERVER_ADDRESS)]
    #[serde(default = "defaults::default_health_server_address")]
    pub health_server_address: String,

    /// Health server interval in seconds
    #[clap(long = "health-server-interval", default_value_t = defaults::DEFAULT_HEALTH_SERVER_INTERVAL)]
    #[serde(default = "defaults::default_health_server_interval")]
    pub health_server_interval: i32,

    /// Do not unload sensors on exit
    #[clap(long = "keep-sensors-on-exit")]
    pub keep_sensors_on_exit: bool,

    /// enable CRI client for tetragon
    #[clap(long = "enable-cri")]
    pub enable_cri: bool,

    /// CRI endpoint
    #[clap(long = "cri-endpoint")]
    pub cri_endpoint: Option<String>,

    /// enable pod resolution via cgroup ids
    #[clap(long = "enable-cgidmap")]
    pub enable_cg_idmap: bool,

    /// enable cgidmap debugging info
    #[clap(long = "enable-cgidmap-debug")]
    pub enable_cg_idmap_debug: bool,

    /// enable cgroup tracker id (only used if 'enable-cgidmap' is set)
    #[clap(long = "enable-cgtrackerid", default_value = "true")]
    #[serde(default = "defaults::default_enable_cg_tracker_id")]
    pub enable_cg_tracker_id: bool,

    /// Number of retries for event cache
    #[clap(long = "event-cache-retries", default_value_t = defaults::DEFAULT_EVENT_CACHE_NUM_RETRIES)]
    #[serde(default = "defaults::default_event_cache_num_retries")]
    pub event_cache_num_retries: i32,

    /// Delay in seconds between event cache retries
    #[clap(long = "event-cache-retry-delay", default_value_t = defaults::DEFAULT_EVENT_CACHE_RETRY_DELAY)]
    #[serde(default = "defaults::default_event_cache_retry_delay")]
    pub event_cache_retry_delay: i32,

    /// syscall64 type will produce output of type size (compatibility flag, will be removed in v1.4)
    #[clap(long = "enable-compatibility-syscall64-size-type")]
    pub compatibility_syscall64_size_type: bool,

    /// Set log level
    #[clap(long = "log-level", default_value = defaults::DEFAULT_LOG_LEVEL)]
    #[serde(default = "defaults::default_log_level")]
    pub log_level: String,

    /// Set log format
    #[clap(long = "log-format", default_value = defaults::DEFAULT_LOG_FORMAT)]
    #[serde(default = "defaults::default_log_format")]
    pub log_format: String,

    /// JSON export allowlist
    #[clap(long = "export-allowlist")]
    pub export_allowlist: Option<String>,

    /// JSON export denylist
    #[clap(long = "export-denylist")]
    pub export_denylist: Option<String>,

    /// Field filters for event exports
    #[clap(long = "field-filters")]
    pub field_filters: Option<String>,

    /// Redaction filters for events
    #[clap(long = "redaction-filters")]
    pub redaction_filters: Option<String>,

    /// Network namespace dir
    #[clap(long = "netns-dir", default_value = defaults::DEFAULT_NETNS_DIR)]
    #[serde(default = "defaults::default_netns_dir")]
    pub netns_dir: String,

    /// Allow to disable uprobe multi interface
    #[clap(long = "disable-uprobe-multi")]
    pub disable_uprobe_multi: bool,

    /// Generate documentation in YAML format to stdout
    #[clap(long = "generate-docs")]
    pub generate_docs: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_dir: None,
            debug: false,
            procfs: defaults::default_procfs(),
            kernel_version: None,
            hubble_lib: defaults::default_tetragon_lib(),
            btf: defaults::default_btf_file(),
            verbosity: 0,
            force_small_progs: false,
            force_large_progs: false,
            cluster_name: None,
            enable_process_ns: false,
            enable_process_cred: false,
            enable_k8s: false,
            k8s_kubeconfig_path: None,
            disable_kprobe_multi: false,
            bpf_dir: defaults::default_map_prefix(),
            log_opts: HashMap::new(),
            rb_size: "0".to_string(),
            rb_size_total: "0".to_string(),
            rb_queue_size: defaults::default_rb_queue_size(),
            process_cache_size: defaults::default_process_cache_size(),
            data_cache_size: defaults::default_data_cache_size(),
            metrics_server: None,
            metrics_label_filter: defaults::default_metrics_label_filter(),
            server_address: defaults::default_server_address(),
            tracing_policy: None,
            tracing_policy_dir: defaults::default_tp_dir(),
            export_filename: None,
            export_file_max_size_mb: defaults::default_export_file_max_size_mb(),
            export_file_rotation_interval: None,
            export_file_max_backups: defaults::default_export_file_max_backups(),
            export_file_compress: false,
            export_rate_limit: defaults::default_export_rate_limit(),
            export_file_perm: defaults::default_logs_permission(),
            enable_export_aggregation: false,
            export_aggregation_window_size: defaults::default_export_aggregation_window_size(),
            export_aggregation_buffer_size: defaults::default_export_aggregation_buffer_size(),
            cpu_profile: None,
            mem_profile: None,
            pprof_addr: None,
            event_queue_size: defaults::default_event_queue_size(),
            release_pinned: defaults::default_release_pinned(),
            enable_policy_filter: false,
            enable_policy_filter_debug: false,
            enable_pid_set_filter: false,
            enable_msg_handling_latency: false,
            enable_pod_info: false,
            enable_tracing_policy_crd: defaults::default_enable_tracing_policy_crd(),
            expose_stack_addresses: false,
            cgroup_rate: None,
            username_metadata: UsernameMetadata::default(),
            health_server_address: defaults::default_health_server_address(),
            health_server_interval: defaults::default_health_server_interval(),
            keep_sensors_on_exit: false,
            enable_cri: false,
            cri_endpoint: None,
            enable_cg_idmap: false,
            enable_cg_idmap_debug: false,
            enable_cg_tracker_id: defaults::default_enable_cg_tracker_id(),
            event_cache_num_retries: defaults::default_event_cache_num_retries(),
            event_cache_retry_delay: defaults::default_event_cache_retry_delay(),
            compatibility_syscall64_size_type: false,
            log_level: defaults::default_log_level(),
            log_format: defaults::default_log_format(),
            export_allowlist: None,
            export_denylist: None,
            field_filters: None,
            redaction_filters: None,
            netns_dir: defaults::default_netns_dir(),
            disable_uprobe_multi: false,
            generate_docs: false,
        }
    }
}

impl Config {
    /// Parse cgroup rate from string format "events,interval"
    pub fn parse_cgroup_rate(&self) -> Option<CgroupRate> {
        let rate_str = self.cgroup_rate.as_ref()?;

        if rate_str.is_empty() {
            return None;
        }

        let parts: Vec<&str> = rate_str.split(',').collect();
        if parts.len() != 2 {
            eprintln!("failed to parse cgroup rate '{}'", rate_str);
            return None;
        }

        let events = match parts[0].parse::<u64>() {
            Ok(e) if !parts[0].is_empty() => e,
            _ => {
                eprintln!("failed to parse cgroup rate events '{}'", parts[0]);
                return None;
            }
        };

        let interval_str = parts[1];
        let interval = match humantime::parse_duration(interval_str) {
            Ok(d) if !interval_str.is_empty() => d.as_nanos() as u64,
            _ => {
                eprintln!("failed to parse cgroup rate interval '{}'", interval_str);
                return None;
            }
        };

        Some(CgroupRate { events, interval })
    }

    /// Check if cgroup rate limiting is enabled
    pub fn cgroup_rate_enabled(&self) -> bool {
        self.parse_cgroup_rate()
            .map(|rate| rate.is_enabled())
            .unwrap_or(false)
    }

    /// Merge configuration from environment variables
    pub fn merge_from_env(&mut self) {
        // Environment variables with TETRAGON_ prefix, converting hyphens to underscores

        if let Ok(val) = std::env::var("TETRAGON_DEBUG") {
            self.debug = val.parse().unwrap_or(self.debug);
        }

        if let Ok(val) = std::env::var("TETRAGON_PROCFS") {
            self.procfs = val;
        }

        if let Ok(val) = std::env::var("TETRAGON_KERNEL") {
            self.kernel_version = Some(val);
        }

        if let Ok(val) = std::env::var("TETRAGON_BPF_LIB") {
            self.hubble_lib = val;
        }

        if let Ok(val) = std::env::var("TETRAGON_BTF") {
            self.btf = val;
        }

        if let Ok(val) = std::env::var("TETRAGON_VERBOSE") {
            self.verbosity = val.parse().unwrap_or(self.verbosity);
        }

        if let Ok(val) = std::env::var("TETRAGON_CLUSTER_NAME") {
            self.cluster_name = Some(val);
        }

        if let Ok(val) = std::env::var("TETRAGON_ENABLE_K8S_API") {
            self.enable_k8s = val.parse().unwrap_or(self.enable_k8s);
        }

        if let Ok(val) = std::env::var("TETRAGON_SERVER_ADDRESS") {
            self.server_address = val;
        }

        if let Ok(val) = std::env::var("TETRAGON_METRICS_SERVER") {
            self.metrics_server = Some(val);
        }

        // Add more environment variable mappings as needed...
    }
}

/// Load configuration with priority: config files -> environment variables -> CLI arguments
pub fn load_config() -> anyhow::Result<Config> {
    // 1. Start with default config
    let mut config = Config::default();

    // 2. Load from config files (lowest priority)
    match loader::load_standard_config() {
        Ok(file_config) => {
            config = file_config;
        }
        Err(e) => {
            eprintln!("Warning: failed to load standard config: {}", e);
        }
    }

    // 3. Merge from environment variables (medium priority)
    config.merge_from_env();

    // 4. Parse CLI arguments and override (highest priority)
    let cli_args = Config::parse();

    // Override with CLI arguments only if they're not at default values
    // This is done by checking if the CLI value differs from default
    let default_config = Config::default();

    if cli_args.config_dir != default_config.config_dir {
        config.config_dir = cli_args.config_dir;
    }
    if cli_args.debug != default_config.debug {
        config.debug = cli_args.debug;
    }
    if cli_args.procfs != default_config.procfs {
        config.procfs = cli_args.procfs;
    }
    if cli_args.kernel_version != default_config.kernel_version {
        config.kernel_version = cli_args.kernel_version;
    }
    if cli_args.hubble_lib != default_config.hubble_lib {
        config.hubble_lib = cli_args.hubble_lib;
    }
    if cli_args.btf != default_config.btf {
        config.btf = cli_args.btf;
    }
    if cli_args.verbosity != default_config.verbosity {
        config.verbosity = cli_args.verbosity;
    }
    if cli_args.force_small_progs != default_config.force_small_progs {
        config.force_small_progs = cli_args.force_small_progs;
    }
    if cli_args.force_large_progs != default_config.force_large_progs {
        config.force_large_progs = cli_args.force_large_progs;
    }
    if cli_args.cluster_name != default_config.cluster_name {
        config.cluster_name = cli_args.cluster_name;
    }
    if cli_args.enable_process_ns != default_config.enable_process_ns {
        config.enable_process_ns = cli_args.enable_process_ns;
    }
    if cli_args.enable_process_cred != default_config.enable_process_cred {
        config.enable_process_cred = cli_args.enable_process_cred;
    }
    if cli_args.enable_k8s != default_config.enable_k8s {
        config.enable_k8s = cli_args.enable_k8s;
    }
    if cli_args.k8s_kubeconfig_path != default_config.k8s_kubeconfig_path {
        config.k8s_kubeconfig_path = cli_args.k8s_kubeconfig_path;
    }
    if cli_args.disable_kprobe_multi != default_config.disable_kprobe_multi {
        config.disable_kprobe_multi = cli_args.disable_kprobe_multi;
    }
    if cli_args.bpf_dir != default_config.bpf_dir {
        config.bpf_dir = cli_args.bpf_dir;
    }
    if cli_args.rb_size != default_config.rb_size {
        config.rb_size = cli_args.rb_size;
    }
    if cli_args.rb_size_total != default_config.rb_size_total {
        config.rb_size_total = cli_args.rb_size_total;
    }
    if cli_args.rb_queue_size != default_config.rb_queue_size {
        config.rb_queue_size = cli_args.rb_queue_size;
    }
    if cli_args.process_cache_size != default_config.process_cache_size {
        config.process_cache_size = cli_args.process_cache_size;
    }
    if cli_args.data_cache_size != default_config.data_cache_size {
        config.data_cache_size = cli_args.data_cache_size;
    }
    if cli_args.metrics_server != default_config.metrics_server {
        config.metrics_server = cli_args.metrics_server;
    }
    if cli_args.metrics_label_filter != default_config.metrics_label_filter {
        config.metrics_label_filter = cli_args.metrics_label_filter;
    }
    if cli_args.server_address != default_config.server_address {
        config.server_address = cli_args.server_address;
    }
    if cli_args.tracing_policy != default_config.tracing_policy {
        config.tracing_policy = cli_args.tracing_policy;
    }
    if cli_args.tracing_policy_dir != default_config.tracing_policy_dir {
        config.tracing_policy_dir = cli_args.tracing_policy_dir;
    }
    if cli_args.export_filename != default_config.export_filename {
        config.export_filename = cli_args.export_filename;
    }
    if cli_args.export_file_max_size_mb != default_config.export_file_max_size_mb {
        config.export_file_max_size_mb = cli_args.export_file_max_size_mb;
    }
    if cli_args.export_file_rotation_interval != default_config.export_file_rotation_interval {
        config.export_file_rotation_interval = cli_args.export_file_rotation_interval;
    }
    if cli_args.export_file_max_backups != default_config.export_file_max_backups {
        config.export_file_max_backups = cli_args.export_file_max_backups;
    }
    if cli_args.export_file_compress != default_config.export_file_compress {
        config.export_file_compress = cli_args.export_file_compress;
    }
    if cli_args.export_rate_limit != default_config.export_rate_limit {
        config.export_rate_limit = cli_args.export_rate_limit;
    }
    if cli_args.export_file_perm != default_config.export_file_perm {
        config.export_file_perm = cli_args.export_file_perm;
    }
    if cli_args.enable_export_aggregation != default_config.enable_export_aggregation {
        config.enable_export_aggregation = cli_args.enable_export_aggregation;
    }
    if cli_args.export_aggregation_window_size != default_config.export_aggregation_window_size {
        config.export_aggregation_window_size = cli_args.export_aggregation_window_size;
    }
    if cli_args.export_aggregation_buffer_size != default_config.export_aggregation_buffer_size {
        config.export_aggregation_buffer_size = cli_args.export_aggregation_buffer_size;
    }
    if cli_args.cpu_profile != default_config.cpu_profile {
        config.cpu_profile = cli_args.cpu_profile;
    }
    if cli_args.mem_profile != default_config.mem_profile {
        config.mem_profile = cli_args.mem_profile;
    }
    if cli_args.pprof_addr != default_config.pprof_addr {
        config.pprof_addr = cli_args.pprof_addr;
    }
    if cli_args.event_queue_size != default_config.event_queue_size {
        config.event_queue_size = cli_args.event_queue_size;
    }
    if cli_args.release_pinned != default_config.release_pinned {
        config.release_pinned = cli_args.release_pinned;
    }
    if cli_args.enable_policy_filter != default_config.enable_policy_filter {
        config.enable_policy_filter = cli_args.enable_policy_filter;
    }
    if cli_args.enable_policy_filter_debug != default_config.enable_policy_filter_debug {
        config.enable_policy_filter_debug = cli_args.enable_policy_filter_debug;
    }
    if cli_args.enable_pid_set_filter != default_config.enable_pid_set_filter {
        config.enable_pid_set_filter = cli_args.enable_pid_set_filter;
    }
    if cli_args.enable_msg_handling_latency != default_config.enable_msg_handling_latency {
        config.enable_msg_handling_latency = cli_args.enable_msg_handling_latency;
    }
    if cli_args.enable_pod_info != default_config.enable_pod_info {
        config.enable_pod_info = cli_args.enable_pod_info;
    }
    if cli_args.enable_tracing_policy_crd != default_config.enable_tracing_policy_crd {
        config.enable_tracing_policy_crd = cli_args.enable_tracing_policy_crd;
    }
    if cli_args.expose_stack_addresses != default_config.expose_stack_addresses {
        config.expose_stack_addresses = cli_args.expose_stack_addresses;
    }
    if cli_args.cgroup_rate != default_config.cgroup_rate {
        config.cgroup_rate = cli_args.cgroup_rate;
    }
    if cli_args.username_metadata != default_config.username_metadata {
        config.username_metadata = cli_args.username_metadata;
    }
    if cli_args.health_server_address != default_config.health_server_address {
        config.health_server_address = cli_args.health_server_address;
    }
    if cli_args.health_server_interval != default_config.health_server_interval {
        config.health_server_interval = cli_args.health_server_interval;
    }
    if cli_args.keep_sensors_on_exit != default_config.keep_sensors_on_exit {
        config.keep_sensors_on_exit = cli_args.keep_sensors_on_exit;
    }
    if cli_args.enable_cri != default_config.enable_cri {
        config.enable_cri = cli_args.enable_cri;
    }
    if cli_args.cri_endpoint != default_config.cri_endpoint {
        config.cri_endpoint = cli_args.cri_endpoint;
    }
    if cli_args.enable_cg_idmap != default_config.enable_cg_idmap {
        config.enable_cg_idmap = cli_args.enable_cg_idmap;
    }
    if cli_args.enable_cg_idmap_debug != default_config.enable_cg_idmap_debug {
        config.enable_cg_idmap_debug = cli_args.enable_cg_idmap_debug;
    }
    if cli_args.enable_cg_tracker_id != default_config.enable_cg_tracker_id {
        config.enable_cg_tracker_id = cli_args.enable_cg_tracker_id;
    }
    if cli_args.event_cache_num_retries != default_config.event_cache_num_retries {
        config.event_cache_num_retries = cli_args.event_cache_num_retries;
    }
    if cli_args.event_cache_retry_delay != default_config.event_cache_retry_delay {
        config.event_cache_retry_delay = cli_args.event_cache_retry_delay;
    }
    if cli_args.compatibility_syscall64_size_type
        != default_config.compatibility_syscall64_size_type
    {
        config.compatibility_syscall64_size_type = cli_args.compatibility_syscall64_size_type;
    }
    if cli_args.log_level != default_config.log_level {
        config.log_level = cli_args.log_level;
    }
    if cli_args.log_format != default_config.log_format {
        config.log_format = cli_args.log_format;
    }
    if cli_args.export_allowlist != default_config.export_allowlist {
        config.export_allowlist = cli_args.export_allowlist;
    }
    if cli_args.export_denylist != default_config.export_denylist {
        config.export_denylist = cli_args.export_denylist;
    }
    if cli_args.field_filters != default_config.field_filters {
        config.field_filters = cli_args.field_filters;
    }
    if cli_args.redaction_filters != default_config.redaction_filters {
        config.redaction_filters = cli_args.redaction_filters;
    }
    if cli_args.netns_dir != default_config.netns_dir {
        config.netns_dir = cli_args.netns_dir;
    }
    if cli_args.disable_uprobe_multi != default_config.disable_uprobe_multi {
        config.disable_uprobe_multi = cli_args.disable_uprobe_multi;
    }
    if cli_args.generate_docs != default_config.generate_docs {
        config.generate_docs = cli_args.generate_docs;
    }

    // Handle special case for config_dir override
    if let Some(config_dir) = config.config_dir.clone() {
        config = loader::load_from_dir(config, &config_dir).map_err(|e| {
            anyhow::anyhow!(
                "Failed to load config from directory '{}': {}",
                config_dir,
                e
            )
        })?;
        // Re-apply environment and CLI args after loading from custom dir
        config.merge_from_env();
        // TODO: Re-apply CLI args again here if needed
    }

    // 5. Validate the final configuration
    validation::validate(&config)
        .map_err(|e| anyhow::anyhow!("Configuration validation failed: {}", e))?;

    Ok(config)
}

/// Parse duration from string, returning None for empty/invalid input
fn parse_duration(s: &str) -> Result<Option<Duration>, String> {
    if s.is_empty() {
        return Ok(None);
    }

    humantime::parse_duration(s)
        .map(Some)
        .map_err(|e| format!("Invalid duration format: {}", e))
}

/// Parse duration from string, required (not optional)
fn parse_duration_required(s: &str) -> Result<Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("Invalid duration format: {}", e))
}
