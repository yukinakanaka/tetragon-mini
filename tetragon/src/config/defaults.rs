//! Default values for Tetragon configuration

use std::time::Duration;

// Default paths and directories
pub const DEFAULT_MAP_ROOT: &str = "/sys/fs/bpf";
pub const DEFAULT_MAP_PREFIX: &str = "tetragon";
pub const DEFAULT_EVENT_MAP: &str = "tcpmon";
pub const DEFAULT_MAP_ROOT_FALLBACK: &str = "/run/cilium/bpffs";
pub const DEFAULT_RUN_DIR: &str = "/var/run/tetragon/";
pub const CGROUP2_DIR: &str = "/run/tetragon/cgroup2";
pub const DEFAULT_NETNS_DIR: &str = "/var/run/docker/netns/";
pub const DEFAULT_BTF_FILE: &str = "/sys/kernel/btf/vmlinux";
pub const DEFAULT_TETRAGON_LIB: &str = "/var/lib/tetragon/";
pub const INIT_INFO_FILE: &str = "/var/run/tetragon/tetragon-info.json";
pub const DEFAULT_TP_DIR: &str = "/etc/tetragon/tetragon.tp.d";
pub const DEFAULT_LOGS_PERMISSION: &str = "600";
pub const DEFAULT_PID_FILE: &str = "/var/run/tetragon/tetragon.pid";
pub const DEFAULT_PROCFS: &str = "/proc/";

// Default values for event cache
pub const DEFAULT_EVENT_CACHE_NUM_RETRIES: i32 = 15;
pub const DEFAULT_EVENT_CACHE_RETRY_DELAY: i32 = 2;

// Default numeric values
pub const DEFAULT_PROCESS_CACHE_SIZE: i32 = 65536;
pub const DEFAULT_DATA_CACHE_SIZE: i32 = 1024;
pub const DEFAULT_EXPORT_FILE_MAX_SIZE_MB: i32 = 10;
pub const DEFAULT_EXPORT_FILE_MAX_BACKUPS: i32 = 5;
pub const DEFAULT_EXPORT_RATE_LIMIT: i32 = -1;
pub const DEFAULT_EXPORT_AGGREGATION_BUFFER_SIZE: u64 = 10000;
pub const DEFAULT_EVENT_QUEUE_SIZE: u32 = 10000;
pub const DEFAULT_HEALTH_SERVER_INTERVAL: i32 = 10;

// Default string values
pub const DEFAULT_RB_QUEUE_SIZE: &str = "65535";
pub const DEFAULT_METRICS_LABEL_FILTER: &str = "namespace,workload,pod,binary";
pub const DEFAULT_SERVER_ADDRESS: &str = "localhost:54321";
pub const DEFAULT_LOG_LEVEL: &str = "info";
pub const DEFAULT_LOG_FORMAT: &str = "text";
pub const DEFAULT_HEALTH_SERVER_ADDRESS: &str = "localhost:6789";

// Default duration values
pub const DEFAULT_EXPORT_AGGREGATION_WINDOW_SIZE_SECS: u64 = 15;

// Default functions for serde defaults
pub fn default_procfs() -> String {
    DEFAULT_PROCFS.to_string()
}

pub fn default_btf_file() -> String {
    DEFAULT_BTF_FILE.to_string()
}

pub fn default_tetragon_lib() -> String {
    DEFAULT_TETRAGON_LIB.to_string()
}

pub fn default_map_prefix() -> String {
    DEFAULT_MAP_PREFIX.to_string()
}

pub fn default_rb_queue_size() -> String {
    DEFAULT_RB_QUEUE_SIZE.to_string()
}

pub fn default_process_cache_size() -> i32 {
    DEFAULT_PROCESS_CACHE_SIZE
}

pub fn default_data_cache_size() -> i32 {
    DEFAULT_DATA_CACHE_SIZE
}

pub fn default_metrics_label_filter() -> String {
    DEFAULT_METRICS_LABEL_FILTER.to_string()
}

pub fn default_server_address() -> String {
    DEFAULT_SERVER_ADDRESS.to_string()
}

pub fn default_tp_dir() -> String {
    DEFAULT_TP_DIR.to_string()
}

pub fn default_export_file_max_size_mb() -> i32 {
    DEFAULT_EXPORT_FILE_MAX_SIZE_MB
}

pub fn default_export_file_max_backups() -> i32 {
    DEFAULT_EXPORT_FILE_MAX_BACKUPS
}

pub fn default_export_rate_limit() -> i32 {
    DEFAULT_EXPORT_RATE_LIMIT
}

pub fn default_logs_permission() -> String {
    DEFAULT_LOGS_PERMISSION.to_string()
}

pub fn default_export_aggregation_window_size() -> Duration {
    Duration::from_secs(DEFAULT_EXPORT_AGGREGATION_WINDOW_SIZE_SECS)
}

pub fn default_export_aggregation_buffer_size() -> u64 {
    DEFAULT_EXPORT_AGGREGATION_BUFFER_SIZE
}

pub fn default_event_queue_size() -> u32 {
    DEFAULT_EVENT_QUEUE_SIZE
}

pub fn default_release_pinned() -> bool {
    true
}

pub fn default_enable_tracing_policy_crd() -> bool {
    true
}

pub fn default_health_server_address() -> String {
    DEFAULT_HEALTH_SERVER_ADDRESS.to_string()
}

pub fn default_health_server_interval() -> i32 {
    DEFAULT_HEALTH_SERVER_INTERVAL
}

pub fn default_enable_cg_tracker_id() -> bool {
    true
}

pub fn default_event_cache_num_retries() -> i32 {
    DEFAULT_EVENT_CACHE_NUM_RETRIES
}

pub fn default_event_cache_retry_delay() -> i32 {
    DEFAULT_EVENT_CACHE_RETRY_DELAY
}

pub fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

pub fn default_log_format() -> String {
    DEFAULT_LOG_FORMAT.to_string()
}

pub fn default_netns_dir() -> String {
    DEFAULT_NETNS_DIR.to_string()
}
