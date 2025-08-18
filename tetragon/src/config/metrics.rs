//! Metrics configuration and label filtering functionality

use std::collections::HashMap;

/// Label filter for metrics
#[derive(Debug, Clone)]
pub struct LabelFilter {
    filters: HashMap<String, bool>,
}

impl LabelFilter {
    /// Create a new label filter
    pub fn new() -> Self {
        Self {
            filters: HashMap::new(),
        }
    }

    /// Create a label filter with enabled labels
    pub fn with_enabled_labels(labels: Vec<String>) -> Self {
        let mut filters = HashMap::new();
        for label in labels {
            filters.insert(label, true);
        }
        Self { filters }
    }

    /// Check if a label is enabled
    pub fn is_enabled(&self, label: &str) -> bool {
        self.filters.get(label).copied().unwrap_or(false)
    }

    /// Enable a label
    pub fn enable(&mut self, label: &str) {
        self.filters.insert(label.to_string(), true);
    }

    /// Disable a label
    pub fn disable(&mut self, label: &str) {
        self.filters.insert(label.to_string(), false);
    }

    /// Get all enabled labels
    pub fn enabled_labels(&self) -> Vec<String> {
        self.filters
            .iter()
            .filter_map(
                |(label, &enabled)| {
                    if enabled {
                        Some(label.clone())
                    } else {
                        None
                    }
                },
            )
            .collect()
    }
}

impl Default for LabelFilter {
    fn default() -> Self {
        default_label_filter()
    }
}

/// Create the default label filter with standard labels enabled
pub fn default_label_filter() -> LabelFilter {
    let mut filters = HashMap::new();
    filters.insert("namespace".to_string(), true);
    filters.insert("workload".to_string(), true);
    filters.insert("pod".to_string(), true);
    filters.insert("binary".to_string(), true);

    LabelFilter { filters }
}

/// Parse metrics label filter from comma-separated string
pub fn parse_metrics_label_filter(labels_string: &str) -> Vec<String> {
    labels_string
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Process labels for metrics collection
#[derive(Debug, Clone, Default)]
pub struct ProcessLabels {
    pub namespace: String,
    pub workload: String,
    pub pod: String,
    pub binary: String,
}

impl ProcessLabels {
    /// Create new process labels
    pub fn new(namespace: String, workload: String, pod: String, binary: String) -> Self {
        Self {
            namespace,
            workload,
            pod,
            binary,
        }
    }

    /// Create process labels with the global labels filter applied
    pub fn create_filtered(
        filter: &LabelFilter,
        namespace: String,
        workload: String,
        pod: String,
        binary: String,
    ) -> Self {
        Self {
            namespace: if filter.is_enabled("namespace") {
                namespace
            } else {
                String::new()
            },
            workload: if filter.is_enabled("workload") {
                workload
            } else {
                String::new()
            },
            pod: if filter.is_enabled("pod") {
                pod
            } else {
                String::new()
            },
            binary: if filter.is_enabled("binary") {
                binary
            } else {
                String::new()
            },
        }
    }

    /// Convert to a vector of label values for metric collection
    pub fn to_values(&self) -> Vec<&str> {
        vec![&self.namespace, &self.workload, &self.pod, &self.binary]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_label_filter() {
        let filter = default_label_filter();
        assert!(filter.is_enabled("namespace"));
        assert!(filter.is_enabled("workload"));
        assert!(filter.is_enabled("pod"));
        assert!(filter.is_enabled("binary"));
        assert!(!filter.is_enabled("unknown"));
    }

    #[test]
    fn test_parse_metrics_label_filter() {
        let labels = parse_metrics_label_filter("namespace, workload,pod,  binary  ");
        assert_eq!(labels, vec!["namespace", "workload", "pod", "binary"]);

        let empty_labels = parse_metrics_label_filter("");
        assert!(empty_labels.is_empty());

        let single_label = parse_metrics_label_filter("namespace");
        assert_eq!(single_label, vec!["namespace"]);
    }

    #[test]
    fn test_label_filter_operations() {
        let mut filter = LabelFilter::new();
        assert!(!filter.is_enabled("test"));

        filter.enable("test");
        assert!(filter.is_enabled("test"));

        filter.disable("test");
        assert!(!filter.is_enabled("test"));
    }

    #[test]
    fn test_process_labels_filtering() {
        let mut filter = LabelFilter::new();
        filter.enable("namespace");
        filter.enable("binary");
        // workload and pod are disabled

        let labels = ProcessLabels::create_filtered(
            &filter,
            "default".to_string(),
            "my-workload".to_string(),
            "my-pod".to_string(),
            "my-binary".to_string(),
        );

        assert_eq!(labels.namespace, "default");
        assert_eq!(labels.workload, ""); // disabled
        assert_eq!(labels.pod, ""); // disabled
        assert_eq!(labels.binary, "my-binary");
    }

    #[test]
    fn test_process_labels_to_values() {
        let labels = ProcessLabels::new(
            "default".to_string(),
            "workload".to_string(),
            "pod".to_string(),
            "binary".to_string(),
        );

        let values = labels.to_values();
        assert_eq!(values, vec!["default", "workload", "pod", "binary"]);
    }
}
