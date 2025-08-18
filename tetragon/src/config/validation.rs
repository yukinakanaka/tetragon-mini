//! Configuration validation functionality

use std::path::Path;
use thiserror::Error;

use super::Config;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Process cache GC interval must be greater than 0")]
    InvalidProcessCacheGCInterval,

    #[error("Invalid cgroup rate format: {0}")]
    InvalidCgroupRate(String),

    #[error("Invalid file permissions: {0}")]
    InvalidFilePermissions(String),

    #[error("Directory does not exist: {0}")]
    DirectoryNotFound(String),

    #[error("File does not exist: {0}")]
    FileNotFound(String),

    #[error("Invalid numeric value for {field}: {value}")]
    InvalidNumericValue { field: String, value: String },

    #[error("Conflicting options: {0}")]
    ConflictingOptions(String),

    #[error("Required field missing: {0}")]
    RequiredFieldMissing(String),
}

/// Trait for configuration validation
pub trait Validate {
    /// Validate the configuration and return any errors
    fn validate(&self) -> Result<(), ValidationError>;
}

impl Validate for Config {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate conflicting program size options
        if self.force_small_progs && self.force_large_progs {
            return Err(ValidationError::ConflictingOptions(
                "cannot set both force-small-progs and force-large-progs".to_string(),
            ));
        }

        // Validate cgroup rate format if specified
        if let Some(cgroup_rate) = &self.cgroup_rate {
            if self.parse_cgroup_rate().is_none() {
                return Err(ValidationError::InvalidCgroupRate(cgroup_rate.clone()));
            }
        }

        // Validate file permissions format
        if !is_valid_file_permissions(&self.export_file_perm) {
            return Err(ValidationError::InvalidFilePermissions(
                self.export_file_perm.clone(),
            ));
        }

        // Validate numeric ranges
        if self.process_cache_size <= 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "process-cache-size".to_string(),
                value: self.process_cache_size.to_string(),
            });
        }

        if self.data_cache_size <= 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "data-cache-size".to_string(),
                value: self.data_cache_size.to_string(),
            });
        }

        if self.verbosity < 0 || self.verbosity > 2 {
            return Err(ValidationError::InvalidNumericValue {
                field: "verbosity".to_string(),
                value: self.verbosity.to_string(),
            });
        }

        // Validate export file settings
        if self.export_file_max_size_mb <= 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "export-file-max-size-mb".to_string(),
                value: self.export_file_max_size_mb.to_string(),
            });
        }

        if self.export_file_max_backups < 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "export-file-max-backups".to_string(),
                value: self.export_file_max_backups.to_string(),
            });
        }

        // Validate event queue size
        if self.event_queue_size == 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "event-queue-size".to_string(),
                value: self.event_queue_size.to_string(),
            });
        }

        // Validate health server interval
        if self.health_server_interval <= 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "health-server-interval".to_string(),
                value: self.health_server_interval.to_string(),
            });
        }

        // Validate event cache settings
        if self.event_cache_num_retries < 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "event-cache-retries".to_string(),
                value: self.event_cache_num_retries.to_string(),
            });
        }

        if self.event_cache_retry_delay < 0 {
            return Err(ValidationError::InvalidNumericValue {
                field: "event-cache-retry-delay".to_string(),
                value: self.event_cache_retry_delay.to_string(),
            });
        }

        // Validate directories exist if specified
        self.validate_directories()?;

        // Validate files exist if specified
        self.validate_files()?;

        Ok(())
    }
}

impl Config {
    /// Validate that specified directories exist
    fn validate_directories(&self) -> Result<(), ValidationError> {
        let directories = [
            (&self.procfs, "procfs"),
            (&self.tracing_policy_dir, "tracing-policy-dir"),
            (&self.netns_dir, "netns-dir"),
        ];

        for (dir, field_name) in directories {
            if !dir.is_empty() && !Path::new(dir).is_dir() {
                // Only validate if the directory is expected to exist
                // Some directories might be created at runtime
                if should_validate_directory_existence(field_name) {
                    return Err(ValidationError::DirectoryNotFound(dir.clone()));
                }
            }
        }

        // Validate config directory if specified
        if let Some(config_dir) = &self.config_dir {
            if !config_dir.is_empty() && !Path::new(config_dir).is_dir() {
                return Err(ValidationError::DirectoryNotFound(config_dir.clone()));
            }
        }

        Ok(())
    }

    /// Validate that specified files exist
    fn validate_files(&self) -> Result<(), ValidationError> {
        // Validate btf file (String type)
        if !self.btf.is_empty()
            && !Path::new(&self.btf).is_file()
            && should_validate_file_existence("btf")
        {
            return Err(ValidationError::FileNotFound(self.btf.clone()));
        }

        // Validate tracing_policy file (Option<String> type)
        if let Some(tracing_policy) = &self.tracing_policy {
            if !tracing_policy.is_empty()
                && !Path::new(tracing_policy).is_file()
                && should_validate_file_existence("tracing-policy")
            {
                return Err(ValidationError::FileNotFound(tracing_policy.clone()));
            }
        }

        // Validate k8s_kubeconfig_path file (Option<String> type)
        if let Some(k8s_kubeconfig_path) = &self.k8s_kubeconfig_path {
            if !k8s_kubeconfig_path.is_empty()
                && !Path::new(k8s_kubeconfig_path).is_file()
                && should_validate_file_existence("k8s-kubeconfig-path")
            {
                return Err(ValidationError::FileNotFound(k8s_kubeconfig_path.clone()));
            }
        }

        Ok(())
    }
}

/// Check if file permissions string is valid (octal format)
fn is_valid_file_permissions(perm: &str) -> bool {
    if perm.is_empty() {
        return false;
    }

    // Check if it's a valid octal string (3 or 4 digits)
    if perm.len() != 3 && perm.len() != 4 {
        return false;
    }

    // Check if all characters are valid octal digits (0-7)
    perm.chars().all(|c| c.is_ascii_digit() && c <= '7')
}

/// Determine if we should validate directory existence for a given field
fn should_validate_directory_existence(field_name: &str) -> bool {
    match field_name {
        "procfs" => true, // /proc should always exist
        _ => false,       // Other directories might be created at runtime
    }
}

/// Determine if we should validate file existence for a given field
fn should_validate_file_existence(field_name: &str) -> bool {
    match field_name {
        "tracing-policy" => true,      // If specified, should exist
        "k8s-kubeconfig-path" => true, // If specified, should exist
        _ => false,                    // Other files might be optional or created at runtime
    }
}

/// Public function to validate a configuration
pub fn validate(config: &Config) -> Result<(), ValidationError> {
    config.validate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_conflicting_prog_size_options() {
        let mut config = Config::default();
        config.force_small_progs = true;
        config.force_large_progs = true;

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::ConflictingOptions(_))
        ));
    }

    #[test]
    fn test_invalid_process_cache_size() {
        let mut config = Config::default();
        config.process_cache_size = 0;

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::InvalidNumericValue { .. })
        ));
    }

    #[test]
    fn test_invalid_verbosity() {
        let mut config = Config::default();
        config.verbosity = 3; // Valid range is 0-2

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::InvalidNumericValue { .. })
        ));
    }

    #[test]
    fn test_valid_file_permissions() {
        assert!(is_valid_file_permissions("600"));
        assert!(is_valid_file_permissions("644"));
        assert!(is_valid_file_permissions("0600"));
        assert!(is_valid_file_permissions("0644"));

        assert!(!is_valid_file_permissions(""));
        assert!(!is_valid_file_permissions("60"));
        assert!(!is_valid_file_permissions("8000")); // 8 is not a valid octal digit
        assert!(!is_valid_file_permissions("999")); // 9 is not a valid octal digit
        assert!(!is_valid_file_permissions("12345")); // Too long
    }

    #[test]
    fn test_invalid_file_permissions() {
        let mut config = Config::default();
        config.export_file_perm = "999".to_string(); // Invalid octal

        let result = config.validate();
        assert!(matches!(
            result,
            Err(ValidationError::InvalidFilePermissions(_))
        ));
    }
}
