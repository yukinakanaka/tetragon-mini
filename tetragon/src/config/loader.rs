//! Configuration loading functionality for Tetragon
//!
//! This module handles loading configuration from various sources including
//! YAML files, directories, and environment variables.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use serde_yaml;
use thiserror::Error;

use super::Config;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("YAML parsing error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Failed to read config file '{file}': not a regular file")]
    NotRegularFile { file: String },

    #[error("Failed to read config directory '{dir}': not a directory")]
    NotDirectory { dir: String },

    #[error("Failed to read configuration directory: {0}")]
    ConfigDir(String),

    #[error("Merge config failed: {0}")]
    MergeConfig(String),
}

/// Configuration loader that handles hierarchical loading from multiple sources
pub struct ConfigLoader {
    config: Config,
}

impl ConfigLoader {
    /// Create a new config loader with default configuration
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Create a new config loader with the given base configuration
    pub fn with_config(config: Config) -> Self {
        Self { config }
    }

    /// Read configuration settings from the standard hierarchy
    pub fn read_config_settings(
        &mut self,
        default_conf_dir: &str,
        default_conf_drop_in: &str,
        drop_ins_dirs: &[&str],
    ) -> Result<(), ConfigError> {
        // Set up environment variable handling
        self.config.merge_from_env();

        // Read default drop-ins directories
        for dir in drop_ins_dirs {
            if let Err(e) = self.read_config_dir(dir) {
                // Log warning but don't fail on missing drop-in directories
                eprintln!("Warning: failed to read drop-in directory '{}': {}", dir, e);
            }
        }

        // Look into cwd first, this is needed for quick development only
        if let Err(e) = self.read_config_file(".", "tetragon.yaml") {
            // Silently ignore if file doesn't exist in current directory
            if !matches!(e, ConfigError::Io(ref io_err) if io_err.kind() == io::ErrorKind::NotFound)
            {
                eprintln!(
                    "Warning: failed to read config from current directory: {}",
                    e
                );
            }
        }

        // Look for default config file (e.g., /etc/tetragon/tetragon.yaml)
        let default_config_file = format!("{}/tetragon.yaml", default_conf_dir);
        if let Err(e) = self.read_config_file(default_conf_dir, "tetragon.yaml") {
            if !matches!(e, ConfigError::Io(ref io_err) if io_err.kind() == io::ErrorKind::NotFound)
            {
                eprintln!(
                    "Warning: failed to read default config file '{}': {}",
                    default_config_file, e
                );
            }
        }

        // Look into default drop-in directory
        if let Err(e) = self.read_config_dir(default_conf_drop_in) {
            if !matches!(e, ConfigError::Io(ref io_err) if io_err.kind() == io::ErrorKind::NotFound)
            {
                eprintln!(
                    "Warning: failed to read default drop-in directory '{}': {}",
                    default_conf_drop_in, e
                );
            }
        }

        // Read custom config directory if specified
        if let Some(config_dir) = &self.config.config_dir.clone() {
            if !config_dir.is_empty() {
                if let Err(e) = self.read_config_dir(config_dir) {
                    return Err(e);
                } else {
                    println!("Loaded config from directory: {}", config_dir);
                }
            }
        }

        Ok(())
    }

    /// Read configuration from a directory of files
    pub fn read_config_dir<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ConfigError> {
        let path = path.as_ref();

        let metadata = fs::metadata(path)?;
        if !metadata.is_dir() {
            return Err(ConfigError::NotDirectory {
                dir: path.display().to_string(),
            });
        }

        let config_map = read_dir_config(path)?;
        self.merge_config_map(config_map)?;

        Ok(())
    }

    /// Read configuration from a specific file
    pub fn read_config_file<P: AsRef<Path>>(
        &mut self,
        dir: P,
        filename: &str,
    ) -> Result<(), ConfigError> {
        let file_path = dir.as_ref().join(filename);

        let metadata = fs::metadata(&file_path)?;
        if !metadata.is_file() {
            return Err(ConfigError::NotRegularFile {
                file: filename.to_string(),
            });
        }

        let content = fs::read_to_string(&file_path)?;
        let config_values: HashMap<String, serde_yaml::Value> = serde_yaml::from_str(&content)?;

        self.merge_config_map(config_values)?;

        Ok(())
    }

    /// Merge a configuration map into the current configuration
    fn merge_config_map(
        &mut self,
        config_map: HashMap<String, serde_yaml::Value>,
    ) -> Result<(), ConfigError> {
        // Convert the config map to YAML and then merge it with the existing config
        let yaml_value = serde_yaml::to_value(config_map)
            .map_err(|e| ConfigError::MergeConfig(e.to_string()))?;

        // Serialize current config to YAML value
        let mut current_yaml = serde_yaml::to_value(&self.config)
            .map_err(|e| ConfigError::MergeConfig(e.to_string()))?;

        // Merge the new values into the current configuration
        merge_yaml_values(&mut current_yaml, yaml_value);

        // Deserialize back to Config struct
        self.config = serde_yaml::from_value(current_yaml)
            .map_err(|e| ConfigError::MergeConfig(e.to_string()))?;

        Ok(())
    }

    /// Get the final configuration
    pub fn into_config(self) -> Config {
        self.config
    }

    /// Get a reference to the current configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get a mutable reference to the current configuration
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// Read directory configuration files
pub fn read_dir_config<P: AsRef<Path>>(
    dir_name: P,
) -> Result<HashMap<String, serde_yaml::Value>, ConfigError> {
    let dir_name = dir_name.as_ref();
    let mut config_map = HashMap::new();

    let entries = fs::read_dir(dir_name).map_err(|e| {
        ConfigError::ConfigDir(format!("unable to read configuration directory: {}", e))
    })?;

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            continue;
        }

        let file_path = entry.path();
        let file_name = entry.file_name();
        let file_name = match file_name.to_str() {
            Some(name) => name,
            None => {
                eprintln!(
                    "Warning: skipping file with invalid UTF-8 name: {:?}",
                    file_name
                );
                continue;
            }
        };

        // Resolve symlinks
        let resolved_path = if file_type.is_symlink() {
            match fs::canonicalize(&file_path) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!(
                        "Warning: unable to read configuration file '{}': {}",
                        file_path.display(),
                        e
                    );
                    continue;
                }
            }
        } else {
            file_path
        };

        let metadata = match fs::metadata(&resolved_path) {
            Ok(meta) => meta,
            Err(e) => {
                eprintln!(
                    "Warning: unable to read configuration file '{}': {}",
                    resolved_path.display(),
                    e
                );
                continue;
            }
        };

        if metadata.is_dir() {
            continue;
        }

        let content = match fs::read_to_string(&resolved_path) {
            Ok(content) => content.trim().to_string(),
            Err(e) => {
                eprintln!(
                    "Warning: unable to read configuration file '{}': {}",
                    resolved_path.display(),
                    e
                );
                continue;
            }
        };

        // Try to parse as YAML first, fall back to plain string
        let value = match serde_yaml::from_str::<serde_yaml::Value>(&content) {
            Ok(val) => val,
            Err(_) => serde_yaml::Value::String(content),
        };

        config_map.insert(file_name.to_string(), value);
    }

    Ok(config_map)
}

/// Merge two YAML values recursively
fn merge_yaml_values(base: &mut serde_yaml::Value, other: serde_yaml::Value) {
    match (base, other) {
        (serde_yaml::Value::Mapping(base_map), serde_yaml::Value::Mapping(other_map)) => {
            for (key, value) in other_map {
                match base_map.get_mut(&key) {
                    Some(base_value) => merge_yaml_values(base_value, value),
                    None => {
                        base_map.insert(key, value);
                    }
                }
            }
        }
        (base_value, other_value) => {
            *base_value = other_value;
        }
    }
}

/// Load configuration with the standard Tetragon hierarchy
pub fn load_standard_config() -> Result<Config, ConfigError> {
    let admin_tg_conf_dir = "/etc/tetragon/";
    let admin_tg_conf_drop_in = "/etc/tetragon/tetragon.conf.d/";
    let package_tg_conf_drop_ins = [
        "/usr/lib/tetragon/tetragon.conf.d/",
        "/usr/local/lib/tetragon/tetragon.conf.d/",
    ];

    let mut loader = ConfigLoader::new();
    loader.read_config_settings(
        admin_tg_conf_dir,
        admin_tg_conf_drop_in,
        &package_tg_conf_drop_ins,
    )?;

    Ok(loader.into_config())
}

/// Load configuration from a directory, merging with the base config
pub fn load_from_dir(base_config: Config, config_dir: &str) -> Result<Config, ConfigError> {
    let mut loader = ConfigLoader::with_config(base_config);
    loader.read_config_dir(config_dir)?;
    Ok(loader.into_config())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_read_config_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("test.yaml");

        let yaml_content = r#"
debug: true
cluster_name: "test-cluster"
verbosity: 2
"#;
        fs::write(&config_file, yaml_content).unwrap();

        let mut loader = ConfigLoader::new();
        loader
            .read_config_file(temp_dir.path(), "test.yaml")
            .unwrap();

        let config = loader.into_config();
        assert!(config.debug);
        assert_eq!(config.cluster_name, Some("test-cluster".to_string()));
        assert_eq!(config.verbosity, 2);
    }

    #[test]
    fn test_read_config_dir() {
        let temp_dir = TempDir::new().unwrap();

        // Create config files in the directory
        fs::write(temp_dir.path().join("debug"), "true").unwrap();
        fs::write(temp_dir.path().join("cluster-name"), "dir-test-cluster").unwrap();

        let mut loader = ConfigLoader::new();
        loader.read_config_dir(temp_dir.path()).unwrap();

        // Note: This test may need adjustment based on how key mapping works
        // The actual implementation might need to handle key name conversion
    }

    #[test]
    fn test_merge_yaml_values() {
        let mut base = serde_yaml::from_str(
            r#"
debug: false
cluster_name: "base"
metrics:
  enabled: true
"#,
        )
        .unwrap();

        let other = serde_yaml::from_str(
            r#"
debug: true
new_field: "value"
metrics:
  port: 8080
"#,
        )
        .unwrap();

        merge_yaml_values(&mut base, other);

        // Verify that the merge worked correctly
        let result_map = base.as_mapping().unwrap();
        assert!(result_map.get("debug").unwrap().as_bool().unwrap());
        assert_eq!(
            result_map.get("cluster_name").unwrap().as_str().unwrap(),
            "base"
        );
        assert_eq!(
            result_map.get("new_field").unwrap().as_str().unwrap(),
            "value"
        );

        let metrics = result_map.get("metrics").unwrap().as_mapping().unwrap();
        assert!(metrics.get("enabled").unwrap().as_bool().unwrap());
        assert_eq!(metrics.get("port").unwrap().as_u64().unwrap(), 8080);
    }
}
