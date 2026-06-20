//! Top-level node configuration.

use std::path::{Path, PathBuf};

use commonware_codec::ReadExt as _;
use serde::{Deserialize, Serialize};

use crate::{ConfigError, ConsensusConfig, ExecutionConfig, NetworkConfig, RpcConfig};

/// Default chain ID for local development.
///
/// Uses 1337 (standard devnet chain ID) to avoid colliding with
/// Ethereum mainnet (chain_id=1) and the associated EIP-155 replay risk.
pub const DEFAULT_CHAIN_ID: u64 = 1337;

/// Default data directory.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/kora";

/// Default cap for worker threads.
pub const DEFAULT_WORKER_THREADS_CAP: usize = 8;

/// Complete node configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    /// Chain ID for the network.
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,

    /// Data directory for persistent storage.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,

    /// Number of tokio async worker threads for the commonware runtime.
    ///
    /// Defaults to the number of available CPU cores, capped at 8.
    /// Set explicitly in config to override.
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    /// Consensus configuration.
    #[serde(default)]
    pub consensus: ConsensusConfig,

    /// Network configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Execution configuration.
    #[serde(default)]
    pub execution: ExecutionConfig,

    /// RPC configuration.
    #[serde(default)]
    pub rpc: RpcConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID,
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            worker_threads: default_worker_threads(),
            consensus: ConsensusConfig::default(),
            network: NetworkConfig::default(),
            execution: ExecutionConfig::default(),
            rpc: RpcConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Validate configuration values.
    ///
    /// Returns an error if any value is out of range or consensus parameters
    /// are internally inconsistent.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.worker_threads == 0 {
            return Err(ConfigError::InvalidValue("worker_threads must be >= 1".to_string()));
        }

        // Validate chain_id is not zero (invalid per EIP-155).
        if self.chain_id == 0 {
            return Err(ConfigError::InvalidValue("chain_id must not be 0".to_string()));
        }

        // Cross-check consensus parameters when participants are configured.
        if !self.consensus.participants.is_empty() {
            if self.consensus.threshold == 0 {
                return Err(ConfigError::InvalidValue(
                    "consensus.threshold must be >= 1 when participants are configured".to_string(),
                ));
            }
            if self.consensus.threshold > self.consensus.participants.len() as u32 {
                return Err(ConfigError::InvalidValue(format!(
                    "consensus.threshold ({}) exceeds participant count ({})",
                    self.consensus.threshold,
                    self.consensus.participants.len()
                )));
            }
        }

        Ok(())
    }

    /// Load configuration from a file path, auto-detecting format by extension.
    ///
    /// If the path is `None`, returns the default configuration.
    /// Supported extensions: `.json` for JSON, all others default to TOML.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let config = path.map_or_else(
            || Ok(Self::default()),
            |p| {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("toml");
                match ext {
                    "json" => Self::from_json_file(p),
                    _ => Self::from_toml_file(p),
                }
            },
        )?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from a TOML file.
    pub fn from_toml_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read { path: path.into(), source: e })?;
        Self::from_toml(&contents)
    }

    /// Parse configuration from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        Ok(toml::from_str(s)?)
    }

    /// Load configuration from a JSON file.
    pub fn from_json_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read { path: path.into(), source: e })?;
        Self::from_json(&contents)
    }

    /// Parse configuration from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, ConfigError> {
        Ok(serde_json::from_str(s)?)
    }

    /// Serialize configuration to a TOML string.
    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Serialize configuration to a JSON string.
    pub fn to_json(&self) -> Result<String, ConfigError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Get or create the validator private key from `{data_dir}/validator.key`.
    pub fn validator_key(
        &self,
    ) -> Result<commonware_cryptography::ed25519::PrivateKey, ConfigError> {
        let key_path = self
            .consensus
            .validator_key
            .clone()
            .unwrap_or_else(|| self.data_dir.join("validator.key"));

        // Try to load existing key
        match std::fs::read(&key_path) {
            Ok(key_bytes) => {
                if key_bytes.len() != 32 {
                    return Err(ConfigError::InvalidKeyLength(key_bytes.len()));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&key_bytes);
                Ok(private_key_from_seed(seed))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Generate new key -- warn prominently so operators notice in production
                tracing::warn!(
                    path = %key_path.display(),
                    "Validator key not found -- generating a new random key. \
                     This is only appropriate for development. In production, \
                     provide an existing key file via 'consensus.validator_key' in config."
                );
                let mut seed = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);

                // Ensure parent directory exists
                if let Some(parent) = key_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| ConfigError::CreateDir {
                        path: parent.to_path_buf(),
                        source: e,
                    })?;
                }

                // Write key to disk with restrictive permissions (0600)
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&key_path)
                        .map_err(|e| ConfigError::Write { path: key_path.clone(), source: e })?;
                    std::io::Write::write_all(&mut f, &seed)
                        .map_err(|e| ConfigError::Write { path: key_path.clone(), source: e })?;
                }

                Ok(private_key_from_seed(seed))
            }
            Err(e) => Err(ConfigError::Read { path: key_path, source: e }),
        }
    }

    /// Get the validator public key.
    pub fn validator_public_key(
        &self,
    ) -> Result<commonware_cryptography::ed25519::PublicKey, ConfigError> {
        use commonware_cryptography::Signer as _;
        Ok(self.validator_key()?.public_key())
    }
}

fn private_key_from_seed(seed: [u8; 32]) -> commonware_cryptography::ed25519::PrivateKey {
    commonware_cryptography::ed25519::PrivateKey::read(&mut seed.as_slice())
        .expect("32-byte ed25519 seed should decode")
}

const fn default_chain_id() -> u64 {
    DEFAULT_CHAIN_ID
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR)
}

fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(DEFAULT_WORKER_THREADS_CAP))
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.data_dir, PathBuf::from(DEFAULT_DATA_DIR));
        assert!(config.worker_threads >= 1);
        assert!(config.worker_threads <= DEFAULT_WORKER_THREADS_CAP);
    }

    #[test]
    fn test_worker_threads_default_from_toml() {
        // A TOML config without worker_threads should get the default.
        let config = NodeConfig::from_toml("chain_id = 1337\n").unwrap();
        assert!(config.worker_threads >= 1);
        assert!(config.worker_threads <= DEFAULT_WORKER_THREADS_CAP);
    }

    #[test]
    fn test_worker_threads_explicit() {
        let config = NodeConfig::from_toml("worker_threads = 6\n").unwrap();
        assert_eq!(config.worker_threads, 6);
    }

    #[test]
    fn test_worker_threads_zero_rejected() {
        let config = NodeConfig::from_toml("worker_threads = 0\n").unwrap();
        let err = config.validate();
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("worker_threads"));
    }

    #[test]
    fn test_load_rejects_zero_worker_threads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "worker_threads = 0\n").unwrap();
        assert!(NodeConfig::load(Some(&path)).is_err());
    }

    #[test]
    fn test_toml_roundtrip() {
        let config = NodeConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed = NodeConfig::from_toml(&toml_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_json_roundtrip() {
        let config = NodeConfig::default();
        let json_str = config.to_json().unwrap();
        let parsed = NodeConfig::from_json(&json_str).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_load_none_returns_default() {
        let config = NodeConfig::load(None).unwrap();
        assert_eq!(config, NodeConfig::default());
    }

    #[test]
    fn test_load_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let expected = NodeConfig { chain_id: 42, ..Default::default() };
        std::fs::write(&path, expected.to_toml().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 42);
    }

    #[test]
    fn test_load_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let expected = NodeConfig { chain_id: 99, ..Default::default() };
        std::fs::write(&path, expected.to_json().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 99);
    }

    #[test]
    fn test_load_unknown_extension_defaults_to_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.conf");
        let expected = NodeConfig { chain_id: 77, ..Default::default() };
        std::fs::write(&path, expected.to_toml().unwrap()).unwrap();

        let loaded = NodeConfig::load(Some(&path)).unwrap();
        assert_eq!(loaded.chain_id, 77);
    }

    #[test]
    fn test_load_missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.toml");
        assert!(NodeConfig::load(Some(&path)).is_err());
    }

    #[test]
    fn test_chain_id_zero_rejected() {
        let config = NodeConfig { chain_id: 0, ..Default::default() };
        let err = config.validate();
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("chain_id"));
    }

    #[test]
    fn test_threshold_exceeds_participants_rejected() {
        let config = NodeConfig {
            consensus: crate::ConsensusConfig {
                threshold: 5,
                participants: vec![vec![0u8; 32], vec![1u8; 32]],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = config.validate();
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("exceeds participant count"));
    }

    #[test]
    fn test_default_chain_id_is_1337() {
        assert_eq!(DEFAULT_CHAIN_ID, 1337);
    }
}
