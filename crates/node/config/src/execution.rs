//! Execution configuration.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

/// Default gas limit per block.
pub const DEFAULT_GAS_LIMIT: u64 = 250_000_000;

/// Default QMDB page cache size in number of pages (4096 pages * 16 KB = 64 MB per partition).
pub const DEFAULT_QMDB_PAGE_CACHE_SIZE: usize = 4_096;

/// Initial base fee per gas (1 gwei).
///
/// EIP-1559 base-fee accounting requires a non-zero seed value; starting
/// from zero means `calculate_base_fee` can never increase the fee because
/// `0 * anything = 0`. One gwei is the Ethereum-mainnet genesis value and
/// a reasonable default for devnets.
pub const INITIAL_BASE_FEE: u64 = 1_000_000_000;

/// Execution layer configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionConfig {
    /// Maximum gas per block.
    #[serde(default = "default_gas_limit")]
    pub gas_limit: u64,

    /// Address that receives priority fees (tips) from transactions.
    ///
    /// When set, this address is used as the `beneficiary` in the block
    /// header, causing EIP-1559 priority fees to be credited to it.
    /// When `None` (the default), `Address::ZERO` is used, which
    /// effectively burns all priority fees.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_address",
        deserialize_with = "deserialize_optional_address"
    )]
    pub fee_recipient: Option<Address>,

    /// Number of pages in the QMDB page cache (per partition).
    ///
    /// Each page is 16 KB. The default of 4096 pages gives 64 MB per partition
    /// (192 MB total across accounts, storage, and code). Increase for
    /// production workloads with large state; decrease for memory-constrained
    /// devnet nodes.
    #[serde(default = "default_qmdb_page_cache_size")]
    pub qmdb_page_cache_size: usize,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            gas_limit: DEFAULT_GAS_LIMIT,
            fee_recipient: None,
            qmdb_page_cache_size: DEFAULT_QMDB_PAGE_CACHE_SIZE,
        }
    }
}

const fn default_gas_limit() -> u64 {
    DEFAULT_GAS_LIMIT
}

const fn default_qmdb_page_cache_size() -> usize {
    DEFAULT_QMDB_PAGE_CACHE_SIZE
}

fn serialize_optional_address<S>(addr: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match addr {
        Some(a) => serializer.serialize_str(&format!("{a:#x}")),
        None => serializer.serialize_none(),
    }
}

fn deserialize_optional_address<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    opt.map_or_else(
        || Ok(None),
        |s| {
            let s = s.trim();
            s.parse::<Address>().map(Some).map_err(serde::de::Error::custom)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_execution_config() {
        let config = ExecutionConfig::default();
        assert_eq!(config.gas_limit, DEFAULT_GAS_LIMIT);
        assert_eq!(config.fee_recipient, None);
        assert_eq!(config.qmdb_page_cache_size, DEFAULT_QMDB_PAGE_CACHE_SIZE);
    }

    #[test]
    fn test_execution_config_serde_roundtrip() {
        let config = ExecutionConfig {
            gas_limit: 300_000_000,
            fee_recipient: None,
            qmdb_page_cache_size: DEFAULT_QMDB_PAGE_CACHE_SIZE,
        };
        let serialized = serde_json::to_string(&config).expect("serialize");
        let deserialized: ExecutionConfig = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_execution_config_toml_roundtrip() {
        let config = ExecutionConfig {
            gas_limit: 150_000_000,
            fee_recipient: None,
            qmdb_page_cache_size: DEFAULT_QMDB_PAGE_CACHE_SIZE,
        };
        let serialized = toml::to_string(&config).expect("serialize toml");
        let deserialized: ExecutionConfig = toml::from_str(&serialized).expect("deserialize toml");
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_execution_config_serde_defaults() {
        let config: ExecutionConfig = serde_json::from_str("{}").expect("deserialize");
        assert_eq!(config.gas_limit, DEFAULT_GAS_LIMIT);
        assert_eq!(config.fee_recipient, None);
        assert_eq!(config.qmdb_page_cache_size, DEFAULT_QMDB_PAGE_CACHE_SIZE);
    }

    #[test]
    fn test_execution_config_partial_defaults() {
        let config: ExecutionConfig =
            serde_json::from_str(r#"{"gas_limit": 10000000}"#).expect("deserialize");
        assert_eq!(config.gas_limit, 10_000_000);
        assert_eq!(config.fee_recipient, None);
        assert_eq!(config.qmdb_page_cache_size, DEFAULT_QMDB_PAGE_CACHE_SIZE);
    }

    #[test]
    fn initial_base_fee_is_one_gwei() {
        assert_eq!(INITIAL_BASE_FEE, 1_000_000_000);
    }

    #[test]
    fn test_execution_config_clone_and_eq() {
        let config = ExecutionConfig {
            gas_limit: 999,
            fee_recipient: None,
            qmdb_page_cache_size: DEFAULT_QMDB_PAGE_CACHE_SIZE,
        };
        assert_eq!(config, config.clone());
        assert_ne!(config, ExecutionConfig::default());
    }

    #[test]
    fn test_fee_recipient_json_roundtrip() {
        let addr = "0xdead000000000000000000000000000000000001".parse::<Address>().unwrap();
        let config = ExecutionConfig { fee_recipient: Some(addr), ..ExecutionConfig::default() };
        let serialized = serde_json::to_string(&config).expect("serialize");
        assert!(serialized.contains("0xdead"));
        let deserialized: ExecutionConfig = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_fee_recipient_toml_roundtrip() {
        let addr = "0xdead000000000000000000000000000000000001".parse::<Address>().unwrap();
        let config = ExecutionConfig { fee_recipient: Some(addr), ..ExecutionConfig::default() };
        let serialized = toml::to_string(&config).expect("serialize toml");
        let deserialized: ExecutionConfig = toml::from_str(&serialized).expect("deserialize toml");
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_fee_recipient_none_omitted_from_json() {
        let config = ExecutionConfig::default();
        let serialized = serde_json::to_string(&config).expect("serialize");
        assert!(!serialized.contains("fee_recipient"));
    }
}
