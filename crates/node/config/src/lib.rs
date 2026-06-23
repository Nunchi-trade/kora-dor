//! Configuration types for Kora nodes.
#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/refcell/kora/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod consensus;
pub use consensus::{
    ConsensusBlockCodecConfig, ConsensusConfig, ConsensusSimplexConfig,
    DEFAULT_BLOCK_CODEC_MAX_TX_BYTES, DEFAULT_BLOCK_CODEC_MAX_TXS,
    DEFAULT_SIMPLEX_ACTIVITY_TIMEOUT_VIEWS, DEFAULT_SIMPLEX_CERTIFICATION_TIMEOUT_SECS,
    DEFAULT_SIMPLEX_FETCH_CONCURRENT, DEFAULT_SIMPLEX_FETCH_TIMEOUT_SECS,
    DEFAULT_SIMPLEX_LEADER_TIMEOUT_SECS, DEFAULT_SIMPLEX_REPLAY_BUFFER_BYTES,
    DEFAULT_SIMPLEX_SKIP_TIMEOUT_VIEWS, DEFAULT_SIMPLEX_TIMEOUT_RETRY_SECS,
    DEFAULT_SIMPLEX_WRITE_BUFFER_BYTES, DEFAULT_THRESHOLD,
};

mod error;
pub use error::ConfigError;

mod execution;
pub use execution::{
    DEFAULT_GAS_LIMIT, DEFAULT_QMDB_PAGE_CACHE_SIZE, ExecutionConfig, INITIAL_BASE_FEE,
};

mod network;
pub use network::{DEFAULT_LISTEN_ADDR, NetworkConfig};

mod node;
pub use node::{DEFAULT_CHAIN_ID, DEFAULT_DATA_DIR, DEFAULT_WORKER_THREADS_CAP, NodeConfig};

mod rpc;
pub use rpc::{DEFAULT_HTTP_ADDR, DEFAULT_WS_ADDR, RpcConfig};
