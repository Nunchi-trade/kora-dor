//! Ethereum JSON-RPC API implementation.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use alloy_consensus::{
    Transaction as _, TxEnvelope,
    transaction::{SignerRecoverable as _, to_eip155_value},
};
use alloy_eips::eip2718::Decodable2718 as _;
use alloy_primitives::{Address, B256, Bytes, U64, U256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use kora_domain::MempoolEvent;
use kora_txpool::TransactionPool;
use tokio::sync::RwLock;
use tracing::warn;

use crate::{
    error::RpcError,
    filters::{Filter, FilterChanges, FilterStore},
    state::NodeState,
    state_provider::StateProvider,
    subscription::{MempoolEventSender, PendingTxEvent, PendingTxEventSender, PendingTxInfo},
    types::{
        BlockNumberOrTag, BlockTag, BlockTransactions, CallRequest, RpcBlock, RpcLog, RpcLogFilter,
        RpcTransaction, RpcTransactionReceipt, SyncInfo, SyncStatus,
    },
};

const DEFAULT_GAS_ORACLE_BLOCKS: usize = 20;
const DEFAULT_GAS_ORACLE_PERCENTILE: u8 = 60;
const GWEI: u64 = 1_000_000_000;
const DEFAULT_MAX_GAS_PRICE: u64 = 500 * GWEI;

/// Maximum number of pending transactions to track in memory.
///
/// When the limit is reached, the oldest entries are evicted on the next
/// `send_raw_transaction` call. This prevents unbounded memory growth
/// under sustained load when transactions are submitted faster than they
/// are finalized and queried.
const MAX_PENDING_TXS: usize = 10_000;

/// Ethereum JSON-RPC API trait.
///
/// Defines the core eth_* methods required for Ethereum compatibility.
#[rpc(server, namespace = "eth")]
pub trait EthApi {
    /// Returns the chain ID.
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U64>;

    /// Returns the current block number.
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> RpcResult<U64>;

    /// Returns the balance of an account.
    #[method(name = "getBalance")]
    async fn get_balance(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U256>;

    /// Returns the nonce (transaction count) of an account.
    #[method(name = "getTransactionCount")]
    async fn get_transaction_count(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U64>;

    /// Returns the code at an address.
    #[method(name = "getCode")]
    async fn get_code(&self, address: Address, block: Option<BlockNumberOrTag>)
    -> RpcResult<Bytes>;

    /// Returns the value of a storage slot.
    #[method(name = "getStorageAt")]
    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U256>;

    /// Submits a raw transaction to the mempool.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, data: Bytes) -> RpcResult<B256>;

    /// Executes a call without creating a transaction.
    #[method(name = "call")]
    async fn call(&self, request: CallRequest, block: Option<BlockNumberOrTag>)
    -> RpcResult<Bytes>;

    /// Estimates gas for a transaction.
    #[method(name = "estimateGas")]
    async fn estimate_gas(
        &self,
        request: CallRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U64>;

    /// Returns a block by number.
    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(
        &self,
        block: BlockNumberOrTag,
        full_transactions: bool,
    ) -> RpcResult<Option<RpcBlock>>;

    /// Returns a block by hash.
    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(
        &self,
        hash: B256,
        full_transactions: bool,
    ) -> RpcResult<Option<RpcBlock>>;

    /// Returns a transaction by hash.
    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<RpcTransaction>>;

    /// Returns a transaction receipt by hash.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(&self, hash: B256)
    -> RpcResult<Option<RpcTransactionReceipt>>;

    /// Returns the current gas price.
    #[method(name = "gasPrice")]
    async fn gas_price(&self) -> RpcResult<U256>;

    /// Returns the max priority fee per gas.
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256>;

    /// Returns fee history.
    #[method(name = "feeHistory")]
    async fn fee_history(
        &self,
        block_count: U64,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory>;

    /// Returns the accounts owned by the client (empty for non-wallet nodes).
    #[method(name = "accounts")]
    async fn accounts(&self) -> RpcResult<Vec<Address>>;

    /// Returns protocol version.
    #[method(name = "protocolVersion")]
    async fn protocol_version(&self) -> RpcResult<String>;

    /// Returns syncing status.
    #[method(name = "syncing")]
    async fn syncing(&self) -> RpcResult<SyncStatus>;

    /// Returns logs matching the given filter.
    #[method(name = "getLogs")]
    async fn get_logs(&self, filter: RpcLogFilter) -> RpcResult<Vec<RpcLog>>;

    /// Creates a log filter.
    #[method(name = "newFilter")]
    async fn new_filter(&self, filter: RpcLogFilter) -> RpcResult<U256>;

    /// Creates a block filter.
    #[method(name = "newBlockFilter")]
    async fn new_block_filter(&self) -> RpcResult<U256>;

    /// Creates a pending transaction filter.
    #[method(name = "newPendingTransactionFilter")]
    async fn new_pending_transaction_filter(&self) -> RpcResult<U256>;

    /// Returns changes since the last poll for the given filter.
    #[method(name = "getFilterChanges")]
    async fn get_filter_changes(&self, filter_id: U256) -> RpcResult<FilterChanges>;

    /// Returns all logs matching the given log filter.
    #[method(name = "getFilterLogs")]
    async fn get_filter_logs(&self, filter_id: U256) -> RpcResult<Vec<RpcLog>>;

    /// Removes a filter.
    #[method(name = "uninstallFilter")]
    async fn uninstall_filter(&self, filter_id: U256) -> RpcResult<bool>;
}

/// Net namespace API.
#[rpc(server, namespace = "net")]
pub trait NetApi {
    /// Returns the network ID.
    #[method(name = "version")]
    fn version(&self) -> RpcResult<String>;

    /// Returns true if the client is listening for connections.
    #[method(name = "listening")]
    fn listening(&self) -> RpcResult<bool>;

    /// Returns the number of connected peers.
    #[method(name = "peerCount")]
    fn peer_count(&self) -> RpcResult<U64>;
}

/// Web3 namespace API.
#[rpc(server, namespace = "web3")]
pub trait Web3Api {
    /// Returns the client version.
    #[method(name = "clientVersion")]
    fn client_version(&self) -> RpcResult<String>;

    /// Returns the Keccak-256 hash of the given data.
    #[method(name = "sha3")]
    fn sha3(&self, data: Bytes) -> RpcResult<B256>;
}

/// Fee history response.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistory {
    /// Base fee per gas for each block.
    pub base_fee_per_gas: Vec<U256>,
    /// Gas used ratio for each block.
    pub gas_used_ratio: Vec<f64>,
    /// Oldest block number.
    pub oldest_block: U64,
    /// Reward percentiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward: Option<Vec<Vec<U256>>>,
}

/// Transaction submission callback type.
///
/// Called when a raw transaction is submitted via `eth_sendRawTransaction`.
/// Resolves successfully only if the transaction was accepted.
pub type TxSubmitFuture = Pin<Box<dyn Future<Output = Result<(), RpcError>> + Send>>;

/// Async transaction submission callback type.
pub type TxSubmitCallback = Arc<dyn Fn(Bytes) -> TxSubmitFuture + Send + Sync>;

/// Configuration for recent-block fee estimation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasOracleConfig {
    /// Number of recent blocks sampled by the oracle.
    pub blocks: usize,
    /// Percentile used when selecting sampled gas prices and priority fees.
    pub percentile: u8,
    /// Minimum total gas price returned by `eth_gasPrice`.
    pub min_price: U256,
    /// Maximum total gas price returned by `eth_gasPrice`.
    pub max_price: U256,
    /// Minimum priority fee returned by `eth_maxPriorityFeePerGas`.
    pub min_priority_fee: U256,
}

impl Default for GasOracleConfig {
    fn default() -> Self {
        Self {
            blocks: DEFAULT_GAS_ORACLE_BLOCKS,
            percentile: DEFAULT_GAS_ORACLE_PERCENTILE,
            min_price: U256::from(GWEI),
            max_price: U256::from(DEFAULT_MAX_GAS_PRICE),
            min_priority_fee: U256::from(GWEI),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct GasOracleEstimate {
    gas_price: U256,
    priority_fee: U256,
}

#[derive(Clone, Copy, Debug)]
struct CachedGasOracleEstimate {
    head: u64,
    estimate: GasOracleEstimate,
}

/// Ethereum API implementation with state provider.
pub struct EthApiImpl<S: StateProvider> {
    chain_id: u64,
    block_height: Arc<std::sync::atomic::AtomicU64>,
    tx_submit: Option<TxSubmitCallback>,
    state_provider: Arc<RwLock<S>>,
    pending_txs: Arc<RwLock<HashMap<B256, RpcTransaction>>>,
    pending_tx_broadcast: Option<PendingTxEventSender>,
    mempool_broadcast: Option<MempoolEventSender>,
    /// Transaction pool used for pending nonce lookups in
    /// `eth_getTransactionCount("pending")`.
    txpool: Option<TransactionPool>,
    gas_oracle_config: GasOracleConfig,
    gas_oracle_cache: Arc<RwLock<Option<CachedGasOracleEstimate>>>,
    /// Insertion-ordered record of pending transaction hashes so that
    /// `eth_getFilterChanges` for pending-tx filters can return hashes
    /// in arrival order rather than an arbitrary sorted order.
    pending_tx_order: Arc<RwLock<VecDeque<B256>>>,
    /// Cumulative count of entries evicted from the front of
    /// `pending_tx_order`. Filter cursors store an absolute index; this
    /// offset converts it to a position inside the (now shorter) deque.
    pending_tx_evicted: Arc<std::sync::atomic::AtomicUsize>,
    /// Maximum number of pending transactions to hold in memory before
    /// evicting the oldest entries.
    max_pending_txs: usize,
    filter_store: Arc<FilterStore>,
    /// Shared node state for sync status reporting.
    node_state: Option<NodeState>,
}

impl<S: StateProvider> std::fmt::Debug for EthApiImpl<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthApiImpl")
            .field("chain_id", &self.chain_id)
            .field("block_height", &self.block_height)
            .field("tx_submit", &self.tx_submit.is_some())
            .field("txpool", &self.txpool.is_some())
            .field("gas_oracle_config", &self.gas_oracle_config)
            .finish()
    }
}

impl<S: StateProvider + 'static> EthApiImpl<S> {
    /// Create a new Ethereum API implementation with a state provider.
    pub fn new(chain_id: u64, state_provider: S) -> Self {
        Self::from_parts(chain_id, state_provider, None, GasOracleConfig::default())
    }

    /// Create a new Ethereum API implementation with a transaction submission callback.
    pub fn with_tx_submit(chain_id: u64, state_provider: S, tx_submit: TxSubmitCallback) -> Self {
        Self::from_parts(chain_id, state_provider, Some(tx_submit), GasOracleConfig::default())
    }

    fn from_parts(
        chain_id: u64,
        state_provider: S,
        tx_submit: Option<TxSubmitCallback>,
        gas_oracle_config: GasOracleConfig,
    ) -> Self {
        Self {
            chain_id,
            block_height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            tx_submit,
            state_provider: Arc::new(RwLock::new(state_provider)),
            pending_txs: Arc::new(RwLock::new(HashMap::new())),
            pending_tx_broadcast: None,
            mempool_broadcast: None,
            txpool: None,
            gas_oracle_config,
            gas_oracle_cache: Arc::new(RwLock::new(None)),
            pending_tx_order: Arc::new(RwLock::new(VecDeque::new())),
            pending_tx_evicted: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_pending_txs: MAX_PENDING_TXS,
            filter_store: Arc::new(FilterStore::default()),
            node_state: None,
        }
    }

    /// Attach a pending transaction broadcast channel.
    #[must_use]
    pub fn with_pending_tx_broadcast(mut self, pending_tx_broadcast: PendingTxEventSender) -> Self {
        self.pending_tx_broadcast = Some(pending_tx_broadcast);
        self
    }

    /// Attach a Kora mempool event broadcast channel.
    #[must_use]
    pub fn with_mempool_broadcast(mut self, mempool_broadcast: MempoolEventSender) -> Self {
        self.mempool_broadcast = Some(mempool_broadcast);
        self
    }

    /// Attach a transaction pool for pending nonce lookups.
    ///
    /// When set, `eth_getTransactionCount("pending")` will return the
    /// next nonce after all pending mempool transactions, rather than
    /// the finalized on-chain nonce.
    #[must_use]
    pub fn with_txpool(mut self, txpool: TransactionPool) -> Self {
        self.txpool = Some(txpool);
        self
    }

    /// Attach shared node state for sync status reporting.
    #[must_use]
    pub fn with_node_state(mut self, node_state: NodeState) -> Self {
        self.node_state = Some(node_state);
        self
    }

    /// Override the maximum number of pending transactions held in memory.
    #[cfg(test)]
    const fn with_max_pending_txs(mut self, max_pending_txs: usize) -> Self {
        self.max_pending_txs = max_pending_txs;
        self
    }

    /// Override the default recent-block gas oracle configuration.
    pub fn with_gas_oracle_config(mut self, gas_oracle_config: GasOracleConfig) -> Self {
        self.gas_oracle_config = gas_oracle_config;
        self.gas_oracle_cache = Arc::new(RwLock::new(None));
        self
    }

    /// Get a handle to update the block height.
    pub fn block_height_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.block_height.clone()
    }

    /// Update the current block height.
    pub fn set_block_height(&self, height: u64) {
        self.block_height.store(height, std::sync::atomic::Ordering::Relaxed);
    }

    async fn current_block_number(&self) -> u64 {
        let provider = self.state_provider.read().await;
        provider
            .block_number()
            .await
            .unwrap_or_else(|_| self.block_height.load(std::sync::atomic::Ordering::Relaxed))
    }

    async fn recent_fee_estimate(&self) -> RpcResult<GasOracleEstimate> {
        let provider = self.state_provider.read().await;
        let head = provider
            .block_number()
            .await
            .unwrap_or_else(|_| self.block_height.load(std::sync::atomic::Ordering::Relaxed));

        if let Some(cached) = *self.gas_oracle_cache.read().await
            && cached.head == head
        {
            return Ok(cached.estimate);
        }

        let estimate = estimate_recent_fees(&*provider, head, self.gas_oracle_config).await;
        // Release the state_provider read lock before acquiring the
        // gas_oracle_cache write lock.  This eliminates the nested lock
        // ordering dependency (state_provider -> gas_oracle_cache) and
        // reduces the duration the state_provider lock is held.
        drop(provider);
        *self.gas_oracle_cache.write().await = Some(CachedGasOracleEstimate { head, estimate });
        Ok(estimate)
    }
}

#[jsonrpsee::core::async_trait]
impl<S: StateProvider + 'static> EthApiServer for EthApiImpl<S> {
    async fn chain_id(&self) -> RpcResult<U64> {
        Ok(U64::from(self.chain_id))
    }

    async fn block_number(&self) -> RpcResult<U64> {
        Ok(U64::from(self.current_block_number().await))
    }

    async fn get_balance(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U256> {
        let provider = self.state_provider.read().await;
        provider.balance(address, block).await.map_err(Into::into)
    }

    async fn get_transaction_count(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U64> {
        let is_pending = block.as_ref().is_some_and(BlockNumberOrTag::is_pending);

        let provider = self.state_provider.read().await;
        let finalized_nonce = provider.nonce(address, block).await?;

        // When the caller asks for the "pending" nonce, augment the
        // finalized on-chain nonce with the transaction pool's view so
        // that sequential sends from one account get strictly increasing
        // nonces.
        if is_pending
            && let Some(ref txpool) = self.txpool
            && let Some(pool_nonce) = txpool.next_nonce(&address)
        {
            return Ok(U64::from(pool_nonce.max(finalized_nonce)));
        }

        Ok(U64::from(finalized_nonce))
    }

    async fn get_code(
        &self,
        address: Address,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<Bytes> {
        let provider = self.state_provider.read().await;
        provider.code(address, block).await.map_err(Into::into)
    }

    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U256> {
        let provider = self.state_provider.read().await;
        provider.storage(address, slot, block).await.map_err(Into::into)
    }

    async fn send_raw_transaction(&self, data: Bytes) -> RpcResult<B256> {
        let tx_hash = alloy_primitives::keccak256(&data);
        let pending_tx = raw_tx_to_pending_rpc(&data)?;

        let accepted = if let Some(ref submit) = self.tx_submit {
            submit(data).await?;
            true
        } else {
            false
        };

        {
            let mut txs = self.pending_txs.write().await;
            let mut order = self.pending_tx_order.write().await;
            txs.insert(tx_hash, pending_tx.clone());
            order.push_back(tx_hash);

            // Evict oldest entries when either the pending map or the
            // order deque exceeds the cap. The deque can accumulate stale
            // entries (hashes removed from the map by
            // `get_transaction_by_hash` but not from the deque), so we
            // must bound both independently.
            let cap = self.max_pending_txs;
            let needs_eviction = txs.len() > cap || order.len() > cap;
            if needs_eviction {
                let map_excess = txs.len().saturating_sub(cap);
                let deque_excess = order.len().saturating_sub(cap);
                let target = map_excess.max(deque_excess);
                warn!(
                    map_excess,
                    deque_excess,
                    cap,
                    "pending transaction cache exceeded limit, evicting oldest entries"
                );
                let mut evicted = 0;
                let mut drained = 0usize;
                // Drain from the front (oldest) of the order deque until
                // we have removed enough entries from the map AND trimmed
                // the deque back to the cap.
                while (evicted < map_excess || drained < target) && !order.is_empty() {
                    let old_hash = order.pop_front().unwrap();
                    drained += 1;
                    if txs.remove(&old_hash).is_some() {
                        evicted += 1;
                    }
                }
                // Update the cumulative eviction offset so that filter
                // cursors (which store absolute indices) remain correct.
                self.pending_tx_evicted.fetch_add(drained, std::sync::atomic::Ordering::Relaxed);
            }
        }

        if accepted {
            self.broadcast_pending_tx(tx_hash, pending_tx);
        }
        Ok(tx_hash)
    }

    async fn call(
        &self,
        request: CallRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<Bytes> {
        let provider = self.state_provider.read().await;
        provider.call(request, block).await.map_err(Into::into)
    }

    async fn estimate_gas(
        &self,
        request: CallRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<U64> {
        let provider = self.state_provider.read().await;
        let gas = provider.estimate_gas(request, block).await?;
        Ok(U64::from(gas))
    }

    async fn get_block_by_number(
        &self,
        block: BlockNumberOrTag,
        full_transactions: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let provider = self.state_provider.read().await;
        provider.block_by_number(block, full_transactions).await.map_err(Into::into)
    }

    async fn get_block_by_hash(
        &self,
        hash: B256,
        full_transactions: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let provider = self.state_provider.read().await;
        provider.block_by_hash(hash, full_transactions).await.map_err(Into::into)
    }

    async fn get_transaction_by_hash(&self, hash: B256) -> RpcResult<Option<RpcTransaction>> {
        let provider = self.state_provider.read().await;
        let indexed = provider.transaction_by_hash(hash).await?;
        if indexed.is_some() {
            // Only acquire the write lock when the hash is actually in the
            // pending pool.  The common case (confirmed tx that was never
            // pending locally) now takes a cheap read lock instead of
            // serializing with send_raw_transaction writers.
            if self.pending_txs.read().await.contains_key(&hash) {
                self.pending_txs.write().await.remove(&hash);
            }
            return Ok(indexed);
        }
        Ok(self.pending_txs.read().await.get(&hash).cloned())
    }

    async fn get_transaction_receipt(
        &self,
        hash: B256,
    ) -> RpcResult<Option<RpcTransactionReceipt>> {
        let provider = self.state_provider.read().await;
        provider.receipt_by_hash(hash).await.map_err(Into::into)
    }

    async fn gas_price(&self) -> RpcResult<U256> {
        Ok(self.recent_fee_estimate().await?.gas_price)
    }

    async fn max_priority_fee_per_gas(&self) -> RpcResult<U256> {
        Ok(self.recent_fee_estimate().await?.priority_fee)
    }

    async fn fee_history(
        &self,
        block_count: U64,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory> {
        // Validate percentile values before doing any work.
        if let Some(percentiles) = &reward_percentiles {
            validate_reward_percentiles(percentiles)?;
        }

        // Acquire the lock briefly to resolve the head block number, then
        // release it so that writers are not starved during the loop below
        // which may iterate over up to 1,024 blocks.
        let head = {
            let provider = self.state_provider.read().await;
            provider
                .block_number()
                .await
                .unwrap_or_else(|_| self.block_height.load(std::sync::atomic::Ordering::Relaxed))
        };
        let newest = resolve_fee_history_newest(newest_block, head);
        let requested = block_count.to::<u64>().min(1024);
        let count = requested.min(newest.saturating_add(1)) as usize;
        let oldest = newest.saturating_add(1).saturating_sub(count as u64);

        let mut base_fee_per_gas = Vec::with_capacity(count + 1);
        let mut gas_used_ratio = Vec::with_capacity(count);
        let mut reward = reward_percentiles.as_ref().map(|_| Vec::with_capacity(count));
        let mut last_base_fee = None;
        let mut last_gas_used = 0;
        let mut last_gas_limit = 0;

        for block_number in oldest..oldest + count as u64 {
            // Re-acquire the read lock per iteration so that writers (e.g.
            // state provider swaps) can proceed between blocks.  Fee history
            // is advisory data for gas estimation, so a slightly inconsistent
            // cross-block view is acceptable.
            let provider = self.state_provider.read().await;
            let block = block_by_number_or_none(&*provider, block_number, reward.is_some()).await;
            let base_fee = block
                .as_ref()
                .and_then(|block| block.base_fee_per_gas)
                .or(last_base_fee)
                .unwrap_or_else(default_base_fee);
            base_fee_per_gas.push(base_fee);

            if let Some(block) = block {
                let gas_used = block.gas_used.to::<u64>();
                let gas_limit = block.gas_limit.to::<u64>();
                gas_used_ratio.push(block_gas_used_ratio(gas_used, gas_limit));

                if let (Some(percentiles), Some(rows)) = (&reward_percentiles, reward.as_mut()) {
                    let tx_gas_used = fetch_tx_gas_used(&*provider, &block).await;
                    rows.push(compute_reward_percentiles(&block, &tx_gas_used, percentiles));
                }

                last_base_fee = Some(base_fee);
                last_gas_used = gas_used;
                last_gas_limit = gas_limit;
            } else {
                gas_used_ratio.push(0.0);
                if let (Some(percentiles), Some(rows)) = (&reward_percentiles, reward.as_mut()) {
                    rows.push(vec![U256::ZERO; percentiles.len()]);
                }
            }
            // provider read lock is released here at end of each iteration
        }

        let next_base_fee = last_base_fee
            .map(|base_fee| calculate_next_base_fee(base_fee, last_gas_used, last_gas_limit))
            .unwrap_or_else(default_base_fee);
        base_fee_per_gas.push(next_base_fee);

        Ok(FeeHistory { base_fee_per_gas, gas_used_ratio, oldest_block: U64::from(oldest), reward })
    }

    async fn accounts(&self) -> RpcResult<Vec<Address>> {
        Ok(Vec::new())
    }

    async fn protocol_version(&self) -> RpcResult<String> {
        Ok("0x44".to_string())
    }

    async fn syncing(&self) -> RpcResult<SyncStatus> {
        if let Some(ref state) = self.node_state
            && state.is_catching_up()
        {
            let current_block = self.current_block_number().await;
            Ok(SyncStatus::Syncing(SyncInfo {
                starting_block: U64::from(state.recovered_height()),
                current_block: U64::from(current_block),
                highest_block: U64::from(current_block),
            }))
        } else {
            Ok(SyncStatus::NotSyncing(false))
        }
    }

    async fn get_logs(&self, filter: RpcLogFilter) -> RpcResult<Vec<RpcLog>> {
        let provider = self.state_provider.read().await;
        provider.get_logs(filter).await.map_err(Into::into)
    }

    async fn new_filter(&self, filter: RpcLogFilter) -> RpcResult<U256> {
        let head = self.current_block_number().await;
        // Initialize the cursor so the first `getFilterChanges` starts at
        // `from_block` (inclusive) when explicitly provided, rather than
        // always starting from the current head.
        let last_poll_block = if filter.block_hash.is_some() {
            // block_hash filters are single-block; `None` ensures the
            // first poll returns results, and subsequent polls return empty.
            None
        } else {
            match &filter.from_block {
                Some(BlockNumberOrTag::Number(n)) => {
                    let from = n.to::<u64>();
                    // Cursor is *last included* block, so subtract 1 so the
                    // first poll begins at `from`. For block 0 we use `None`
                    // to represent "nothing polled yet".
                    if from == 0 { None } else { Some(from - 1) }
                }
                Some(BlockNumberOrTag::Tag(crate::types::BlockTag::Earliest)) => {
                    // Start from genesis: no blocks polled yet.
                    None
                }
                // latest / pending / safe / finalized / default -> current head
                _ => Some(head),
            }
        };
        let id = self.filter_store.create(Filter::Log { criteria: filter, last_poll_block });
        Ok(U256::from(id))
    }

    async fn new_block_filter(&self) -> RpcResult<U256> {
        let head = self.current_block_number().await;
        let id = self.filter_store.create(Filter::Block { last_poll_block: head });
        Ok(U256::from(id))
    }

    async fn new_pending_transaction_filter(&self) -> RpcResult<U256> {
        let known_hashes = self.pending_txs.read().await.keys().copied().collect();
        // Read `evicted` and `order.len()` under the same lock to avoid a
        // race where an eviction between the two reads would shift the
        // cursor. This is consistent with `send_raw_transaction`'s lock
        // ordering (`pending_txs` then `pending_tx_order`).
        let last_seen_index = {
            let order = self.pending_tx_order.read().await;
            let evicted = self.pending_tx_evicted.load(std::sync::atomic::Ordering::Relaxed);
            evicted + order.len()
        };
        let id =
            self.filter_store.create(Filter::PendingTransaction { known_hashes, last_seen_index });
        Ok(U256::from(id))
    }

    async fn get_filter_changes(&self, filter_id: U256) -> RpcResult<FilterChanges> {
        let id = filter_id_to_u64(filter_id).ok_or(RpcError::FilterNotFound)?;
        let entry = self.filter_store.get(id).ok_or(RpcError::FilterNotFound)?;

        // Read filter state under the lock, then release before any async I/O.
        enum FilterSnapshot {
            Log { criteria: RpcLogFilter, last_poll_block: Option<u64> },
            Block { last_poll_block: u64 },
            PendingTx { known_hashes: HashSet<B256>, last_seen_index: usize },
        }

        let snapshot = {
            let filter = entry.lock().await;
            match &*filter {
                Filter::Log { criteria, last_poll_block } => FilterSnapshot::Log {
                    criteria: criteria.clone(),
                    last_poll_block: *last_poll_block,
                },
                Filter::Block { last_poll_block } => {
                    FilterSnapshot::Block { last_poll_block: *last_poll_block }
                }
                Filter::PendingTransaction { known_hashes, last_seen_index } => {
                    FilterSnapshot::PendingTx {
                        known_hashes: known_hashes.clone(),
                        last_seen_index: *last_seen_index,
                    }
                }
            }
        };
        // Lock is released here.

        match snapshot {
            FilterSnapshot::Log { criteria, last_poll_block } => {
                let head = self.current_block_number().await;
                if let Some(lpb) = last_poll_block
                    && head <= lpb
                {
                    entry.touch();
                    return Ok(FilterChanges::Logs(Vec::new()));
                }

                // Preserve the original `to_block` / `block_hash`.
                // Only override `from_block` to advance the cursor, and
                // only cap `to_block` at head when no fixed bound was set.
                let changes_filter = if criteria.block_hash.is_some() {
                    // block_hash filters are single-block and already returned
                    // their results on the first poll (when last_poll_block was
                    // None). Subsequent polls always return empty.
                    if last_poll_block.is_some() {
                        entry.touch();
                        return Ok(FilterChanges::Logs(Vec::new()));
                    }
                    criteria.clone()
                } else {
                    let from = last_poll_block.map(|lpb| lpb.saturating_add(1)).unwrap_or(0);
                    let to = match &criteria.to_block {
                        // Honour the original fixed upper bound.
                        Some(BlockNumberOrTag::Number(n)) => n.to::<u64>().min(head),
                        // Open-ended or "latest": cap at current head.
                        _ => head,
                    };
                    RpcLogFilter {
                        from_block: Some(BlockNumberOrTag::Number(U64::from(from))),
                        to_block: Some(BlockNumberOrTag::Number(U64::from(to))),
                        // Preserve everything else from the original criteria.
                        address: criteria.address.clone(),
                        topics: criteria.topics.clone(),
                        block_hash: None,
                    }
                };

                let provider = self.state_provider.read().await;
                let logs = provider.get_logs(changes_filter).await?;

                // Update the cursor under the lock.
                let mut filter = entry.lock().await;
                if let Filter::Log { last_poll_block: lpb, .. } = &mut *filter {
                    *lpb = Some(head);
                }
                entry.touch();
                Ok(FilterChanges::Logs(logs))
            }
            FilterSnapshot::Block { last_poll_block } => {
                let head = self.current_block_number().await;
                if head <= last_poll_block {
                    entry.touch();
                    return Ok(FilterChanges::Hashes(Vec::new()));
                }

                let provider = self.state_provider.read().await;
                let mut hashes = Vec::new();
                // Track the highest block that was actually observed
                // rather than blindly advancing to `head`.
                let mut highest_observed = last_poll_block;
                for block_num in last_poll_block.saturating_add(1)..=head {
                    if let Some(block) = provider
                        .block_by_number(BlockNumberOrTag::Number(U64::from(block_num)), false)
                        .await?
                    {
                        hashes.push(block.hash);
                        highest_observed = block_num;
                    }
                }

                let mut filter = entry.lock().await;
                if let Filter::Block { last_poll_block: lpb } = &mut *filter {
                    *lpb = highest_observed;
                }
                entry.touch();
                Ok(FilterChanges::Hashes(hashes))
            }
            FilterSnapshot::PendingTx { known_hashes, last_seen_index } => {
                // Return new pending tx hashes in insertion order.
                //
                // IMPORTANT: We must drop the `pending_tx_order` lock before
                // acquiring `pending_txs` to maintain consistent lock ordering
                // with `send_raw_transaction` (which takes `pending_txs` then
                // `pending_tx_order`).
                let (new_hashes, new_index) = {
                    let tx_order = self.pending_tx_order.read().await;
                    let evicted =
                        self.pending_tx_evicted.load(std::sync::atomic::Ordering::Relaxed);
                    // Convert the absolute cursor to a deque-relative offset.
                    // If entries were evicted past the cursor, start from the
                    // front of the deque (relative offset 0).
                    let relative_skip = last_seen_index.saturating_sub(evicted);
                    let hashes: Vec<B256> = tx_order
                        .iter()
                        .skip(relative_skip)
                        .filter(|h| !known_hashes.contains(*h))
                        .copied()
                        .collect();
                    let idx = evicted + tx_order.len();
                    (hashes, idx)
                    // tx_order lock is dropped here
                };
                let current_hashes: HashSet<B256> =
                    self.pending_txs.read().await.keys().copied().collect();

                let mut filter = entry.lock().await;
                if let Filter::PendingTransaction { known_hashes: kh, last_seen_index: idx } =
                    &mut *filter
                {
                    *kh = current_hashes;
                    *idx = new_index;
                }
                entry.touch();
                Ok(FilterChanges::Hashes(new_hashes))
            }
        }
    }

    async fn get_filter_logs(&self, filter_id: U256) -> RpcResult<Vec<RpcLog>> {
        let id = filter_id_to_u64(filter_id).ok_or(RpcError::FilterNotFound)?;
        let entry = self.filter_store.get(id).ok_or(RpcError::FilterNotFound)?;
        let criteria = {
            let filter = entry.lock().await;
            match &*filter {
                Filter::Log { criteria, .. } => criteria.clone(),
                Filter::Block { .. } | Filter::PendingTransaction { .. } => {
                    return Err(RpcError::FilterNotFound.into());
                }
            }
        };

        let provider = self.state_provider.read().await;
        let logs = provider.get_logs(criteria).await?;
        entry.touch();
        Ok(logs)
    }

    async fn uninstall_filter(&self, filter_id: U256) -> RpcResult<bool> {
        let Some(id) = filter_id_to_u64(filter_id) else {
            return Ok(false);
        };
        Ok(self.filter_store.remove(id))
    }
}

impl<S: StateProvider> EthApiImpl<S> {
    fn broadcast_pending_tx(&self, tx_hash: B256, pending_tx: RpcTransaction) {
        if let Some(sender) = &self.pending_tx_broadcast {
            let _ = sender.send(PendingTxEvent::Added(PendingTxInfo {
                hash: tx_hash,
                full_tx: Some(pending_tx.clone()),
            }));
        }

        if let Some(sender) = &self.mempool_broadcast {
            let _ = sender.send(MempoolEvent::TxAdded {
                hash: tx_hash,
                from: pending_tx.from,
                to: pending_tx.to,
                value: pending_tx.value,
                gas_price: pending_tx.gas_price,
                nonce: pending_tx.nonce.to::<u64>(),
            });
        }
    }
}

/// Net API implementation.
pub struct NetApiImpl {
    chain_id: u64,
    peer_count: Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for NetApiImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetApiImpl")
            .field("chain_id", &self.chain_id)
            .field("peer_count", &self.peer_count.load(std::sync::atomic::Ordering::Relaxed))
            .finish()
    }
}

impl NetApiImpl {
    /// Create a new Net API implementation.
    pub fn new(chain_id: u64) -> Self {
        Self { chain_id, peer_count: Arc::new(std::sync::atomic::AtomicU64::new(0)) }
    }

    /// Get a handle to update the peer count.
    pub fn peer_count_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        self.peer_count.clone()
    }

    /// Update the peer count.
    pub fn set_peer_count(&self, count: u64) {
        self.peer_count.store(count, std::sync::atomic::Ordering::Relaxed);
    }
}

impl NetApiServer for NetApiImpl {
    fn version(&self) -> RpcResult<String> {
        Ok(self.chain_id.to_string())
    }

    fn listening(&self) -> RpcResult<bool> {
        Ok(true)
    }

    fn peer_count(&self) -> RpcResult<U64> {
        let count = self.peer_count.load(std::sync::atomic::Ordering::Relaxed);
        Ok(U64::from(count))
    }
}

/// Web3 API implementation.
#[derive(Clone, Debug, Default)]
pub struct Web3ApiImpl;

impl Web3ApiImpl {
    /// Create a new Web3 API implementation.
    pub const fn new() -> Self {
        Self
    }
}

impl Web3ApiServer for Web3ApiImpl {
    fn client_version(&self) -> RpcResult<String> {
        Ok(format!("kora/{}", env!("CARGO_PKG_VERSION")))
    }

    fn sha3(&self, data: Bytes) -> RpcResult<B256> {
        Ok(alloy_primitives::keccak256(&data))
    }
}

const fn filter_id_to_u64(filter_id: U256) -> Option<u64> {
    let limbs = filter_id.as_limbs();
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    Some(limbs[0])
}

async fn estimate_recent_fees<S: StateProvider>(
    provider: &S,
    head: u64,
    config: GasOracleConfig,
) -> GasOracleEstimate {
    let block_count = config.blocks.max(1);
    let start = head.saturating_sub(block_count.saturating_sub(1) as u64);
    let mut gas_prices = Vec::new();
    let mut priority_fees = Vec::new();
    let mut latest_base_fee = None;

    for block_number in start..=head {
        let Some(block) = block_by_number_or_none(provider, block_number, true).await else {
            continue;
        };
        let base_fee = block.base_fee_per_gas.unwrap_or_else(default_base_fee);
        latest_base_fee = Some(base_fee);

        if let BlockTransactions::Full(txs) = &block.transactions {
            gas_prices.extend(txs.iter().map(|tx| effective_gas_price_for_sampling(tx, base_fee)));
            priority_fees.extend(txs.iter().map(|tx| effective_priority_fee(tx, base_fee)));
        }
    }

    let priority_fee =
        percentile_value(&mut priority_fees, config.percentile).unwrap_or(config.min_priority_fee);
    let priority_fee = priority_fee.max(config.min_priority_fee);
    let latest_base_fee = latest_base_fee.unwrap_or_else(default_base_fee);

    // Clamp priority fee so that base_fee + priority_fee does not exceed
    // max_price (when the base fee alone is still under the cap).
    let priority_fee = if latest_base_fee < config.max_price {
        priority_fee.min(config.max_price.saturating_sub(latest_base_fee))
    } else {
        priority_fee
    };

    let min_gas_price = config.min_price.max(latest_base_fee.saturating_add(priority_fee));
    let gas_price = percentile_value(&mut gas_prices, config.percentile).unwrap_or(min_gas_price);
    let gas_price = gas_price.max(min_gas_price);

    // Always enforce the hard cap unless the base fee alone exceeds it --
    // in that case the chain's base fee is already above the configured
    // maximum and we must still return a usable price.
    let gas_price = if latest_base_fee <= config.max_price {
        gas_price.min(config.max_price)
    } else {
        gas_price
    };

    GasOracleEstimate { gas_price, priority_fee }
}

async fn block_by_number_or_none<S: StateProvider>(
    provider: &S,
    block_number: u64,
    full_transactions: bool,
) -> Option<RpcBlock> {
    match provider
        .block_by_number(BlockNumberOrTag::Number(U64::from(block_number)), full_transactions)
        .await
    {
        Ok(block) => block,
        Err(e) => {
            warn!(block_number, error = %e, "failed to fetch block by number");
            None
        }
    }
}

fn resolve_fee_history_newest(newest_block: BlockNumberOrTag, head: u64) -> u64 {
    match newest_block {
        BlockNumberOrTag::Number(n) => n.to::<u64>().min(head),
        BlockNumberOrTag::Tag(BlockTag::Earliest) => 0,
        BlockNumberOrTag::Tag(_) | BlockNumberOrTag::Latest => head,
    }
}

fn default_base_fee() -> U256 {
    U256::from(GWEI)
}

fn percentile_value(values: &mut [U256], percentile: u8) -> Option<U256> {
    if values.is_empty() {
        return None;
    }

    values.sort_unstable();
    let percentile = usize::from(percentile.min(100));
    let index = (values.len() * percentile / 100).min(values.len() - 1);
    Some(values[index])
}

fn block_gas_used_ratio(gas_used: u64, gas_limit: u64) -> f64 {
    if gas_limit == 0 {
        return 0.0;
    }
    (gas_used as f64 / gas_limit as f64).clamp(0.0, 1.0)
}

/// Validates that `reward_percentiles` values are in `[0, 100]` and
/// monotonically non-decreasing, per the Ethereum JSON-RPC specification.
fn validate_reward_percentiles(percentiles: &[f64]) -> RpcResult<()> {
    for p in percentiles {
        if !p.is_finite() || *p < 0.0 || *p > 100.0 {
            return Err(RpcError::InvalidTransaction(
                "reward percentiles must be in [0, 100]".to_string(),
            )
            .into());
        }
    }
    for w in percentiles.windows(2) {
        if w[0] > w[1] {
            return Err(RpcError::InvalidTransaction(
                "reward percentiles must be monotonically non-decreasing".to_string(),
            )
            .into());
        }
    }
    Ok(())
}

/// Fetches per-transaction `gas_used` from receipts for all transactions in
/// the block. Returns a `Vec` parallel to the block's full transaction list.
/// When a receipt cannot be found, falls back to the transaction's gas limit.
async fn fetch_tx_gas_used<S: StateProvider>(provider: &S, block: &RpcBlock) -> Vec<u64> {
    let BlockTransactions::Full(txs) = &block.transactions else {
        return Vec::new();
    };
    let mut gas_used = Vec::with_capacity(txs.len());
    for tx in txs {
        let used = match provider.receipt_by_hash(tx.hash).await {
            Ok(Some(receipt)) => receipt.gas_used.to::<u64>(),
            _ => tx.gas.to::<u64>(),
        };
        gas_used.push(used);
    }
    gas_used
}

fn compute_reward_percentiles(
    block: &RpcBlock,
    tx_gas_used: &[u64],
    percentiles: &[f64],
) -> Vec<U256> {
    let BlockTransactions::Full(txs) = &block.transactions else {
        return vec![U256::ZERO; percentiles.len()];
    };
    if txs.is_empty() {
        return vec![U256::ZERO; percentiles.len()];
    }

    let base_fee = block.base_fee_per_gas.unwrap_or_default();
    let mut rewards: Vec<(U256, u64)> = txs
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let gas = tx_gas_used.get(i).copied().unwrap_or_else(|| tx.gas.to::<u64>());
            (effective_priority_fee(tx, base_fee), gas)
        })
        .filter(|(_, gas)| *gas > 0)
        .collect();
    if rewards.is_empty() {
        return vec![U256::ZERO; percentiles.len()];
    }

    rewards.sort_by_key(|(tip, _)| *tip);
    let total_gas = rewards.iter().map(|(_, gas)| u128::from(*gas)).sum();

    percentiles
        .iter()
        .map(|percentile| weighted_percentile_reward(&rewards, total_gas, *percentile))
        .collect()
}

fn weighted_percentile_reward(rewards: &[(U256, u64)], total_gas: u128, percentile: f64) -> U256 {
    let threshold = percentile_threshold(total_gas, percentile);
    let mut cumulative_gas = 0u128;

    for (tip, gas) in rewards {
        cumulative_gas = cumulative_gas.saturating_add(u128::from(*gas));
        if cumulative_gas >= threshold {
            return *tip;
        }
    }

    rewards.last().map(|(tip, _)| *tip).unwrap_or_default()
}

fn percentile_threshold(total_gas: u128, percentile: f64) -> u128 {
    if total_gas == 0 {
        return 0;
    }

    let percentile = if percentile.is_finite() { percentile.clamp(0.0, 100.0) } else { 0.0 };
    ((total_gas as f64 * percentile / 100.0).ceil() as u128).min(total_gas)
}

fn effective_priority_fee(tx: &RpcTransaction, base_fee: U256) -> U256 {
    match (tx.max_fee_per_gas, tx.max_priority_fee_per_gas) {
        (Some(max_fee), Some(max_priority_fee)) => {
            max_priority_fee.min(max_fee.saturating_sub(base_fee))
        }
        _ if is_dynamic_fee_type(tx) => {
            // Indexed EIP-1559 (or later) tx without populated EIP-1559
            // fields: `gas_price` may represent `max_fee_per_gas`, so we
            // cannot reliably derive the tip. Return zero to avoid
            // inflating estimates.
            U256::ZERO
        }
        _ => tx.gas_price.saturating_sub(base_fee),
    }
}

/// Returns `true` when the transaction type uses dynamic-fee semantics
/// (types 2, 3, 4 -- EIP-1559, EIP-4844, EIP-7702).
fn is_dynamic_fee_type(tx: &RpcTransaction) -> bool {
    tx.tx_type.to::<u64>() >= 2
}

/// Derives the effective gas price a transaction actually paid, accounting
/// for the difference between legacy `gas_price` and EIP-1559
/// `min(max_fee, base_fee + tip)`.
fn effective_gas_price_for_sampling(tx: &RpcTransaction, base_fee: U256) -> U256 {
    match (tx.max_fee_per_gas, tx.max_priority_fee_per_gas) {
        (Some(max_fee), Some(max_priority_fee)) => {
            let tip = max_priority_fee.min(max_fee.saturating_sub(base_fee));
            base_fee.saturating_add(tip).min(max_fee)
        }
        _ => tx.gas_price,
    }
}

fn calculate_next_base_fee(
    parent_base_fee: U256,
    parent_gas_used: u64,
    parent_gas_limit: u64,
) -> U256 {
    let parent_gas_target = parent_gas_limit / 2;
    if parent_gas_target == 0 || parent_gas_used == parent_gas_target {
        return parent_base_fee;
    }

    if parent_gas_used > parent_gas_target {
        let gas_used_delta = parent_gas_used - parent_gas_target;
        let base_fee_delta = parent_base_fee * U256::from(gas_used_delta)
            / U256::from(parent_gas_target)
            / U256::from(8);
        parent_base_fee.saturating_add(base_fee_delta.max(U256::from(1)))
    } else {
        let gas_used_delta = parent_gas_target - parent_gas_used;
        let base_fee_delta = parent_base_fee * U256::from(gas_used_delta)
            / U256::from(parent_gas_target)
            / U256::from(8);
        parent_base_fee.saturating_sub(base_fee_delta)
    }
}

fn raw_tx_to_pending_rpc(data: &Bytes) -> Result<RpcTransaction, RpcError> {
    let envelope = TxEnvelope::decode_2718(&mut data.as_ref())
        .map_err(|err| RpcError::InvalidTransaction(format!("failed to decode: {err}")))?;
    let from = envelope
        .recover_signer()
        .map_err(|err| RpcError::InvalidTransaction(format!("failed to recover signer: {err}")))?;
    let signature = envelope.signature();
    let hash = alloy_primitives::keccak256(data);

    Ok(RpcTransaction {
        hash,
        nonce: U64::from(envelope.nonce()),
        block_hash: None,
        block_number: None,
        transaction_index: None,
        from,
        to: envelope.to(),
        value: envelope.value(),
        gas: U64::from(envelope.gas_limit()),
        gas_price: U256::from(effective_gas_price(&envelope)),
        input: envelope.input().clone(),
        tx_type: U64::from(transaction_type(&envelope)),
        chain_id: envelope.chain_id().map(U64::from),
        max_fee_per_gas: max_fee_per_gas(&envelope).map(U256::from),
        max_priority_fee_per_gas: max_priority_fee_per_gas(&envelope).map(U256::from),
        v: U256::from(signature_v(&envelope)),
        r: signature.r(),
        s: signature.s(),
    })
}

fn signature_v(envelope: &TxEnvelope) -> u128 {
    let y_parity = envelope.signature().v();
    match envelope {
        TxEnvelope::Legacy(tx) => to_eip155_value(y_parity, tx.tx().chain_id),
        TxEnvelope::Eip2930(_)
        | TxEnvelope::Eip1559(_)
        | TxEnvelope::Eip4844(_)
        | TxEnvelope::Eip7702(_) => u128::from(y_parity),
    }
}

const fn transaction_type(envelope: &TxEnvelope) -> u64 {
    match envelope {
        TxEnvelope::Legacy(_) => 0,
        TxEnvelope::Eip2930(_) => 1,
        TxEnvelope::Eip1559(_) => 2,
        TxEnvelope::Eip4844(_) => 3,
        TxEnvelope::Eip7702(_) => 4,
    }
}

const fn effective_gas_price(envelope: &TxEnvelope) -> u128 {
    match envelope {
        TxEnvelope::Legacy(tx) => tx.tx().gas_price,
        TxEnvelope::Eip2930(tx) => tx.tx().gas_price,
        TxEnvelope::Eip1559(tx) => tx.tx().max_fee_per_gas,
        TxEnvelope::Eip4844(tx) => tx.tx().tx().max_fee_per_gas,
        TxEnvelope::Eip7702(tx) => tx.tx().max_fee_per_gas,
    }
}

const fn max_fee_per_gas(envelope: &TxEnvelope) -> Option<u128> {
    match envelope {
        TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_) => None,
        TxEnvelope::Eip1559(tx) => Some(tx.tx().max_fee_per_gas),
        TxEnvelope::Eip4844(tx) => Some(tx.tx().tx().max_fee_per_gas),
        TxEnvelope::Eip7702(tx) => Some(tx.tx().max_fee_per_gas),
    }
}

const fn max_priority_fee_per_gas(envelope: &TxEnvelope) -> Option<u128> {
    match envelope {
        TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_) => None,
        TxEnvelope::Eip1559(tx) => Some(tx.tx().max_priority_fee_per_gas),
        TxEnvelope::Eip4844(tx) => Some(tx.tx().tx().max_priority_fee_per_gas),
        TxEnvelope::Eip7702(tx) => Some(tx.tx().max_priority_fee_per_gas),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use alloy_consensus::{SignableTransaction as _, TxEip1559};
    use alloy_eips::eip2718::Encodable2718 as _;
    use alloy_primitives::{Signature, TxKind};
    use async_trait::async_trait;
    use k256::ecdsa::SigningKey;
    use kora_domain::MempoolEvent;
    use sha3::{Digest as _, Keccak256};

    use super::*;
    use crate::{
        PendingTxEvent, mempool_event_channel, pending_tx_channel,
        state_provider::NoopStateProvider,
        types::{AddressFilter, BlockTag, TopicFilter},
    };

    #[derive(Clone, Debug)]
    struct MockFeeStateProvider {
        blocks: HashMap<u64, RpcBlock>,
        receipts: HashMap<B256, RpcTransactionReceipt>,
        head: u64,
    }

    impl MockFeeStateProvider {
        fn new(blocks: Vec<RpcBlock>) -> Self {
            let head = blocks.iter().map(|block| block.number.to::<u64>()).max().unwrap_or(0);
            let blocks =
                blocks.into_iter().map(|block| (block.number.to::<u64>(), block)).collect();
            Self { blocks, receipts: HashMap::new(), head }
        }

        fn with_receipts(mut self, receipts: Vec<RpcTransactionReceipt>) -> Self {
            self.receipts = receipts.into_iter().map(|r| (r.transaction_hash, r)).collect();
            self
        }

        fn resolve_block_number(&self, block: BlockNumberOrTag) -> u64 {
            match block {
                BlockNumberOrTag::Number(number) => number.to::<u64>(),
                BlockNumberOrTag::Tag(BlockTag::Earliest) => 0,
                BlockNumberOrTag::Tag(_) | BlockNumberOrTag::Latest => self.head,
            }
        }

        fn block_with_transaction_shape(
            &self,
            number: u64,
            full_transactions: bool,
        ) -> Option<RpcBlock> {
            let mut block = self.blocks.get(&number).cloned()?;
            if !full_transactions && let BlockTransactions::Full(txs) = &block.transactions {
                block.transactions =
                    BlockTransactions::Hashes(txs.iter().map(|tx| tx.hash).collect());
            }
            Some(block)
        }
    }

    #[async_trait]
    impl StateProvider for MockFeeStateProvider {
        async fn balance(
            &self,
            _address: Address,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<U256, RpcError> {
            Ok(U256::ZERO)
        }

        async fn nonce(
            &self,
            _address: Address,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<u64, RpcError> {
            Ok(0)
        }

        async fn code(
            &self,
            _address: Address,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<Bytes, RpcError> {
            Ok(Bytes::new())
        }

        async fn storage(
            &self,
            _address: Address,
            _slot: U256,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<U256, RpcError> {
            Ok(U256::ZERO)
        }

        async fn block_by_number(
            &self,
            block: BlockNumberOrTag,
            full_transactions: bool,
        ) -> Result<Option<RpcBlock>, RpcError> {
            Ok(self
                .block_with_transaction_shape(self.resolve_block_number(block), full_transactions))
        }

        async fn block_by_hash(
            &self,
            hash: B256,
            full_transactions: bool,
        ) -> Result<Option<RpcBlock>, RpcError> {
            let number = self
                .blocks
                .values()
                .find(|block| block.hash == hash)
                .map(|block| block.number.to::<u64>());
            Ok(number
                .and_then(|number| self.block_with_transaction_shape(number, full_transactions)))
        }

        async fn transaction_by_hash(
            &self,
            hash: B256,
        ) -> Result<Option<RpcTransaction>, RpcError> {
            Ok(self.blocks.values().find_map(|block| match &block.transactions {
                BlockTransactions::Full(txs) => txs.iter().find(|tx| tx.hash == hash).cloned(),
                BlockTransactions::Hashes(_) => None,
            }))
        }

        async fn receipt_by_hash(
            &self,
            hash: B256,
        ) -> Result<Option<RpcTransactionReceipt>, RpcError> {
            Ok(self.receipts.get(&hash).cloned())
        }

        async fn block_number(&self) -> Result<u64, RpcError> {
            Ok(self.head)
        }
    }

    fn gwei(value: u64) -> U256 {
        U256::from(value * GWEI)
    }

    /// EIP-1559 transaction parameters for test block construction.
    struct Eip1559TxParams {
        max_fee: U256,
        max_priority_fee: U256,
    }

    fn make_fee_block(
        number: u64,
        base_fee_per_gas: U256,
        gas_used: u64,
        gas_limit: u64,
        gas_prices: Vec<U256>,
    ) -> RpcBlock {
        let block_hash = B256::repeat_byte(number as u8);
        let transactions = gas_prices
            .into_iter()
            .enumerate()
            .map(|(index, gas_price)| RpcTransaction {
                hash: B256::repeat_byte((number as u8).wrapping_mul(16).wrapping_add(index as u8)),
                nonce: U64::from(index as u64),
                block_hash: Some(block_hash),
                block_number: Some(U64::from(number)),
                transaction_index: Some(U64::from(index as u64)),
                from: Address::repeat_byte(0x11),
                to: Some(Address::repeat_byte(0x22)),
                value: U256::ZERO,
                gas: U64::from(21_000),
                gas_price,
                input: Bytes::new(),
                tx_type: U64::ZERO,
                chain_id: None,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
                v: U256::ZERO,
                r: U256::ZERO,
                s: U256::ZERO,
            })
            .collect();

        RpcBlock {
            hash: block_hash,
            parent_hash: B256::ZERO,
            sha3_uncles: B256::ZERO,
            number: U64::from(number),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bytes::new(),
            timestamp: U64::from(number),
            gas_limit: U64::from(gas_limit),
            gas_used: U64::from(gas_used),
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: Default::default(),
            base_fee_per_gas: Some(base_fee_per_gas),
            miner: Address::ZERO,
            difficulty: U256::ZERO,
            total_difficulty: U256::ZERO,
            uncles: vec![],
            size: U64::ZERO,
            transactions: BlockTransactions::Full(transactions),
            withdrawals: vec![],
            withdrawals_root: B256::ZERO,
        }
    }

    /// Build a block containing EIP-1559 (type 2) transactions with explicit
    /// `max_fee_per_gas` and `max_priority_fee_per_gas` fields.
    fn make_eip1559_fee_block(
        number: u64,
        base_fee_per_gas: U256,
        gas_used: u64,
        gas_limit: u64,
        txs: Vec<Eip1559TxParams>,
    ) -> RpcBlock {
        let block_hash = B256::repeat_byte(number as u8);
        let transactions = txs
            .into_iter()
            .enumerate()
            .map(|(index, params)| {
                // Effective gas price = min(max_fee, base_fee + tip)
                let tip =
                    params.max_priority_fee.min(params.max_fee.saturating_sub(base_fee_per_gas));
                let gas_price = base_fee_per_gas.saturating_add(tip).min(params.max_fee);
                RpcTransaction {
                    hash: B256::repeat_byte(
                        (number as u8).wrapping_mul(16).wrapping_add(index as u8),
                    ),
                    nonce: U64::from(index as u64),
                    block_hash: Some(block_hash),
                    block_number: Some(U64::from(number)),
                    transaction_index: Some(U64::from(index as u64)),
                    from: Address::repeat_byte(0x11),
                    to: Some(Address::repeat_byte(0x22)),
                    value: U256::ZERO,
                    gas: U64::from(21_000),
                    gas_price,
                    input: Bytes::new(),
                    tx_type: U64::from(2),
                    chain_id: Some(U64::from(1)),
                    max_fee_per_gas: Some(params.max_fee),
                    max_priority_fee_per_gas: Some(params.max_priority_fee),
                    v: U256::ZERO,
                    r: U256::ZERO,
                    s: U256::ZERO,
                }
            })
            .collect();

        RpcBlock {
            hash: block_hash,
            parent_hash: B256::ZERO,
            sha3_uncles: B256::ZERO,
            number: U64::from(number),
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bytes::new(),
            timestamp: U64::from(number),
            gas_limit: U64::from(gas_limit),
            gas_used: U64::from(gas_used),
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: Default::default(),
            base_fee_per_gas: Some(base_fee_per_gas),
            miner: Address::ZERO,
            difficulty: U256::ZERO,
            total_difficulty: U256::ZERO,
            uncles: vec![],
            size: U64::ZERO,
            transactions: BlockTransactions::Full(transactions),
            withdrawals: vec![],
            withdrawals_root: B256::ZERO,
        }
    }

    fn make_test_receipt(
        tx_hash: B256,
        block_hash: B256,
        block_number: u64,
        gas_used: u64,
    ) -> RpcTransactionReceipt {
        RpcTransactionReceipt {
            transaction_hash: tx_hash,
            transaction_index: U64::ZERO,
            block_hash,
            block_number: U64::from(block_number),
            from: Address::repeat_byte(0x11),
            to: Some(Address::repeat_byte(0x22)),
            cumulative_gas_used: U64::from(gas_used),
            gas_used: U64::from(gas_used),
            contract_address: None,
            logs: vec![],
            logs_bloom: Bytes::new(),
            tx_type: U64::ZERO,
            status: U64::from(1),
            effective_gas_price: U256::from(GWEI),
        }
    }

    fn signed_test_tx(chain_id: u64, nonce: u64) -> Bytes {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let key = SigningKey::from_bytes((&secret).into()).expect("valid key");
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(Address::repeat_byte(0xbb)),
            value: U256::from(1),
            access_list: Default::default(),
            input: Bytes::new(),
        };
        let digest = Keccak256::new_with_prefix(tx.encoded_for_signing());
        let (sig, recid) = key.sign_digest_recoverable(digest).expect("sign tx");
        let signature = Signature::from((sig, recid));
        let envelope = TxEnvelope::from(tx.into_signed(signature));
        let mut raw = Vec::new();
        envelope.encode_2718(&mut raw);
        Bytes::from(raw)
    }

    #[derive(Clone, Default)]
    struct TestStateProvider {
        inner: Arc<RwLock<TestState>>,
    }

    #[derive(Default)]
    struct TestState {
        head: u64,
        blocks: HashMap<u64, RpcBlock>,
        logs: Vec<RpcLog>,
    }

    impl TestStateProvider {
        async fn insert_block(&self, number: u64, hash: B256) {
            let mut inner = self.inner.write().await;
            inner.head = inner.head.max(number);
            inner.blocks.insert(
                number,
                RpcBlock { hash, number: U64::from(number), ..RpcBlock::default() },
            );
        }

        async fn insert_log(
            &self,
            block_number: u64,
            address: Address,
            topics: Vec<B256>,
        ) -> RpcLog {
            let mut inner = self.inner.write().await;
            let block_hash = inner.blocks.get(&block_number).map_or(B256::ZERO, |block| block.hash);
            let log = RpcLog {
                address,
                topics,
                data: Bytes::new(),
                block_number: U64::from(block_number),
                transaction_hash: B256::ZERO,
                transaction_index: U64::ZERO,
                block_hash,
                log_index: U64::from(inner.logs.len() as u64),
                removed: false,
            };
            inner.logs.push(log.clone());
            log
        }
    }

    #[async_trait::async_trait]
    impl StateProvider for TestStateProvider {
        async fn balance(
            &self,
            _address: Address,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<U256, RpcError> {
            Ok(U256::ZERO)
        }

        async fn nonce(
            &self,
            _address: Address,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<u64, RpcError> {
            Ok(0)
        }

        async fn code(
            &self,
            _address: Address,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<Bytes, RpcError> {
            Ok(Bytes::new())
        }

        async fn storage(
            &self,
            _address: Address,
            _slot: U256,
            _block: Option<BlockNumberOrTag>,
        ) -> Result<U256, RpcError> {
            Ok(U256::ZERO)
        }

        async fn block_by_number(
            &self,
            block: BlockNumberOrTag,
            _full_transactions: bool,
        ) -> Result<Option<RpcBlock>, RpcError> {
            let inner = self.inner.read().await;
            let number = resolve_test_block_number(&block, inner.head);
            Ok(inner.blocks.get(&number).cloned())
        }

        async fn block_by_hash(
            &self,
            hash: B256,
            _full_transactions: bool,
        ) -> Result<Option<RpcBlock>, RpcError> {
            let inner = self.inner.read().await;
            Ok(inner.blocks.values().find(|block| block.hash == hash).cloned())
        }

        async fn transaction_by_hash(
            &self,
            _hash: B256,
        ) -> Result<Option<RpcTransaction>, RpcError> {
            Ok(None)
        }

        async fn receipt_by_hash(
            &self,
            _hash: B256,
        ) -> Result<Option<RpcTransactionReceipt>, RpcError> {
            Ok(None)
        }

        async fn block_number(&self) -> Result<u64, RpcError> {
            Ok(self.inner.read().await.head)
        }

        async fn get_logs(&self, filter: RpcLogFilter) -> Result<Vec<RpcLog>, RpcError> {
            let inner = self.inner.read().await;
            let from = filter
                .from_block
                .as_ref()
                .map_or(0, |block| resolve_test_block_number(block, inner.head));
            let to = filter
                .to_block
                .as_ref()
                .map_or(inner.head, |block| resolve_test_block_number(block, inner.head));
            let addresses = filter.address.clone().map(AddressFilter::into_vec);

            Ok(inner
                .logs
                .iter()
                .filter(|log| {
                    if let Some(block_hash) = filter.block_hash
                        && log.block_hash != block_hash
                    {
                        return false;
                    }
                    if filter.block_hash.is_none()
                        && (log.block_number.to::<u64>() < from
                            || log.block_number.to::<u64>() > to)
                    {
                        return false;
                    }
                    if let Some(addresses) = &addresses
                        && !addresses.contains(&log.address)
                    {
                        return false;
                    }
                    topics_match(log, filter.topics.as_ref())
                })
                .cloned()
                .collect())
        }
    }

    fn resolve_test_block_number(block: &BlockNumberOrTag, head: u64) -> u64 {
        match block {
            BlockNumberOrTag::Number(number) => number.to::<u64>(),
            BlockNumberOrTag::Tag(BlockTag::Earliest) => 0,
            BlockNumberOrTag::Tag(_) | BlockNumberOrTag::Latest => head,
        }
    }

    fn topics_match(log: &RpcLog, filters: Option<&Vec<Option<TopicFilter>>>) -> bool {
        let Some(filters) = filters else {
            return true;
        };

        for (index, filter) in filters.iter().enumerate() {
            let Some(filter) = filter else {
                continue;
            };
            let allowed = filter.clone().into_vec();
            if !log.topics.get(index).is_some_and(|topic| allowed.contains(topic)) {
                return false;
            }
        }
        true
    }

    #[test]
    fn web3_client_version() {
        let api = Web3ApiImpl::new();
        let version = Web3ApiServer::client_version(&api).unwrap();
        assert!(version.starts_with("kora/"));
    }

    #[tokio::test]
    async fn eth_chain_id() {
        let api = EthApiImpl::new(1337, NoopStateProvider);
        let chain_id = EthApiServer::chain_id(&api).await.unwrap();
        assert_eq!(chain_id, U64::from(1337));
    }

    #[test]
    fn net_version() {
        let api = NetApiImpl::new(1337);
        let version = NetApiServer::version(&api).unwrap();
        assert_eq!(version, "1337");
    }

    #[tokio::test]
    async fn eth_block_number() {
        let api = EthApiImpl::new(1, NoopStateProvider);
        api.set_block_height(42);
        let block_number = EthApiServer::block_number(&api).await.unwrap();
        assert_eq!(block_number, U64::from(42));
    }

    #[tokio::test]
    async fn gas_price_reflects_recent_transactions() {
        let provider = MockFeeStateProvider::new(vec![
            make_fee_block(0, gwei(1), 21_000, 30_000_000, vec![gwei(2)]),
            make_fee_block(1, gwei(1), 21_000, 30_000_000, vec![gwei(4)]),
            make_fee_block(2, gwei(1), 21_000, 30_000_000, vec![gwei(6)]),
        ]);
        let api = EthApiImpl::new(1, provider);

        let gas_price = EthApiServer::gas_price(&api).await.unwrap();
        let priority_fee = EthApiServer::max_priority_fee_per_gas(&api).await.unwrap();

        assert_eq!(gas_price, gwei(4));
        assert_eq!(priority_fee, gwei(3));
    }

    #[tokio::test]
    async fn gas_price_falls_back_to_base_fee_plus_min_tip_without_transactions() {
        let provider =
            MockFeeStateProvider::new(vec![make_fee_block(0, gwei(5), 0, 30_000_000, vec![])]);
        let api = EthApiImpl::new(1, provider);

        let gas_price = EthApiServer::gas_price(&api).await.unwrap();
        let priority_fee = EthApiServer::max_priority_fee_per_gas(&api).await.unwrap();

        assert_eq!(gas_price, gwei(6));
        assert_eq!(priority_fee, gwei(1));
    }

    #[tokio::test]
    async fn fee_history_uses_indexed_base_fee_and_gas_ratio() {
        let provider = MockFeeStateProvider::new(vec![make_fee_block(
            0,
            gwei(7),
            15_000_000,
            30_000_000,
            vec![],
        )]);
        let api = EthApiImpl::new(1, provider);

        let history = EthApiServer::fee_history(&api, U64::from(1), BlockNumberOrTag::Latest, None)
            .await
            .unwrap();

        assert_eq!(history.oldest_block, U64::ZERO);
        assert_eq!(history.base_fee_per_gas, vec![gwei(7), gwei(7)]);
        assert_eq!(history.gas_used_ratio, vec![0.5]);
        assert!(history.reward.is_none());
    }

    #[tokio::test]
    async fn fee_history_rewards_reflect_actual_tips() {
        let provider = MockFeeStateProvider::new(vec![make_fee_block(
            0,
            gwei(1),
            42_000,
            30_000_000,
            vec![gwei(3), gwei(5)],
        )]);
        let api = EthApiImpl::new(1, provider);

        let history = EthApiServer::fee_history(
            &api,
            U64::from(1),
            BlockNumberOrTag::Latest,
            Some(vec![50.0]),
        )
        .await
        .unwrap();

        let rewards = history.reward.unwrap();
        assert_eq!(rewards, vec![vec![gwei(2)]]);
    }

    #[tokio::test]
    async fn fee_history_rewards_are_zero_for_empty_blocks() {
        let provider =
            MockFeeStateProvider::new(vec![make_fee_block(0, gwei(1), 0, 30_000_000, vec![])]);
        let api = EthApiImpl::new(1, provider);

        let history = EthApiServer::fee_history(
            &api,
            U64::from(1),
            BlockNumberOrTag::Latest,
            Some(vec![25.0, 75.0]),
        )
        .await
        .unwrap();

        let rewards = history.reward.unwrap();
        assert_eq!(rewards, vec![vec![U256::ZERO, U256::ZERO]]);
    }

    #[tokio::test]
    async fn fee_history_reward_uses_gas_used_not_gas_limit() {
        // Two transactions:
        //   tx0: gas_price=3 gwei (tip=2 gwei), gas_limit=1_000_000, gas_used=50_000
        //   tx1: gas_price=11 gwei (tip=10 gwei), gas_limit=21_000, gas_used=21_000
        //
        // With gas_used weighting: total=71_000, 50th pct threshold=35_500.
        // Sorted by tip: [(2 gwei, 50_000), (10 gwei, 21_000)].
        // cumulative after tx0 = 50_000 >= 35_500 => 50th pct = 2 gwei.
        //
        // With the old (buggy) gas_limit weighting: total=1_021_000.
        // threshold=510_500. cumulative after tx0=1_000_000 >= 510_500 => still 2 gwei.
        // Use 75th pct to differentiate: threshold_used=53_250, threshold_limit=765_750.
        // With gas_used: cumulative after tx0=50_000 < 53_250, after tx1=71_000 >= 53_250 => 10 gwei.
        // With gas_limit: cumulative after tx0=1_000_000 >= 765_750 => 2 gwei.
        let block_hash = B256::repeat_byte(0);
        let tx0_hash = B256::repeat_byte(0x10);
        let tx1_hash = B256::repeat_byte(0x11);
        let block = RpcBlock {
            hash: block_hash,
            parent_hash: B256::ZERO,
            sha3_uncles: B256::ZERO,
            number: U64::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: Bytes::new(),
            timestamp: U64::ZERO,
            gas_limit: U64::from(30_000_000),
            gas_used: U64::from(71_000),
            extra_data: Bytes::new(),
            mix_hash: B256::ZERO,
            nonce: Default::default(),
            base_fee_per_gas: Some(gwei(1)),
            miner: Address::ZERO,
            difficulty: U256::ZERO,
            total_difficulty: U256::ZERO,
            uncles: vec![],
            size: U64::ZERO,
            transactions: BlockTransactions::Full(vec![
                RpcTransaction {
                    hash: tx0_hash,
                    nonce: U64::ZERO,
                    block_hash: Some(block_hash),
                    block_number: Some(U64::ZERO),
                    transaction_index: Some(U64::ZERO),
                    from: Address::repeat_byte(0x11),
                    to: Some(Address::repeat_byte(0x22)),
                    value: U256::ZERO,
                    gas: U64::from(1_000_000),
                    gas_price: gwei(3),
                    input: Bytes::new(),
                    tx_type: U64::ZERO,
                    chain_id: None,
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    v: U256::ZERO,
                    r: U256::ZERO,
                    s: U256::ZERO,
                },
                RpcTransaction {
                    hash: tx1_hash,
                    nonce: U64::from(1),
                    block_hash: Some(block_hash),
                    block_number: Some(U64::ZERO),
                    transaction_index: Some(U64::from(1)),
                    from: Address::repeat_byte(0x11),
                    to: Some(Address::repeat_byte(0x22)),
                    value: U256::ZERO,
                    gas: U64::from(21_000),
                    gas_price: gwei(11),
                    input: Bytes::new(),
                    tx_type: U64::ZERO,
                    chain_id: None,
                    max_fee_per_gas: None,
                    max_priority_fee_per_gas: None,
                    v: U256::ZERO,
                    r: U256::ZERO,
                    s: U256::ZERO,
                },
            ]),
            withdrawals: vec![],
            withdrawals_root: B256::ZERO,
        };
        let receipts = vec![
            make_test_receipt(tx0_hash, block_hash, 0, 50_000),
            make_test_receipt(tx1_hash, block_hash, 0, 21_000),
        ];
        let provider = MockFeeStateProvider::new(vec![block]).with_receipts(receipts);
        let api = EthApiImpl::new(1, provider);

        let history = EthApiServer::fee_history(
            &api,
            U64::from(1),
            BlockNumberOrTag::Latest,
            Some(vec![75.0]),
        )
        .await
        .unwrap();

        let rewards = history.reward.unwrap();
        // With gas_used weighting, 75th percentile should be 10 gwei (tx1).
        // With the old gas_limit weighting, it would have been 2 gwei (tx0).
        assert_eq!(rewards, vec![vec![gwei(10)]]);
    }

    #[tokio::test]
    async fn fee_history_rejects_out_of_range_percentiles() {
        let provider =
            MockFeeStateProvider::new(vec![make_fee_block(0, gwei(1), 0, 30_000_000, vec![])]);
        let api = EthApiImpl::new(1, provider);

        let result = EthApiServer::fee_history(
            &api,
            U64::from(1),
            BlockNumberOrTag::Latest,
            Some(vec![150.0]),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fee_history_rejects_non_monotonic_percentiles() {
        let provider =
            MockFeeStateProvider::new(vec![make_fee_block(0, gwei(1), 0, 30_000_000, vec![])]);
        let api = EthApiImpl::new(1, provider);

        let result = EthApiServer::fee_history(
            &api,
            U64::from(1),
            BlockNumberOrTag::Latest,
            Some(vec![75.0, 25.0]),
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fee_history_accepts_valid_monotonic_percentiles() {
        let provider =
            MockFeeStateProvider::new(vec![make_fee_block(0, gwei(1), 0, 30_000_000, vec![])]);
        let api = EthApiImpl::new(1, provider);

        let result = EthApiServer::fee_history(
            &api,
            U64::from(1),
            BlockNumberOrTag::Latest,
            Some(vec![0.0, 25.0, 50.0, 75.0, 100.0]),
        )
        .await;

        assert!(result.is_ok());
    }

    #[test]
    fn effective_priority_fee_eip1559_uses_min_of_tip_and_headroom() {
        // EIP-1559 tx: max_fee=10 gwei, max_priority_fee=3 gwei, base_fee=2 gwei.
        // headroom = max_fee - base_fee = 8 gwei
        // effective tip = min(3, 8) = 3 gwei
        let tx = RpcTransaction {
            hash: B256::ZERO,
            nonce: U64::ZERO,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::ZERO,
            to: None,
            value: U256::ZERO,
            gas: U64::from(21_000),
            gas_price: gwei(10),
            input: Bytes::new(),
            tx_type: U64::from(2),
            chain_id: Some(U64::from(1)),
            max_fee_per_gas: Some(gwei(10)),
            max_priority_fee_per_gas: Some(gwei(3)),
            v: U256::ZERO,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        assert_eq!(effective_priority_fee(&tx, gwei(2)), gwei(3));
    }

    #[test]
    fn effective_priority_fee_eip1559_caps_at_headroom() {
        // EIP-1559 tx: max_fee=5 gwei, max_priority_fee=4 gwei, base_fee=3 gwei.
        // headroom = 5 - 3 = 2 gwei
        // effective tip = min(4, 2) = 2 gwei
        let tx = RpcTransaction {
            hash: B256::ZERO,
            nonce: U64::ZERO,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::ZERO,
            to: None,
            value: U256::ZERO,
            gas: U64::from(21_000),
            gas_price: gwei(5),
            input: Bytes::new(),
            tx_type: U64::from(2),
            chain_id: Some(U64::from(1)),
            max_fee_per_gas: Some(gwei(5)),
            max_priority_fee_per_gas: Some(gwei(4)),
            v: U256::ZERO,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        assert_eq!(effective_priority_fee(&tx, gwei(3)), gwei(2));
    }

    #[test]
    fn effective_priority_fee_indexed_eip1559_without_fields_returns_zero() {
        // Indexed EIP-1559 tx where max_fee_per_gas/max_priority_fee_per_gas
        // are not populated (None), but gas_price holds max_fee_per_gas.
        // The fallback should return zero rather than inflating the tip.
        let tx = RpcTransaction {
            hash: B256::ZERO,
            nonce: U64::ZERO,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::ZERO,
            to: None,
            value: U256::ZERO,
            gas: U64::from(21_000),
            gas_price: gwei(20),
            input: Bytes::new(),
            tx_type: U64::from(2),
            chain_id: Some(U64::from(1)),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            v: U256::ZERO,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        // Without the fix this would return gwei(19), inflating estimates.
        assert_eq!(effective_priority_fee(&tx, gwei(1)), U256::ZERO);
    }

    #[tokio::test]
    async fn gas_price_eip1559_uses_effective_price_not_max_fee() {
        // base_fee = 2 gwei. A type-2 tx with max_fee=20 gwei, tip=3 gwei.
        // Effective price = base_fee + min(tip, max_fee - base_fee) = 2+3 = 5 gwei.
        // Without the fix, the oracle would sample gas_price = max_fee = 20 gwei.
        let provider = MockFeeStateProvider::new(vec![make_eip1559_fee_block(
            0,
            gwei(2),
            21_000,
            30_000_000,
            vec![Eip1559TxParams { max_fee: gwei(20), max_priority_fee: gwei(3) }],
        )]);
        let api = EthApiImpl::new(1, provider);

        let gas_price = EthApiServer::gas_price(&api).await.unwrap();
        // Should be 5 gwei (base + tip), not 20 gwei (max_fee).
        assert_eq!(gas_price, gwei(5));
    }

    #[tokio::test]
    async fn gas_price_never_exceeds_max_price() {
        // Set up a scenario where min_gas_price (base_fee + priority_fee)
        // would exceed max_price. Ensure the oracle respects the cap.
        let config = GasOracleConfig {
            blocks: 1,
            percentile: 60,
            min_price: U256::from(GWEI),
            max_price: gwei(10),
            min_priority_fee: U256::from(GWEI),
        };
        // base_fee = 8 gwei, tx gas_price = 12 gwei
        // Without fix: min_gas_price = base_fee + priority_fee could exceed max_price
        let provider = MockFeeStateProvider::new(vec![make_fee_block(
            0,
            gwei(8),
            21_000,
            30_000_000,
            vec![gwei(12)],
        )]);
        let api = EthApiImpl::new(1, provider).with_gas_oracle_config(config);

        let gas_price = EthApiServer::gas_price(&api).await.unwrap();
        assert!(gas_price <= gwei(10), "gas_price {gas_price} should not exceed max_price 10 gwei");
    }

    #[tokio::test]
    async fn gas_price_allows_exceeding_max_when_base_fee_above_cap() {
        // When the base fee alone is above max_price, the oracle must still
        // return a usable price rather than clamping to max_price.
        let config = GasOracleConfig {
            blocks: 1,
            percentile: 60,
            min_price: U256::from(GWEI),
            max_price: gwei(5),
            min_priority_fee: U256::from(GWEI),
        };
        // base_fee = 10 gwei (above max_price of 5 gwei)
        let provider = MockFeeStateProvider::new(vec![make_fee_block(
            0,
            gwei(10),
            21_000,
            30_000_000,
            vec![gwei(12)],
        )]);
        let api = EthApiImpl::new(1, provider).with_gas_oracle_config(config);

        let gas_price = EthApiServer::gas_price(&api).await.unwrap();
        // Must be at least base_fee + min_priority_fee
        assert!(
            gas_price >= gwei(11),
            "gas_price {gas_price} should be at least base_fee + min_priority_fee when base_fee exceeds cap"
        );
    }

    #[test]
    fn web3_sha3() {
        let api = Web3ApiImpl::new();
        let hash = Web3ApiServer::sha3(&api, Bytes::from_static(b"hello")).unwrap();
        assert_eq!(hash, alloy_primitives::keccak256(b"hello"));
    }

    #[tokio::test]
    async fn eth_send_raw_transaction() {
        let submitted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let submitted_clone = submitted.clone();
        let callback: TxSubmitCallback = Arc::new(move |_| {
            submitted_clone.store(true, std::sync::atomic::Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        });

        let api = EthApiImpl::with_tx_submit(1, NoopStateProvider, callback);
        let tx_data = signed_test_tx(1, 0);
        let result = EthApiServer::send_raw_transaction(&api, tx_data.clone()).await;

        assert!(result.is_ok());
        assert!(submitted.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(result.unwrap(), alloy_primitives::keccak256(&tx_data));
    }

    #[tokio::test]
    async fn eth_send_raw_transaction_broadcasts_after_acceptance() {
        let callback: TxSubmitCallback = Arc::new(move |_| Box::pin(async { Ok(()) }));
        let (pending_tx, mut pending_rx) = pending_tx_channel();
        let (mempool_tx, mut mempool_rx) = mempool_event_channel();
        let api = EthApiImpl::with_tx_submit(1, NoopStateProvider, callback)
            .with_pending_tx_broadcast(pending_tx)
            .with_mempool_broadcast(mempool_tx);
        let tx_data = signed_test_tx(1, 3);
        let hash = EthApiServer::send_raw_transaction(&api, tx_data).await.unwrap();

        let PendingTxEvent::Added(info) = pending_rx.try_recv().unwrap();
        assert_eq!(info.hash, hash);
        assert_eq!(info.full_tx.as_ref().map(|tx| tx.hash), Some(hash));

        assert!(matches!(
            mempool_rx.try_recv().unwrap(),
            MempoolEvent::TxAdded { hash: event_hash, nonce: 3, .. } if event_hash == hash
        ));
    }

    #[tokio::test]
    async fn invalid_raw_transaction_does_not_broadcast() {
        let callback: TxSubmitCallback = Arc::new(move |_| Box::pin(async { Ok(()) }));
        let (pending_tx, mut pending_rx) = pending_tx_channel();
        let (mempool_tx, mut mempool_rx) = mempool_event_channel();
        let api = EthApiImpl::with_tx_submit(1, NoopStateProvider, callback)
            .with_pending_tx_broadcast(pending_tx)
            .with_mempool_broadcast(mempool_tx);

        let result =
            EthApiServer::send_raw_transaction(&api, Bytes::from_static(b"not a tx")).await;

        assert!(result.is_err());
        assert!(pending_rx.try_recv().is_err());
        assert!(mempool_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn eth_get_transaction_by_hash_returns_pending_submission() {
        let callback: TxSubmitCallback = Arc::new(move |_| Box::pin(async { Ok(()) }));
        let api = EthApiImpl::with_tx_submit(1, NoopStateProvider, callback);
        let tx_data = signed_test_tx(1, 7);
        let hash = EthApiServer::send_raw_transaction(&api, tx_data).await.unwrap();

        let tx = EthApiServer::get_transaction_by_hash(&api, hash).await.unwrap();
        let tx = tx.expect("pending transaction should be visible");
        assert_eq!(tx.hash, hash);
        assert_eq!(tx.nonce, U64::from(7));
        assert!(tx.block_hash.is_none());
    }

    /// Regression: when no `tx_submit` callback is wired, `send_raw_transaction`
    /// silently accepts the tx and returns the hash, but the tx goes nowhere —
    /// no mempool, no producer, no block. This is exactly the failure mode
    /// observed on devnet 1337 (`http://65.109.61.210:8545`) where the deployed
    /// kora binary predates the runner's `with_tx_submit(...)` wiring (commit
    /// `beb637a`): every tx submitted via JSON-RPC was accepted, hash returned,
    /// but never included in any block.
    ///
    /// The fix lives in the runner: always wire `tx_submit` to a real mempool.
    /// The downstream observability fix (warn-log when build_block produces an
    /// empty block while the mempool is non-empty) lives in `app.rs`.
    #[tokio::test]
    async fn send_raw_transaction_with_no_callback_silently_accepts_but_drops() {
        let api = EthApiImpl::new(1, NoopStateProvider); // no tx_submit
        let tx_data = signed_test_tx(1, 0);
        let result = EthApiServer::send_raw_transaction(&api, tx_data.clone()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), alloy_primitives::keccak256(&tx_data));
        // The tx is in pending_txs (so getTransactionByHash returns something) —
        // that's exactly what makes the bug invisible to operators.
        let cached =
            EthApiServer::get_transaction_by_hash(&api, alloy_primitives::keccak256(&tx_data))
                .await
                .unwrap();
        assert!(
            cached.is_some(),
            "RPC caches the tx for visibility even though it has nowhere to send it"
        );
    }

    /// Regression: the existing `eth_send_raw_transaction` test only verifies
    /// that the callback is invoked (a boolean flag). It does not verify that
    /// the bytes passed to the callback are the same bytes the caller sent.
    /// A regression that mangled the body (e.g. dropped the chainId, re-encoded
    /// the envelope, sent a partial slice) would still pass that test. This
    /// one captures the actual bytes and compares them.
    #[tokio::test]
    async fn send_raw_transaction_passes_full_tx_bytes_to_callback() {
        let captured: Arc<RwLock<Vec<Bytes>>> = Arc::new(RwLock::new(Vec::new()));
        let captured_clone = captured.clone();
        let callback: TxSubmitCallback = Arc::new(move |data| {
            let captured_clone = captured_clone.clone();
            Box::pin(async move {
                captured_clone.write().await.push(data);
                Ok(())
            })
        });
        let api = EthApiImpl::with_tx_submit(1, NoopStateProvider, callback);
        let tx_data = signed_test_tx(1, 42);
        let _ = EthApiServer::send_raw_transaction(&api, tx_data.clone()).await.unwrap();
        let inner = captured.read().await;
        assert_eq!(inner.len(), 1, "callback invoked exactly once");
        assert_eq!(
            &inner[0][..],
            &tx_data[..],
            "callback receives the caller's tx bytes verbatim — no re-encoding, no truncation"
        );
    }

    #[tokio::test]
    async fn eth_block_filter_lifecycle() {
        let provider = TestStateProvider::default();
        provider.insert_block(1, B256::repeat_byte(1)).await;
        let api = EthApiImpl::new(1, provider.clone());

        let filter_id = EthApiServer::new_block_filter(&api).await.unwrap();
        provider.insert_block(2, B256::repeat_byte(2)).await;
        provider.insert_block(3, B256::repeat_byte(3)).await;

        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Hashes(hashes) = changes else {
            panic!("block filter should return hashes");
        };
        assert_eq!(hashes, vec![B256::repeat_byte(2), B256::repeat_byte(3)]);

        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Hashes(hashes) = changes else {
            panic!("block filter should return hashes");
        };
        assert!(hashes.is_empty());

        assert!(EthApiServer::uninstall_filter(&api, filter_id).await.unwrap());
        assert!(!EthApiServer::uninstall_filter(&api, filter_id).await.unwrap());
        let err = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap_err();
        assert_eq!(err.code(), crate::error_codes::SERVER_ERROR);
    }

    #[tokio::test]
    async fn eth_log_filter_lifecycle() {
        let provider = TestStateProvider::default();
        let target = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);
        let topic = B256::repeat_byte(0xaa);

        provider.insert_block(1, B256::repeat_byte(1)).await;
        provider.insert_log(1, target, vec![topic]).await;
        let api = EthApiImpl::new(1, provider.clone());
        let filter_id = EthApiServer::new_filter(
            &api,
            RpcLogFilter {
                address: Some(AddressFilter::Single(target)),
                topics: Some(vec![Some(TopicFilter::Single(topic))]),
                ..RpcLogFilter::default()
            },
        )
        .await
        .unwrap();

        provider.insert_block(2, B256::repeat_byte(2)).await;
        provider.insert_log(2, target, vec![topic]).await;
        provider.insert_log(2, other, vec![topic]).await;

        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Logs(logs) = changes else {
            panic!("log filter should return logs");
        };
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, target);
        assert_eq!(logs[0].block_number, U64::from(2));

        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Logs(logs) = changes else {
            panic!("log filter should return logs");
        };
        assert!(logs.is_empty());

        let all_logs = EthApiServer::get_filter_logs(&api, filter_id).await.unwrap();
        assert_eq!(all_logs.len(), 2);
    }

    #[tokio::test]
    async fn eth_pending_transaction_filter_lifecycle() {
        let callback: TxSubmitCallback = Arc::new(move |_| Box::pin(async { Ok(()) }));
        let api = EthApiImpl::with_tx_submit(1, NoopStateProvider, callback);

        let existing =
            EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 0)).await.unwrap();
        let filter_id = EthApiServer::new_pending_transaction_filter(&api).await.unwrap();
        let new = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 1)).await.unwrap();

        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Hashes(hashes) = changes else {
            panic!("pending transaction filter should return hashes");
        };
        assert_eq!(hashes, vec![new]);
        assert!(!hashes.contains(&existing));

        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Hashes(hashes) = changes else {
            panic!("pending transaction filter should return hashes");
        };
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn eth_log_filter_block_hash_returns_once() {
        let provider = TestStateProvider::default();
        let target = Address::repeat_byte(0x11);
        let topic = B256::repeat_byte(0xaa);
        let block_hash = B256::repeat_byte(1);

        provider.insert_block(1, block_hash).await;
        provider.insert_log(1, target, vec![topic]).await;

        let api = EthApiImpl::new(1, provider.clone());
        let filter_id = EthApiServer::new_filter(
            &api,
            RpcLogFilter { block_hash: Some(block_hash), ..RpcLogFilter::default() },
        )
        .await
        .unwrap();

        // First poll returns the matching logs.
        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Logs(logs) = changes else {
            panic!("log filter should return logs");
        };
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].address, target);

        // Advance the chain and confirm subsequent polls return empty.
        provider.insert_block(2, B256::repeat_byte(2)).await;
        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        assert_eq!(changes, FilterChanges::Logs(Vec::new()));
    }

    #[tokio::test]
    async fn eth_get_filter_logs_rejects_non_log_filter() {
        let provider = TestStateProvider::default();
        provider.insert_block(1, B256::repeat_byte(1)).await;
        let api = EthApiImpl::new(1, provider);

        let filter_id = EthApiServer::new_block_filter(&api).await.unwrap();
        let err = EthApiServer::get_filter_logs(&api, filter_id).await.unwrap_err();
        assert_eq!(err.code(), crate::error_codes::SERVER_ERROR);
    }

    #[tokio::test]
    async fn eth_get_filter_changes_invalid_id() {
        let api = EthApiImpl::new(1, NoopStateProvider);

        // Non-existent filter id.
        let err = EthApiServer::get_filter_changes(&api, U256::from(999)).await.unwrap_err();
        assert_eq!(err.code(), crate::error_codes::SERVER_ERROR);

        // Overflowing filter id (> u64::MAX).
        let overflow = U256::from(u64::MAX).wrapping_add(U256::from(1));
        let err = EthApiServer::get_filter_changes(&api, overflow).await.unwrap_err();
        assert_eq!(err.code(), crate::error_codes::SERVER_ERROR);
    }

    #[test]
    fn filter_id_to_u64_edge_cases() {
        assert_eq!(filter_id_to_u64(U256::ZERO), Some(0));
        assert_eq!(filter_id_to_u64(U256::from(1)), Some(1));
        assert_eq!(filter_id_to_u64(U256::from(u64::MAX)), Some(u64::MAX));
        assert_eq!(filter_id_to_u64(U256::from(u64::MAX).wrapping_add(U256::from(1))), None);
        assert_eq!(filter_id_to_u64(U256::MAX), None);
    }

    // --- Unit tests for helper functions ---

    #[test]
    fn calculate_next_base_fee_at_target() {
        // Gas used == target (half of limit): base fee unchanged.
        let base_fee = gwei(10);
        assert_eq!(calculate_next_base_fee(base_fee, 15_000_000, 30_000_000), base_fee);
    }

    #[test]
    fn calculate_next_base_fee_above_target() {
        let next = calculate_next_base_fee(gwei(10), 20_000_000, 30_000_000);
        assert!(next > gwei(10), "base fee should increase when gas exceeds target");
    }

    #[test]
    fn calculate_next_base_fee_below_target() {
        let next = calculate_next_base_fee(gwei(10), 5_000_000, 30_000_000);
        assert!(next < gwei(10), "base fee should decrease when gas is below target");
    }

    #[test]
    fn calculate_next_base_fee_zero_gas_limit() {
        assert_eq!(calculate_next_base_fee(gwei(10), 0, 0), gwei(10));
    }

    #[test]
    fn percentile_value_at_extremes() {
        let mut values = vec![gwei(1), gwei(5), gwei(10)];
        assert_eq!(percentile_value(&mut values, 0), Some(gwei(1)));
        assert_eq!(percentile_value(&mut values, 100), Some(gwei(10)));
    }

    #[test]
    fn percentile_value_empty_returns_none() {
        let mut values: Vec<U256> = vec![];
        assert_eq!(percentile_value(&mut values, 50), None);
    }

    #[test]
    fn resolve_fee_history_newest_earliest_tag() {
        let result = resolve_fee_history_newest(BlockNumberOrTag::Tag(BlockTag::Earliest), 1000);
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn fee_history_multi_block_returns_correct_structure() {
        let provider = MockFeeStateProvider::new(vec![
            make_fee_block(0, gwei(1), 10_000_000, 30_000_000, vec![gwei(2)]),
            make_fee_block(1, gwei(2), 20_000_000, 30_000_000, vec![gwei(4)]),
            make_fee_block(2, gwei(3), 25_000_000, 30_000_000, vec![gwei(6)]),
        ]);
        let api = EthApiImpl::new(1, provider);

        let history = EthApiServer::fee_history(&api, U64::from(3), BlockNumberOrTag::Latest, None)
            .await
            .unwrap();

        assert_eq!(history.oldest_block, U64::ZERO);
        // 3 blocks + 1 predicted next base fee = 4 entries.
        assert_eq!(history.base_fee_per_gas.len(), 4);
        assert_eq!(history.gas_used_ratio.len(), 3);
        assert!(history.reward.is_none());
    }

    #[test]
    fn effective_gas_price_for_sampling_legacy_tx() {
        let tx = RpcTransaction {
            hash: B256::ZERO,
            nonce: U64::ZERO,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::ZERO,
            to: None,
            value: U256::ZERO,
            gas: U64::from(21_000),
            gas_price: gwei(15),
            input: Bytes::new(),
            tx_type: U64::ZERO,
            chain_id: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            v: U256::ZERO,
            r: U256::ZERO,
            s: U256::ZERO,
        };

        assert_eq!(effective_gas_price_for_sampling(&tx, gwei(1)), gwei(15));
    }

    #[test]
    fn block_gas_used_ratio_edge_cases() {
        assert_eq!(block_gas_used_ratio(100, 0), 0.0);
        assert_eq!(block_gas_used_ratio(30_000_000, 30_000_000), 1.0);
    }

    #[tokio::test]
    async fn pending_tx_cache_evicts_oldest_when_over_limit() {
        let callback: TxSubmitCallback = Arc::new(move |_| Box::pin(async { Ok(()) }));
        let api =
            EthApiImpl::with_tx_submit(1, NoopStateProvider, callback).with_max_pending_txs(3);

        // Submit 4 transactions with a cap of 3.
        let h0 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 0)).await.unwrap();
        let _h1 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 1)).await.unwrap();
        let _h2 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 2)).await.unwrap();
        let h3 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 3)).await.unwrap();

        // The oldest transaction (h0) should have been evicted.
        let txs = api.pending_txs.read().await;
        assert_eq!(txs.len(), 3, "map must be bounded to the cap");
        assert!(!txs.contains_key(&h0), "oldest tx should be evicted");
        assert!(txs.contains_key(&h3), "newest tx should still be present");
        drop(txs);

        let order = api.pending_tx_order.read().await;
        assert_eq!(order.len(), 3, "order deque must be bounded to the cap");
    }

    #[tokio::test]
    async fn pending_tx_filter_works_after_eviction() {
        let callback: TxSubmitCallback = Arc::new(move |_| Box::pin(async { Ok(()) }));
        let api =
            EthApiImpl::with_tx_submit(1, NoopStateProvider, callback).with_max_pending_txs(3);

        // Submit 3 transactions, then create a filter.
        let _h0 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 0)).await.unwrap();
        let _h1 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 1)).await.unwrap();
        let _h2 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 2)).await.unwrap();
        let filter_id = EthApiServer::new_pending_transaction_filter(&api).await.unwrap();

        // Submit 2 more which trigger eviction of h0 and h1.
        let h3 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 3)).await.unwrap();
        let h4 = EthApiServer::send_raw_transaction(&api, signed_test_tx(1, 4)).await.unwrap();

        // Filter changes should report the newly added hashes.
        let changes = EthApiServer::get_filter_changes(&api, filter_id).await.unwrap();
        let FilterChanges::Hashes(hashes) = changes else {
            panic!("pending transaction filter should return hashes");
        };
        assert!(hashes.contains(&h3), "new tx after filter creation should appear");
        assert!(hashes.contains(&h4), "new tx after filter creation should appear");
    }
}
