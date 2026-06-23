//! Ledger services for Kora nodes.

#![doc = include_str!("../README.md")]
#![doc(issue_tracker_base_url = "https://github.com/refcell/kora/issues/")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

mod live_state;

use std::{collections::BTreeSet, fmt, sync::Arc, time::Duration};

use alloy_primitives::{Address, B256, U256};
use commonware_consensus::Block as _;
use commonware_cryptography::Committable as _;
use commonware_runtime::{Supervisor as _, tokio};
use futures::{channel::mpsc::UnboundedReceiver, lock::Mutex};
use kora_consensus::{
    ConsensusError, Mempool as _, SeedTracker as _, Snapshot, SnapshotStore as _,
    components::{InMemorySeedTracker, InMemorySnapshotStore},
};
use kora_domain::{
    Block, BlockId, ConsensusDigest, LedgerEvent, LedgerEvents, StateRoot, Tx, TxId,
};
use kora_overlay::OverlayState;
use kora_qmdb::StateRoot as QmdbStateRoot;
use kora_qmdb_ledger::{Error as QmdbError, QmdbChangeSet, QmdbConfig, QmdbLedger, QmdbState};
use kora_traits::{StateDbError, StateDbRead};
use kora_txpool::{PoolConfig, TransactionPool};
pub use live_state::LiveState;
use thiserror::Error;

/// Snapshot type used by the ledger.
pub type LedgerSnapshot = Snapshot<OverlayState<QmdbState>>;

/// Ledger mempool adapter backed by the transaction pool.
#[derive(Clone, Debug)]
pub struct LedgerMempool {
    pool: TransactionPool,
}

impl LedgerMempool {
    /// Create a new ledger mempool adapter.
    pub fn new(config: PoolConfig) -> Self {
        Self { pool: TransactionPool::new(config) }
    }

    /// Return the underlying transaction pool handle.
    pub fn txpool(&self) -> TransactionPool {
        self.pool.clone()
    }
}

impl kora_consensus::Mempool for LedgerMempool {
    fn insert(&self, tx: Tx) -> bool {
        kora_txpool::Mempool::insert(&self.pool, tx)
    }

    fn build(&self, max_txs: usize, excluded: &BTreeSet<TxId>) -> Vec<Tx> {
        kora_txpool::Mempool::build(&self.pool, max_txs, excluded)
    }

    fn prune(&self, tx_ids: &[TxId]) {
        kora_txpool::Mempool::prune(&self.pool, tx_ids);
    }

    fn len(&self) -> usize {
        kora_txpool::Mempool::len(&self.pool)
    }
}

fn tx_ids(txs: &[Tx]) -> BTreeSet<TxId> {
    txs.iter().map(Tx::id).collect()
}

/// Errors surfaced by ledger services.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// QMDB-backed storage error.
    #[error("qmdb error: {0}")]
    Qmdb(#[from] QmdbError),
    /// Snapshot store or consensus component error.
    #[error("consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    /// State database error.
    #[error("state db error: {0}")]
    StateDb(#[from] StateDbError),
}

/// Result alias for ledger operations.
pub type LedgerResult<T> = Result<T, LedgerError>;

/// Ledger view that owns the mutexed execution state.
#[derive(Clone)]
pub struct LedgerView {
    /// Mutex-protected running state.
    inner: Arc<Mutex<LedgerState>>,
    /// Genesis block stored so the automaton can replay from height 0.
    genesis_block: Block,
    /// Notifier signalled whenever a new snapshot is inserted, allowing
    /// waiters to be woken event-driven instead of polling with sleep.
    snapshot_notify: Arc<::tokio::sync::Notify>,
}

impl fmt::Debug for LedgerView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerView").finish_non_exhaustive()
    }
}

/// Internal ledger state guarded by the mutex inside `LedgerView`.
struct LedgerState {
    /// Pending transactions that are not yet included in finalized blocks.
    mempool: LedgerMempool,
    /// Execution snapshots indexed by digest so we can replay ancestors.
    snapshots: InMemorySnapshotStore<OverlayState<QmdbState>>,
    /// Digest of the latest executed snapshot known to the ledger.
    head: ConsensusDigest,
    /// Cached seeds for each digest used to compute prevrandao.
    seeds: InMemorySeedTracker,
    /// Underlying QMDB ledger service for persistence.
    qmdb: QmdbLedger,
}

impl LedgerView {
    /// Initialize a ledger view with a QMDB backend built from the provided settings.
    pub async fn init(
        context: tokio::Context,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> LedgerResult<Self> {
        Self::init_with_genesis_timestamp(context, partition_prefix, genesis_alloc, 0).await
    }

    /// Initialize a ledger view with an explicit genesis block timestamp.
    pub async fn init_with_genesis_timestamp(
        context: tokio::Context,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
        genesis_timestamp: u64,
    ) -> LedgerResult<Self> {
        let config = QmdbConfig::new(partition_prefix);
        Self::init_with_config_and_genesis_timestamp(
            context,
            config,
            genesis_alloc,
            genesis_timestamp,
        )
        .await
    }

    /// Initialize a ledger view, optionally applying the genesis allocation to QMDB.
    pub async fn init_with_genesis(
        context: tokio::Context,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
        apply_genesis: bool,
    ) -> LedgerResult<Self> {
        let config = QmdbConfig::new(partition_prefix);
        Self::init_with_config_and_genesis(context, config, genesis_alloc, apply_genesis).await
    }

    /// Initialize a ledger view with explicit timestamp and control over genesis allocation.
    pub async fn init_with_genesis_options(
        context: tokio::Context,
        partition_prefix: String,
        genesis_alloc: Vec<(Address, U256)>,
        apply_genesis: bool,
        genesis_timestamp: u64,
    ) -> LedgerResult<Self> {
        let config = QmdbConfig::new(partition_prefix);
        Self::init_with_config_and_genesis_options(
            context,
            config,
            genesis_alloc,
            apply_genesis,
            genesis_timestamp,
        )
        .await
    }

    /// Initialize a ledger view with an explicit QMDB configuration.
    pub async fn init_with_config(
        context: tokio::Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> LedgerResult<Self> {
        Self::init_with_config_and_genesis(context, config, genesis_alloc, true).await
    }

    /// Initialize a ledger view with explicit QMDB and genesis timestamp configuration.
    pub async fn init_with_config_and_genesis_timestamp(
        context: tokio::Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
        genesis_timestamp: u64,
    ) -> LedgerResult<Self> {
        Self::init_with_config_and_genesis_options(
            context,
            config,
            genesis_alloc,
            true,
            genesis_timestamp,
        )
        .await
    }

    /// Initialize a ledger view with control over whether genesis is applied to QMDB.
    pub async fn init_with_config_and_genesis(
        context: tokio::Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
        apply_genesis: bool,
    ) -> LedgerResult<Self> {
        Self::init_with_config_and_genesis_options(context, config, genesis_alloc, apply_genesis, 0)
            .await
    }

    /// Initialize a ledger view with explicit QMDB, apply-genesis and timestamp configuration.
    pub async fn init_with_config_and_genesis_options(
        context: tokio::Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
        apply_genesis: bool,
        genesis_timestamp: u64,
    ) -> LedgerResult<Self> {
        let qmdb = QmdbLedger::init_with_genesis(
            context.child("qmdb"),
            config,
            genesis_alloc,
            apply_genesis,
        )
        .await?;
        let genesis_root = qmdb.root().await?;

        let genesis_block = Block::new(
            BlockId(B256::ZERO),
            0,
            genesis_timestamp,
            B256::ZERO,
            genesis_root,
            Vec::new(),
        );
        let genesis_digest = genesis_block.commitment();
        let state = OverlayState::new(qmdb.state(), QmdbChangeSet::default());
        let snapshots = InMemorySnapshotStore::new();
        let genesis_snapshot = Snapshot::new(
            None,
            state,
            genesis_block.state_root,
            QmdbChangeSet::default(),
            BTreeSet::new(),
        );
        snapshots.insert(genesis_digest, genesis_snapshot);
        snapshots.mark_persisted(&[genesis_digest]);

        Ok(Self {
            inner: Arc::new(Mutex::new(LedgerState {
                mempool: LedgerMempool::new(PoolConfig::default()),
                snapshots,
                head: genesis_digest,
                seeds: InMemorySeedTracker::new(genesis_digest),
                qmdb,
            })),
            genesis_block,
            snapshot_notify: Arc::new(::tokio::sync::Notify::new()),
        })
    }

    /// Return the genesis block of this ledger.
    pub fn genesis_block(&self) -> Block {
        self.genesis_block.clone()
    }

    /// Return a cloneable handle to the underlying QMDB state.
    ///
    /// The returned handle shares the same backing store and can be used
    /// for read-only queries (balance, nonce, code, storage) without
    /// acquiring the ledger mutex.
    pub async fn qmdb_state(&self) -> QmdbState {
        let inner = self.inner.lock().await;
        inner.qmdb.state()
    }

    /// Submit a transaction into the mempool.
    pub async fn submit_tx(&self, tx: Tx) -> bool {
        let inner = self.inner.lock().await;
        inner.mempool.insert(tx)
    }

    /// Return a handle to the transaction pool.
    pub async fn txpool(&self) -> TransactionPool {
        let inner = self.inner.lock().await;
        inner.mempool.txpool()
    }

    /// Return an overlay for the latest executed state known to the ledger.
    pub async fn latest_state(&self) -> OverlayState<QmdbState> {
        let inner = self.inner.lock().await;
        inner
            .snapshots
            .get(&inner.head)
            .map(|snapshot| snapshot.state)
            .unwrap_or_else(|| OverlayState::new(inner.qmdb.state(), QmdbChangeSet::default()))
    }

    /// Query a balance at the given digest.
    pub async fn query_balance(&self, digest: ConsensusDigest, address: Address) -> Option<U256> {
        let snapshot = {
            let inner = self.inner.lock().await;
            inner.snapshots.get(&digest)
        }?;
        snapshot.state.balance(&address).await.ok()
    }

    /// Query a state root at the given digest.
    pub async fn query_state_root(&self, digest: ConsensusDigest) -> Option<StateRoot> {
        let inner = self.inner.lock().await;
        inner.snapshots.get(&digest).map(|snapshot| snapshot.state_root)
    }

    /// Query the cached seed at the given digest.
    pub async fn query_seed(&self, digest: ConsensusDigest) -> Option<B256> {
        let inner = self.inner.lock().await;
        inner.seeds.get(&digest)
    }

    /// Return the seed associated with a parent digest.
    pub async fn seed_for_parent(&self, parent: ConsensusDigest) -> Option<B256> {
        let inner = self.inner.lock().await;
        inner.seeds.get(&parent)
    }

    /// Store the seed hash for a digest.
    pub async fn set_seed(&self, digest: ConsensusDigest, seed_hash: B256) {
        let inner = self.inner.lock().await;
        inner.seeds.insert(digest, seed_hash);
    }

    /// Fetch the parent snapshot for a given digest.
    pub async fn parent_snapshot(&self, parent: ConsensusDigest) -> Option<LedgerSnapshot> {
        let inner = self.inner.lock().await;
        inner.snapshots.get(&parent)
    }

    /// Insert a snapshot for a block digest.
    pub async fn insert_snapshot(
        &self,
        digest: ConsensusDigest,
        parent: ConsensusDigest,
        state: OverlayState<QmdbState>,
        root: StateRoot,
        qmdb_changes: QmdbChangeSet,
        txs: &[Tx],
    ) {
        let mut inner = self.inner.lock().await;
        let ids = tx_ids(txs);
        inner.snapshots.insert(digest, Snapshot::new(Some(parent), state, root, qmdb_changes, ids));
        inner.head = digest;
        drop(inner);
        self.snapshot_notify.notify_waiters();
    }

    /// Cache a snapshot that has already been constructed.
    pub async fn cache_snapshot(&self, digest: ConsensusDigest, snapshot: LedgerSnapshot) {
        let mut inner = self.inner.lock().await;
        inner.snapshots.insert(digest, snapshot);
        inner.head = digest;
        drop(inner);
        self.snapshot_notify.notify_waiters();
    }

    /// Restore a finalized block as an already-persisted snapshot over the current QMDB state.
    ///
    /// The resulting snapshot is marked as *unverified* because it was not
    /// produced by full local execution -- the overlay has an empty changeset
    /// that falls through to the QMDB base layer. Callers must not use it as
    /// a parent for building new proposals until QMDB has committed this
    /// block's state transitions.
    pub async fn restore_persisted_snapshot(&self, block: &Block) {
        let mut inner = self.inner.lock().await;
        let digest = block.commitment();
        let state = OverlayState::new(inner.qmdb.state(), QmdbChangeSet::default());
        let snapshot = Snapshot::new_unverified(
            Some(block.parent()),
            state,
            block.state_root,
            QmdbChangeSet::default(),
            tx_ids(&block.txs),
        );
        inner.snapshots.insert(digest, snapshot);
        inner.snapshots.mark_persisted(&[digest]);
        inner.head = digest;
        drop(inner);
        self.snapshot_notify.notify_waiters();
    }

    /// Wait for a parent snapshot to become available, with a timeout.
    ///
    /// Instead of polling with fixed sleep intervals, this method awaits the
    /// internal [`Notify`](::tokio::sync::Notify) that fires whenever a new
    /// snapshot is inserted. Falls back to the timeout if the snapshot never
    /// arrives.
    pub async fn wait_for_snapshot(
        &self,
        parent: ConsensusDigest,
        timeout: Duration,
    ) -> Option<LedgerSnapshot> {
        let deadline = ::tokio::time::Instant::now() + timeout;
        loop {
            // Register the notification future BEFORE checking the snapshot.
            // This eliminates the race window where `notify_waiters()` fires
            // between the check and the wait, which would cause a lost
            // wake-up and an unnecessary full-timeout delay.
            let notified = self.snapshot_notify.notified();
            if let Some(snap) = self.parent_snapshot(parent).await {
                return Some(snap);
            }
            let remaining = deadline.saturating_duration_since(::tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            // Wait for any snapshot insertion, or the remaining timeout.
            let _ = ::tokio::time::timeout(remaining, notified).await;
        }
        None
    }

    /// Fetch the components needed to build a proposal.
    pub async fn proposal_components(
        &self,
    ) -> (OverlayState<QmdbState>, LedgerMempool, InMemorySnapshotStore<OverlayState<QmdbState>>)
    {
        let inner = self.inner.lock().await;
        let root_state = OverlayState::new(inner.qmdb.state(), QmdbChangeSet::default());
        (root_state, inner.mempool.clone(), inner.snapshots.clone())
    }

    /// Compute a preview root as if all unpersisted ancestors plus `changes` were applied.
    ///
    /// Note: QMDB roots include commit metadata, so persisted roots can differ from this preview.
    #[cfg(test)]
    pub async fn compute_root(
        &self,
        parent: ConsensusDigest,
        changes: &QmdbChangeSet,
    ) -> LedgerResult<StateRoot> {
        self.compute_root_from_store(parent, changes).await
    }

    /// Compute the deterministic consensus root for a state transition.
    ///
    /// Takes `changes` by reference to avoid cloning the entire changeset
    /// (which contains BTreeMaps of account updates and storage slots).
    pub async fn compute_root_from_store(
        &self,
        parent: ConsensusDigest,
        changes: &QmdbChangeSet,
    ) -> LedgerResult<StateRoot> {
        let parent_root = {
            let inner = self.inner.lock().await;
            inner.snapshots.get(&parent).ok_or(ConsensusError::SnapshotNotFound(parent))?.state_root
        };
        Ok(StateRoot(QmdbStateRoot::transition(parent_root.0, changes)))
    }

    /// Persist `digest` and any missing ancestors to QMDB.
    ///
    /// Returns `Ok(true)` if a new commit happened, or `Ok(false)` if the digest is already
    /// persisted or currently being persisted by another task.
    pub async fn persist_snapshot(&self, digest: ConsensusDigest) -> LedgerResult<bool> {
        let (changes, qmdb, chain) = {
            let inner = self.inner.lock().await;
            let (chain, changes) = inner.snapshots.changes_for_persist(digest)?;
            if chain.is_empty() {
                return Ok(false);
            }
            if !inner.snapshots.can_persist_chain(&chain) {
                return Ok(false);
            }
            inner.snapshots.mark_persisting_chain(&chain);
            (changes, inner.qmdb.clone(), chain)
        };

        let result = qmdb.commit_changes(changes).await;
        {
            let inner = self.inner.lock().await;
            inner.snapshots.clear_persisting_chain(&chain);
            match result {
                Ok(_) => {
                    for digest in &chain {
                        let snapshot = inner
                            .snapshots
                            .get(digest)
                            .ok_or(ConsensusError::SnapshotNotFound(*digest))?;
                        let compact_state =
                            OverlayState::new(inner.qmdb.state(), QmdbChangeSet::default());
                        inner.snapshots.insert(
                            *digest,
                            Snapshot::new(
                                snapshot.parent,
                                compact_state,
                                snapshot.state_root,
                                QmdbChangeSet::default(),
                                snapshot.tx_ids,
                            ),
                        );
                    }
                    inner.snapshots.mark_persisted(&chain);
                    // Evict oldest persisted snapshots to bound memory usage.
                    // Must happen inside the ledger mutex to prevent a TOCTOU
                    // race where another thread reads a snapshot between
                    // mark_persisted() and eviction.
                    inner.snapshots.evict_persisted();
                    Ok(())
                }
                Err(err) => Err(LedgerError::from(err)),
            }
        }?;
        Ok(true)
    }

    /// Remove transactions that are included in a block from the mempool.
    pub async fn prune_mempool(&self, txs: &[Tx]) {
        let inner = self.inner.lock().await;
        let tx_ids: Vec<TxId> = txs.iter().map(Tx::id).collect();
        inner.mempool.prune(&tx_ids);
    }

    /// Remove transactions with stale nonces from the mempool.
    ///
    /// For each sender with transactions in the pool, queries the finalized
    /// QMDB state for the current account nonce and removes all transactions
    /// whose nonce is below that value.  This catches stale transactions that
    /// were not literally included in the finalized block but whose nonces
    /// have been consumed by other transactions in earlier blocks.
    pub async fn prune_stale_nonces(&self) {
        let (pool, qmdb_state) = {
            let inner = self.inner.lock().await;
            (inner.mempool.txpool(), inner.qmdb.state())
        };

        let senders = pool.senders();
        if senders.is_empty() {
            return;
        }

        for sender in senders {
            let finalized_nonce = match qmdb_state.nonce(&sender).await {
                Ok(n) => n,
                Err(err) => {
                    tracing::warn!(%sender, error = ?err, "failed to query nonce during stale-nonce pruning");
                    continue;
                }
            };

            // The finalized nonce is the *next* nonce to be used, so all
            // transactions with nonce < finalized_nonce are confirmed/stale.
            if finalized_nonce > 0 {
                pool.remove_confirmed(&sender, finalized_nonce - 1);
            }
        }
    }

    /// Returns `true` if the snapshot for `digest` has been persisted to QMDB
    /// (even if the in-memory snapshot data has since been evicted).
    pub async fn is_snapshot_persisted(&self, digest: &ConsensusDigest) -> bool {
        let inner = self.inner.lock().await;
        inner.snapshots.is_persisted(digest)
    }

    /// Return snapshot store statistics: `(total, unpersisted)`.
    ///
    /// - `total`: number of snapshots currently held in memory.
    /// - `unpersisted`: number of snapshots not yet persisted to QMDB.
    pub async fn snapshot_store_stats(&self) -> (usize, usize) {
        let inner = self.inner.lock().await;
        (inner.snapshots.len(), inner.snapshots.unpersisted_count())
    }
}

/// Domain service that exposes high-level ledger commands.
#[derive(Clone)]
pub struct LedgerService {
    view: LedgerView,
    events: LedgerEvents,
}

impl fmt::Debug for LedgerService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerService").finish_non_exhaustive()
    }
}

impl LedgerService {
    /// Create a new ledger service from a ledger view.
    pub fn new(view: LedgerView) -> Self {
        Self { view, events: LedgerEvents::new() }
    }

    fn publish(&self, event: LedgerEvent) {
        self.events.publish(event);
    }

    /// Subscribe to ledger events.
    pub fn subscribe(&self) -> UnboundedReceiver<LedgerEvent> {
        self.events.subscribe()
    }

    /// Return the genesis block.
    pub fn genesis_block(&self) -> Block {
        self.view.genesis_block()
    }

    /// Submit a transaction and emit events.
    pub async fn submit_tx(&self, tx: Tx) -> bool {
        let tx_id = tx.id();
        let inserted = self.view.submit_tx(tx).await;
        if inserted {
            self.publish(LedgerEvent::TransactionSubmitted(tx_id));
        }
        inserted
    }

    /// Return a handle to the transaction pool.
    pub async fn txpool(&self) -> TransactionPool {
        self.view.txpool().await
    }

    /// Return an overlay for the latest executed state known to the ledger.
    pub async fn latest_state(&self) -> OverlayState<QmdbState> {
        self.view.latest_state().await
    }

    /// Query a balance at the given digest.
    pub async fn query_balance(&self, digest: ConsensusDigest, address: Address) -> Option<U256> {
        self.view.query_balance(digest, address).await
    }

    /// Query the stored state root at the given digest.
    pub async fn query_state_root(&self, digest: ConsensusDigest) -> Option<StateRoot> {
        self.view.query_state_root(digest).await
    }

    /// Query the cached seed at the given digest.
    pub async fn query_seed(&self, digest: ConsensusDigest) -> Option<B256> {
        self.view.query_seed(digest).await
    }

    /// Query the seed for a parent digest.
    pub async fn seed_for_parent(&self, parent: ConsensusDigest) -> Option<B256> {
        self.view.seed_for_parent(parent).await
    }

    /// Store the seed for a digest and publish an event.
    pub async fn set_seed(&self, digest: ConsensusDigest, seed_hash: B256) {
        self.view.set_seed(digest, seed_hash).await;
        self.publish(LedgerEvent::SeedUpdated(digest, seed_hash));
    }

    /// Fetch the snapshot of a parent digest.
    pub async fn parent_snapshot(&self, parent: ConsensusDigest) -> Option<LedgerSnapshot> {
        self.view.parent_snapshot(parent).await
    }

    /// Wait for a parent snapshot to become available, with a timeout.
    ///
    /// Uses event-driven notification rather than polling with sleep.
    /// See [`LedgerView::wait_for_snapshot`] for details.
    pub async fn wait_for_snapshot(
        &self,
        parent: ConsensusDigest,
        timeout: Duration,
    ) -> Option<LedgerSnapshot> {
        self.view.wait_for_snapshot(parent, timeout).await
    }

    /// Insert a new snapshot.
    pub async fn insert_snapshot(
        &self,
        digest: ConsensusDigest,
        parent: ConsensusDigest,
        state: OverlayState<QmdbState>,
        root: StateRoot,
        changes: QmdbChangeSet,
        txs: &[Tx],
    ) {
        self.view.insert_snapshot(digest, parent, state, root, changes, txs).await;
    }

    /// Cache a fully constructed snapshot.
    pub async fn cache_snapshot(&self, digest: ConsensusDigest, snapshot: LedgerSnapshot) {
        self.view.cache_snapshot(digest, snapshot).await;
    }

    /// Restore a finalized block as an already-persisted snapshot.
    pub async fn restore_persisted_snapshot(&self, block: &Block) {
        self.view.restore_persisted_snapshot(block).await;
    }

    /// Fetch proposal components.
    pub async fn proposal_components(
        &self,
    ) -> (OverlayState<QmdbState>, LedgerMempool, InMemorySnapshotStore<OverlayState<QmdbState>>)
    {
        self.view.proposal_components().await
    }

    /// Compute a preview root (test-only helper).
    #[cfg(test)]
    pub async fn compute_root(
        &self,
        parent: ConsensusDigest,
        changes: &QmdbChangeSet,
    ) -> LedgerResult<StateRoot> {
        self.view.compute_root(parent, changes).await
    }

    /// Compute a root using the persisted store.
    pub async fn compute_root_from_store(
        &self,
        parent: ConsensusDigest,
        changes: &QmdbChangeSet,
    ) -> LedgerResult<StateRoot> {
        self.view.compute_root_from_store(parent, changes).await
    }

    /// Persist a snapshot and publish an event if a new commit occurs.
    pub async fn persist_snapshot(&self, digest: ConsensusDigest) -> LedgerResult<()> {
        let persisted = self.view.persist_snapshot(digest).await?;
        if persisted {
            self.publish(LedgerEvent::SnapshotPersisted(digest));
        }
        Ok(())
    }

    /// Remove transactions from the mempool.
    pub async fn prune_mempool(&self, txs: &[Tx]) {
        self.view.prune_mempool(txs).await;
    }

    /// Remove transactions with stale nonces from the mempool.
    ///
    /// Delegates to [`LedgerView::prune_stale_nonces`] which queries the
    /// finalized QMDB state for each sender in the pool.
    pub async fn prune_stale_nonces(&self) {
        self.view.prune_stale_nonces().await;
    }

    /// Returns `true` if the snapshot for `digest` has been persisted to QMDB
    /// (even if the in-memory snapshot data has since been evicted).
    pub async fn is_snapshot_persisted(&self, digest: &ConsensusDigest) -> bool {
        self.view.is_snapshot_persisted(digest).await
    }

    /// Return snapshot store statistics: `(total, unpersisted)`.
    ///
    /// Delegates to [`LedgerView::snapshot_store_stats`].
    pub async fn snapshot_store_stats(&self) -> (usize, usize) {
        self.view.snapshot_store_stats().await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use alloy_consensus::Header;
    use alloy_primitives::{Address, B256, Bytes, U256};
    use commonware_cryptography::Committable as _;
    use commonware_runtime::{Runner, tokio};
    use k256::ecdsa::SigningKey;
    use kora_config::INITIAL_BASE_FEE;
    use kora_domain::{Block, ConsensusDigest, Tx, evm::Evm};
    use kora_executor::{BlockContext, BlockExecutor, RevmExecutor};
    use kora_overlay::OverlayState;
    use kora_traits::StateDbRead;

    use super::{LedgerService, LedgerSnapshot, LedgerView};

    static PARTITION_COUNTER: AtomicUsize = AtomicUsize::new(0);

    const GENESIS_BALANCE: u64 = 1_000_000_000_000_000_000; // 1 ETH in wei
    const DUPLICATE_BALANCE: u64 = 1_000_000_000_000_000_000; // 1 ETH in wei
    const TRANSFER_ONE: u64 = 10;
    const TRANSFER_TWO: u64 = 5;
    const TRANSFER_DUPLICATE: u64 = 1;
    const GAS_LIMIT_TRANSFER: u64 = 21_000;
    const HEIGHT_ONE: u64 = 1;
    const HEIGHT_TWO: u64 = 2;
    const PREVRANDAO: B256 = B256::ZERO;
    const FROM_BYTE_A: u8 = 0x11;
    const TO_BYTE_A: u8 = 0x22;
    const FROM_BYTE_B: u8 = 0x33;
    const TO_BYTE_B: u8 = 0x44;
    const CHAIN_ID: u64 = 1337;

    struct LedgerSetup {
        ledger: LedgerView,
        service: LedgerService,
        genesis: Block,
        genesis_digest: ConsensusDigest,
    }

    struct BuiltBlock {
        block: Block,
        digest: ConsensusDigest,
    }

    fn run_ledger_test<F, Fut>(f: F)
    where
        F: FnOnce(tokio::Context) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let handle = std::thread::Builder::new()
            .name("kora-ledger-test".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let executor = tokio::Runner::default();
                executor.start(f);
            })
            .expect("failed to spawn ledger test thread");

        match handle.join() {
            Ok(()) => (),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    fn key_from_byte(byte: u8) -> SigningKey {
        let mut bytes = [0u8; 32];
        bytes[0] = byte.max(1);
        SigningKey::from_bytes(&bytes.into()).expect("valid key")
    }

    fn next_partition(prefix: &str) -> String {
        let id = PARTITION_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{id}")
    }

    fn transfer_tx(from_key: &SigningKey, to: Address, value: u64, nonce: u64) -> Tx {
        Evm::sign_eip1559_transfer(
            from_key,
            CHAIN_ID,
            to,
            U256::from(value),
            nonce,
            GAS_LIMIT_TRANSFER,
            INITIAL_BASE_FEE as u128,
            0,
        )
    }

    fn block_context(height: u64, timestamp: u64, prevrandao: B256) -> BlockContext {
        let header = Header {
            number: height,
            timestamp,
            gas_limit: 30_000_000,
            beneficiary: Address::ZERO,
            base_fee_per_gas: Some(INITIAL_BASE_FEE),
            ..Default::default()
        };
        BlockContext::new(header, B256::ZERO, prevrandao)
    }

    async fn setup_ledger(
        context: tokio::Context,
        partition_prefix: &str,
        allocations: Vec<(Address, U256)>,
    ) -> LedgerSetup {
        let ledger = LedgerView::init(context, next_partition(partition_prefix), allocations)
            .await
            .expect("init ledger");
        let service = LedgerService::new(ledger.clone());
        let genesis = service.genesis_block();
        let genesis_digest = genesis.commitment();
        LedgerSetup { ledger, service, genesis, genesis_digest }
    }

    #[test]
    fn init_uses_configured_genesis_timestamp() {
        run_ledger_test(|context| async move {
            let ledger = LedgerView::init_with_genesis_timestamp(
                context,
                next_partition("revm-ledger-genesis-timestamp"),
                Vec::new(),
                1_700_000_000,
            )
            .await
            .expect("init ledger");

            assert_eq!(ledger.genesis_block().timestamp, 1_700_000_000);
        });
    }

    async fn build_block_snapshot(
        service: &LedgerService,
        parent: &Block,
        parent_snapshot: LedgerSnapshot,
        height: u64,
        txs: Vec<Tx>,
    ) -> BuiltBlock {
        let executor = RevmExecutor::new(CHAIN_ID);
        let timestamp = Block::next_timestamp(0, parent.timestamp).expect("timestamp overflow");
        let context = block_context(height, timestamp, PREVRANDAO);
        let txs_bytes: Vec<Bytes> = txs.iter().map(|tx| tx.bytes.clone()).collect();
        let outcome =
            executor.execute(&parent_snapshot.state, &context, &txs_bytes).expect("execute txs");
        let merged_changes = parent_snapshot.state.merge_changes(outcome.changes.clone());
        let parent_digest = parent.commitment();
        let root =
            service.compute_root(parent_digest, &outcome.changes).await.expect("compute root");
        let block = Block::new(parent.id(), height, timestamp, PREVRANDAO, root, txs);
        let digest = block.commitment();
        let next_state = OverlayState::new(parent_snapshot.state.base(), merged_changes);
        service
            .insert_snapshot(digest, parent_digest, next_state, root, outcome.changes, &block.txs)
            .await;
        BuiltBlock { block, digest }
    }

    #[test]
    fn persist_snapshot_merges_unpersisted_ancestors() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        run_ledger_test(|context| async move {
            // Arrange
            let from_key = key_from_byte(FROM_BYTE_A);
            let to_key = key_from_byte(TO_BYTE_A);
            let from = Evm::address_from_key(&from_key);
            let to = Evm::address_from_key(&to_key);
            let setup = setup_ledger(
                context,
                "revm-ledger-merge",
                vec![(from, U256::from(GENESIS_BALANCE)), (to, U256::ZERO)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block1 = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(&from_key, to, TRANSFER_ONE, 0)],
            )
            .await;
            let parent_snapshot =
                setup.service.parent_snapshot(block1.digest).await.expect("block1 snapshot");
            let block2 = build_block_snapshot(
                &setup.service,
                &block1.block,
                parent_snapshot,
                HEIGHT_TWO,
                vec![transfer_tx(&from_key, to, TRANSFER_TWO, 1)],
            )
            .await;

            // Act
            let persisted =
                setup.ledger.persist_snapshot(block2.digest).await.expect("persist snapshot");

            // Assert
            assert!(persisted);
            let state_root =
                setup.ledger.query_state_root(block2.digest).await.expect("state root");
            let qmdb = setup.ledger.inner.lock().await.qmdb.clone();
            let result = qmdb.state().balance(&to).await.expect("balance");
            assert_eq!(result, U256::from(TRANSFER_ONE + TRANSFER_TWO));
            assert_eq!(state_root, block2.block.state_root);
        });
    }

    #[test]
    fn persist_snapshot_compacts_all_persisted_chain_snapshots() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        run_ledger_test(|context| async move {
            // Arrange
            let from_key = key_from_byte(FROM_BYTE_A);
            let to_key = key_from_byte(TO_BYTE_A);
            let from = Evm::address_from_key(&from_key);
            let to = Evm::address_from_key(&to_key);
            let setup = setup_ledger(
                context,
                "revm-ledger-compact-chain",
                vec![(from, U256::from(GENESIS_BALANCE)), (to, U256::ZERO)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block1 = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(&from_key, to, TRANSFER_ONE, 0)],
            )
            .await;
            let parent_snapshot =
                setup.service.parent_snapshot(block1.digest).await.expect("block1 snapshot");
            let block2 = build_block_snapshot(
                &setup.service,
                &block1.block,
                parent_snapshot,
                HEIGHT_TWO,
                vec![transfer_tx(&from_key, to, TRANSFER_TWO, 1)],
            )
            .await;

            let block1_before =
                setup.service.parent_snapshot(block1.digest).await.expect("block1 snapshot");
            let block2_before =
                setup.service.parent_snapshot(block2.digest).await.expect("block2 snapshot");
            assert!(!block1_before.changes.is_empty());
            assert!(!block2_before.changes.is_empty());

            let block1_parent = block1_before.parent;
            let block1_state_root = block1_before.state_root;
            let block1_tx_ids = block1_before.tx_ids.clone();
            let block2_parent = block2_before.parent;
            let block2_state_root = block2_before.state_root;
            let block2_tx_ids = block2_before.tx_ids.clone();

            // Act
            let persisted =
                setup.ledger.persist_snapshot(block2.digest).await.expect("persist snapshot");

            // Assert
            assert!(persisted);
            let block1_after =
                setup.service.parent_snapshot(block1.digest).await.expect("block1 snapshot");
            let block2_after =
                setup.service.parent_snapshot(block2.digest).await.expect("block2 snapshot");

            assert!(block1_after.changes.is_empty());
            assert!(block2_after.changes.is_empty());
            assert!(
                block1_after.state.changes_is_empty(),
                "block1 overlay change set should be empty after compaction"
            );
            assert!(
                block2_after.state.changes_is_empty(),
                "block2 overlay change set should be empty after compaction"
            );
            assert_eq!(block1_after.parent, block1_parent);
            assert_eq!(block1_after.state_root, block1_state_root);
            assert_eq!(block1_after.tx_ids, block1_tx_ids);
            assert_eq!(block2_after.parent, block2_parent);
            assert_eq!(block2_after.state_root, block2_state_root);
            assert_eq!(block2_after.tx_ids, block2_tx_ids);
        });
    }

    #[test]
    fn empty_child_inherits_parent_state_root_after_persist() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        run_ledger_test(|context| async move {
            // Arrange: create and persist a non-empty parent, matching the timing that can differ
            // across validators during consensus.
            let from_key = key_from_byte(FROM_BYTE_A);
            let to_key = key_from_byte(TO_BYTE_A);
            let from = Evm::address_from_key(&from_key);
            let to = Evm::address_from_key(&to_key);
            let setup = setup_ledger(
                context,
                "revm-ledger-empty-child",
                vec![(from, U256::from(GENESIS_BALANCE)), (to, U256::ZERO)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let parent = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(&from_key, to, TRANSFER_ONE, 0)],
            )
            .await;
            assert!(setup.ledger.persist_snapshot(parent.digest).await.expect("persist"));

            // Act: an empty child has no state transition and must not recompute a new QMDB root
            // from local persistence metadata.
            let empty_root = setup
                .service
                .compute_root(parent.digest, &Default::default())
                .await
                .expect("compute empty child root");

            // Assert
            assert_eq!(empty_root, parent.block.state_root);
        });
    }

    #[test]
    fn persist_snapshot_duplicate_is_noop() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        run_ledger_test(|context| async move {
            // Arrange
            let from_key = key_from_byte(FROM_BYTE_A);
            let to_key = key_from_byte(TO_BYTE_A);
            let from = Evm::address_from_key(&from_key);
            let to = Evm::address_from_key(&to_key);
            let setup = setup_ledger(
                context,
                "revm-ledger-duplicate",
                vec![(from, U256::from(GENESIS_BALANCE)), (to, U256::ZERO)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(&from_key, to, TRANSFER_ONE, 0)],
            )
            .await;

            // Act
            let first =
                setup.ledger.persist_snapshot(block.digest).await.expect("persist snapshot");
            assert!(first);

            let second =
                setup.ledger.persist_snapshot(block.digest).await.expect("persist snapshot");

            // Assert
            assert!(!second);
        });
    }

    #[test]
    fn persist_snapshot_merges_overlays() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        run_ledger_test(|context| async move {
            // Arrange
            let sender_bytes = [0x11, 0x12, 0x13, 0x14, 0x15];
            let recipient_bytes = [0x21, 0x22, 0x23, 0x24, 0x25];
            let mut sender_keys = Vec::new();
            let mut recipients = Vec::new();
            let mut genesis_alloc = Vec::new();
            for (sender_byte, recipient_byte) in sender_bytes.iter().zip(recipient_bytes.iter()) {
                let recipient_key = key_from_byte(*recipient_byte);
                let recipient = Evm::address_from_key(&recipient_key);
                recipients.push(recipient);
                genesis_alloc.push((recipient, U256::ZERO));
                let key = key_from_byte(*sender_byte);
                let addr = Evm::address_from_key(&key);
                sender_keys.push(key);
                genesis_alloc.push((addr, U256::from(GENESIS_BALANCE)));
            }
            let setup = setup_ledger(context, "revm-ledger-overlay", genesis_alloc).await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let txs: Vec<Tx> = sender_keys
                .iter()
                .zip(recipients.iter().copied())
                .map(|(key, recipient)| transfer_tx(key, recipient, TRANSFER_DUPLICATE, 0))
                .collect();
            let block = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                txs,
            )
            .await;

            // Act
            let persisted = setup.ledger.persist_snapshot(block.digest).await.expect("persist");
            assert!(persisted);

            // Assert
            let qmdb = setup.ledger.inner.lock().await.qmdb.clone();
            for recipient in recipients {
                let result = qmdb.state().balance(&recipient).await.expect("balance");
                assert_eq!(result, U256::from(TRANSFER_DUPLICATE));
            }
        });
    }

    #[test]
    fn persist_snapshot_unrelated_merges() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        run_ledger_test(|context| async move {
            // Arrange
            let from_key_a = key_from_byte(FROM_BYTE_A);
            let to_key_a = key_from_byte(TO_BYTE_A);
            let from_a = Evm::address_from_key(&from_key_a);
            let to_a = Evm::address_from_key(&to_key_a);
            let from_key_b = key_from_byte(FROM_BYTE_B);
            let to_key_b = key_from_byte(TO_BYTE_B);
            let from_b = Evm::address_from_key(&from_key_b);
            let to_b = Evm::address_from_key(&to_key_b);
            let setup = setup_ledger(
                context,
                "revm-ledger-unrelated",
                vec![
                    (from_a, U256::from(GENESIS_BALANCE)),
                    (to_a, U256::ZERO),
                    (from_b, U256::from(DUPLICATE_BALANCE)),
                    (to_b, U256::ZERO),
                ],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block1 = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(&from_key_a, to_a, TRANSFER_ONE, 0)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block2 = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(&from_key_b, to_b, TRANSFER_DUPLICATE, 0)],
            )
            .await;

            // Act
            let persisted_1 =
                setup.ledger.persist_snapshot(block1.digest).await.expect("persist snapshot");
            let persisted_2 =
                setup.ledger.persist_snapshot(block2.digest).await.expect("persist snapshot");

            // Assert
            assert!(persisted_1);
            assert!(persisted_2);
            let qmdb = setup.ledger.inner.lock().await.qmdb.clone();
            assert_eq!(
                qmdb.state().balance(&to_a).await.expect("balance"),
                U256::from(TRANSFER_ONE)
            );
            assert_eq!(
                qmdb.state().balance(&to_b).await.expect("balance"),
                U256::from(TRANSFER_DUPLICATE)
            );
        });
    }

    #[test]
    fn persist_snapshot_updates_snapshot_state() {
        // Tokio runtime required for WrapDatabaseAsync in the QMDB adapter.
        run_ledger_test(|context| async move {
            // Arrange
            let from_key = key_from_byte(FROM_BYTE_A);
            let to_key = key_from_byte(TO_BYTE_A);
            let from = Evm::address_from_key(&from_key);
            let to = Evm::address_from_key(&to_key);
            let setup = setup_ledger(
                context,
                "revm-ledger-updates",
                vec![(from, U256::from(GENESIS_BALANCE)), (to, U256::ZERO)],
            )
            .await;
            let parent_snapshot = setup
                .service
                .parent_snapshot(setup.genesis_digest)
                .await
                .expect("genesis snapshot");
            let block = build_block_snapshot(
                &setup.service,
                &setup.genesis,
                parent_snapshot,
                HEIGHT_ONE,
                vec![transfer_tx(&from_key, to, TRANSFER_ONE, 0)],
            )
            .await;

            // Act
            let persisted = setup.ledger.persist_snapshot(block.digest).await.expect("persist");

            // Assert
            assert!(persisted);
            let state_root = setup.ledger.query_state_root(block.digest).await.expect("state root");
            assert_eq!(state_root, block.block.state_root);
        });
    }
}
