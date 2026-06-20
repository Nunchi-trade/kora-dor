use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, keccak256};
use anyhow::Context as _;
use commonware_actor::Feedback;
use commonware_consensus::{
    Block as _, Reporters,
    marshal::{
        core::Mailbox,
        standard::{Inline, Standard},
    },
    simplex::{
        self, elector::Random, scheme::bls12381_threshold::vrf::Seedable as _, types::Finalization,
    },
    types::{Epoch, FixedEpocher, ViewDelta},
};
use commonware_cryptography::{
    Committable as _, Hasher as _, Sha256, bls12381::primitives::variant::MinSig, ed25519,
};
use commonware_p2p::{Blocker, Manager, Receiver as _, Recipients, Sender as _, TrackedPeers};
use commonware_runtime::{
    Clock as _, Handle as RuntimeHandle, Metrics as _, Spawner, Supervisor as _, ThreadPooler as _,
    buffer::paged::CacheRef, tokio as cw_tokio,
};
use commonware_storage::archive::{Archive, Identifier as ArchiveId};
use commonware_utils::{NZU64, NZUsize, acknowledgement::Exact, ordered::Set};
use futures::StreamExt;
use kora_consensus::BlockExecution;
use kora_domain::{Block, BlockCfg, BootstrapConfig, ConsensusDigest, LedgerEvent, Tx, TxCfg};
use kora_executor::{BaseFeeParams, BlockContext, RevmExecutor, calculate_base_fee};
use kora_indexer::{BlockIndex, EMPTY_ROOT_HASH, IndexedBlock};
use kora_ledger::{LedgerService, LedgerView, LiveState};
use kora_marshal::{ArchiveInitializer, BroadcastInitializer, PeerInitializer};
use kora_metrics::AppMetrics;
use kora_reporters::{BlockContextProvider, FinalizedReporter, NodeStateReporter, SeedReporter};
use kora_service::{NodeRunContext, NodeRunner};
use kora_simplex::{DEFAULT_MAILBOX_SIZE as MAILBOX_SIZE, DefaultPool};
use kora_transport::NetworkTransport;
use kora_txpool::{PoolConfig, TransactionPool, TransactionValidator};
use tracing::{debug, error, info, trace, warn};

use crate::{
    RevmApplication, RunnerError, no_sync_storage::NoSyncStorage, scheme::ThresholdScheme,
};

/// Adapter that bridges `kora_metrics::MetricsRegister` to the commonware
/// runtime's `Metrics` trait.
struct RuntimeMetrics<'a>(&'a cw_tokio::Context);

impl kora_metrics::MetricsRegister for RuntimeMetrics<'_> {
    fn register<N: Into<String>, H: Into<String>>(
        &self,
        name: N,
        help: H,
        metric: impl prometheus_client::registry::Metric,
    ) {
        // AppMetrics lives for the process lifetime; keep commonware's
        // registration handles alive for the same duration.
        std::mem::forget(commonware_runtime::Metrics::register(self.0, name, help, metric));
    }
}

const EPOCH_LENGTH: u64 = u64::MAX;
const PARTITION_PREFIX: &str = "kora";
const TXPOOL_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const PARTITION_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const RUNTIME_DIR_ENV: &str = "KORA_RUNTIME_DIR";
const CHECKPOINT_INTERVAL_ENV: &str = "KORA_CHECKPOINT_INTERVAL";
const DEFAULT_CHECKPOINT_INTERVAL: u64 = 256;

/// Maximum number of transaction hashes retained in the gossip seen-set.
/// When the set exceeds this size it is cleared to avoid unbounded memory
/// growth. Under normal load the TTL-based cleanup keeps the set far smaller.
const TX_GOSSIP_SEEN_SET_CAPACITY: usize = 65_536;

/// Buffer size for the internal channel that forwards locally accepted
/// transactions to the P2P gossip broadcast task.
const TX_GOSSIP_OUTBOUND_BUFFER: usize = 4096;

type Peer = ed25519::PublicKey;
type CertArchive = Finalization<ThresholdScheme, ConsensusDigest>;
type MarshalMailbox = Mailbox<ThresholdScheme, Standard<Block>>;
type NodeStateRptr = NodeStateReporter<ThresholdScheme>;

/// A [`Blocker`] that suppresses peer bans during catch-up but delegates to
/// the real oracle blocker during normal operation.
///
/// When a restarted node catches up, the resolver's `verify_block()` may return
/// `false` because parent state snapshots are missing (not because the peer sent
/// invalid data). The default blocker (`transport.oracle`) permanently blocks
/// that peer, and in a 4-validator cluster all 3 peers get blocked within
/// milliseconds, making catch-up impossible.
///
/// `GraduatedBlocker` solves this by checking a shared `catching_up` flag:
/// - **During catch-up** (`catching_up = true`): block requests are logged at
///   `warn` level but suppressed, allowing the resolver to retry with other
///   peers.
/// - **During normal operation** (`catching_up = false`): block requests are
///   forwarded to the underlying oracle, which disconnects the peer and
///   prevents future connections.
///
/// The `catching_up` flag is set to `true` when the node is recovering from a
/// restart (i.e., `recovered_head_height` is `Some`) and cleared to `false`
/// for fresh genesis starts. A future improvement should wire a "backfill
/// complete" signal from the resolver to clear this flag once historical block
/// sync finishes.
#[derive(Clone, Debug)]
struct GraduatedBlocker<P: commonware_cryptography::PublicKey> {
    oracle: commonware_p2p::authenticated::discovery::Oracle<P>,
    catching_up: Arc<AtomicBool>,
}

impl<P: commonware_cryptography::PublicKey> GraduatedBlocker<P> {
    const fn new(
        oracle: commonware_p2p::authenticated::discovery::Oracle<P>,
        catching_up: Arc<AtomicBool>,
    ) -> Self {
        Self { oracle, catching_up }
    }
}

impl<P: commonware_cryptography::PublicKey> Blocker for GraduatedBlocker<P> {
    type PublicKey = P;

    fn block(&mut self, peer: Self::PublicKey) -> Feedback {
        let catching_up = self.catching_up.load(Ordering::Relaxed);
        if catching_up {
            warn!(?peer, "GraduatedBlocker: suppressing block request during catch-up");
            Feedback::Ok
        } else {
            warn!(?peer, "GraduatedBlocker: blocking Byzantine peer via oracle");
            self.oracle.block(peer)
        }
    }
}

fn default_page_cache(context: &cw_tokio::Context) -> CacheRef {
    DefaultPool::init(context)
}

/// Resolve the storage directory used by the Commonware runtime.
///
/// By default this lives under `data_dir/runtime` so validator state survives
/// restarts. Local devnets can set `KORA_RUNTIME_DIR` to put consensus journals
/// on tmpfs and avoid Docker-volume fsync latency.
#[must_use]
pub fn runtime_storage_directory(data_dir: &Path) -> PathBuf {
    runtime_storage_directory_from(data_dir, std::env::var_os(RUNTIME_DIR_ENV))
}

fn runtime_storage_directory_from(data_dir: &Path, override_dir: Option<OsString>) -> PathBuf {
    match override_dir {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => data_dir.join("runtime"),
    }
}

fn checkpoint_interval() -> u64 {
    std::env::var(CHECKPOINT_INTERVAL_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CHECKPOINT_INTERVAL)
}

const fn block_codec_cfg(config: &kora_config::ConsensusBlockCodecConfig) -> BlockCfg {
    BlockCfg {
        max_txs: config.max_txs.get(),
        tx: TxCfg { max_tx_bytes: config.max_tx_bytes.get() },
    }
}

fn seed_genesis_block_index(index: &BlockIndex, genesis: &Block, gas_limit: u64) {
    index.insert_block(
        IndexedBlock {
            hash: genesis.id().0,
            number: 0,
            parent_hash: genesis.parent.0,
            state_root: genesis.state_root.0,
            transactions_root: EMPTY_ROOT_HASH,
            receipts_root: EMPTY_ROOT_HASH,
            timestamp: genesis.timestamp,
            gas_limit,
            gas_used: 0,
            base_fee_per_gas: Some(kora_config::INITIAL_BASE_FEE),
            mix_hash: genesis.prevrandao,
            logs_bloom: alloy_primitives::Bloom::ZERO,
            size: 508,
            transaction_hashes: Vec::new(),
        },
        Vec::new(),
        Vec::new(),
    );
}

/// Compute the consensus digest for a block hash (BlockId).
///
/// Mirrors `digest_for_block_id` in `kora_domain::block` which is private.
fn consensus_digest_for_hash(block_hash: B256) -> ConsensusDigest {
    let mut hasher = Sha256::default();
    hasher.update(block_hash.as_slice());
    hasher.finalize()
}

/// Seed the [`RevmApplication`] block-fee cache with entries from the
/// [`BlockIndex`] so that the first blocks after restart derive a correct
/// EIP-1559 base fee.
///
/// Seeds the last few blocks ending at `head_height`.
fn seed_block_fee_cache(
    app: &RevmApplication<ThresholdScheme, RevmExecutor>,
    block_index: &BlockIndex,
    head_height: u64,
) {
    // Seed the last few blocks so that both the HEAD and its recent
    // ancestors are available for base-fee derivation.
    let start = head_height.saturating_sub(4);
    let mut entries = Vec::new();
    for h in start..=head_height {
        if let Some(indexed) = block_index.get_block_by_number(h) {
            let digest = consensus_digest_for_hash(indexed.hash);
            let base_fee = indexed.base_fee_per_gas.unwrap_or(kora_config::INITIAL_BASE_FEE);
            entries.push((digest, indexed.gas_used, base_fee));
        }
    }
    if !entries.is_empty() {
        app.seed_block_fees(&entries);
        debug!(
            head_height,
            seeded = entries.len(),
            "seeded block-fee cache from block index for EIP-1559 base fee recovery"
        );
    }
}

fn seed_hash(seed: impl commonware_codec::Encode) -> B256 {
    keccak256(seed.encode())
}

fn index_recovered_block(
    index: &kora_indexer::BlockIndex,
    block: &Block,
    provider: &RevmContextProvider,
) {
    let block_context = provider.context(block);
    let transaction_hashes = block.txs.iter().map(|tx| keccak256(&tx.bytes)).collect();
    let tx_bytes_total: u64 = block.txs.iter().map(|tx| tx.bytes.len() as u64).sum();
    let indexed_block = kora_indexer::IndexedBlock {
        hash: block.id().0,
        number: block.height,
        parent_hash: block.parent.0,
        state_root: block.state_root.0,
        transactions_root: EMPTY_ROOT_HASH,
        receipts_root: EMPTY_ROOT_HASH,
        timestamp: block_context.header.timestamp,
        gas_limit: block_context.header.gas_limit,
        gas_used: 0,
        base_fee_per_gas: block_context.header.base_fee_per_gas,
        mix_hash: block.prevrandao,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        size: 508 + tx_bytes_total,
        transaction_hashes,
    };
    index.insert_block(indexed_block, Vec::new(), Vec::new());
}

/// Number of recent blocks to restore during startup to pre-populate the
/// snapshot cache. This ensures that blocks arriving shortly after restart
/// can find their parent snapshot without entering catch-up mode.
///
/// A larger window (64 blocks) means the node can survive outages where
/// the network advances up to 64 blocks before the node restarts.  Blocks
/// within this window are resolved from the local archive without needing
/// catch-up trust.  Beyond this window, the catch-up mechanism in
/// `RevmApplication::verify_block` handles the gap.
const SNAPSHOT_PREPOPULATE_COUNT: u64 = 64;

async fn recover_finalized_state<FB, FC>(
    ledger: &LedgerService,
    block_index: &Arc<kora_indexer::BlockIndex>,
    finalized_blocks: &FB,
    finalizations_by_height: &FC,
    provider: &RevmContextProvider,
    data_dir: &Path,
    chain_id: u64,
) -> anyhow::Result<Option<(u64, bool)>>
where
    FB: Archive<Key = ConsensusDigest, Value = Block>,
    FC: Archive<Key = ConsensusDigest, Value = CertArchive>,
{
    let block_ranges: Vec<_> = finalized_blocks.ranges().collect();
    let finalization_ranges: Vec<_> = finalizations_by_height.ranges().collect();

    for (start, end) in finalization_ranges {
        for height in start..=end {
            if let Some(finalization) = finalizations_by_height
                .get(ArchiveId::Index(height))
                .await
                .with_context(|| format!("load finalization at height {height}"))?
            {
                ledger
                    .set_seed(finalization.proposal.payload, seed_hash(finalization.seed()))
                    .await;
            }
        }
    }

    let mut recovered = 0u64;
    let mut recovered_blocks = BTreeMap::new();
    for (start, end) in block_ranges {
        for height in start..=end {
            let Some(block) = finalized_blocks
                .get(ArchiveId::Index(height))
                .await
                .with_context(|| format!("load finalized block at height {height}"))?
            else {
                continue;
            };

            index_recovered_block(block_index, &block, provider);
            recovered_blocks.insert(height, block);
            recovered += 1;
        }
    }

    let head_height = if let Some((_, archive_head)) = recovered_blocks.last_key_value() {
        let (restored_height, replayed_tail) = restore_checkpoint_and_replay_tail(
            ledger,
            &recovered_blocks,
            provider,
            data_dir,
            chain_id,
            block_index,
        )
        .await?;
        info!(
            archive_head_height = archive_head.height,
            restored_height,
            blocks = recovered,
            "recovered finalized ledger head from archive"
        );
        Some((restored_height, replayed_tail))
    } else {
        None
    };

    Ok(head_height)
}

async fn restore_checkpoint_and_replay_tail(
    ledger: &LedgerService,
    recovered_blocks: &BTreeMap<u64, Block>,
    provider: &RevmContextProvider,
    data_dir: &Path,
    chain_id: u64,
    block_index: &BlockIndex,
) -> anyhow::Result<(u64, bool)> {
    let Some((_, head)) = recovered_blocks.last_key_value() else {
        return Ok((0, false));
    };
    let marker_digest = crate::commit_marker::read_commit_marker(data_dir);
    let checkpoint_height = marker_digest.and_then(|marker| {
        recovered_blocks
            .iter()
            .find_map(|(height, block)| (block.commitment() == marker).then_some(*height))
    });

    match checkpoint_height {
        Some(height) => {
            let checkpoint = &recovered_blocks[&height];
            ledger.restore_persisted_snapshot(checkpoint).await;
            info!(
                checkpoint_height = checkpoint.height,
                archive_head_height = head.height,
                replay_blocks = recovered_blocks.len().saturating_sub(
                    recovered_blocks
                        .keys()
                        .position(|candidate| *candidate == height)
                        .map_or(0, |index| index + 1)
                ),
                "restored QMDB checkpoint and replaying archive tail"
            );

            let executor = RevmExecutor::new(chain_id);
            let mut restored_height = checkpoint.height;
            let mut restored_digest = checkpoint.commitment();
            let mut replayed_tail = false;
            for expected_height in checkpoint.height.saturating_add(1)..=head.height {
                let Some(block) = recovered_blocks.get(&expected_height) else {
                    warn!(
                        expected_height,
                        archive_head_height = head.height,
                        restored_height,
                        "stopping finalized archive replay at durable gap"
                    );
                    break;
                };
                if block.parent() != restored_digest {
                    warn!(
                        expected_height,
                        restored_height,
                        expected_parent = ?restored_digest,
                        actual_parent = ?block.parent(),
                        "stopping finalized archive replay at non-contiguous parent"
                    );
                    break;
                }
                replay_finalized_block(ledger, provider, &executor, block, block_index).await?;
                // Write the commit marker synchronously after each successful
                // replay so that a crash does not leave the marker pointing to
                // a stale block.
                if let Err(e) =
                    crate::commit_marker::write_commit_marker(data_dir, &block.commitment())
                {
                    warn!(
                        error = %e,
                        height = block.height,
                        "failed to write commit marker during replay"
                    );
                }
                restored_height = block.height;
                restored_digest = block.commitment();
                replayed_tail = true;
            }
            Ok((restored_height, replayed_tail))
        }
        None => {
            if let Some(marker) = marker_digest {
                // A commit marker exists on disk but does not match any
                // block in the archive.  QMDB was last committed at a
                // height we cannot identify, so creating a snapshot from
                // the archive head would produce inconsistent state.
                let head_digest = head.commitment();
                error!(
                    marker_digest = %hex::encode(marker.as_ref()),
                    head_digest = %hex::encode(head_digest.as_ref()),
                    archive_head_height = head.height,
                    "commit marker does not match any archived block; \
                     QMDB state is at an unknown height.  Refusing to \
                     start with potentially inconsistent state.  \
                     Re-sync from a trusted snapshot or wipe state."
                );
                anyhow::bail!(
                    "commit marker {} does not match any archived block; \
                     cannot safely determine QMDB state height \
                     (archive head is at height {})",
                    hex::encode(marker.as_ref()),
                    head.height,
                );
            }
            // No commit marker at all -- fresh node or upgrade from a
            // pre-marker build.  Safe to trust the archive head.
            info!(
                archive_head_height = head.height,
                "no commit marker found; restoring archive head as initial \
                 QMDB state (expected for fresh nodes or first startup \
                 after upgrade)"
            );
            ledger.restore_persisted_snapshot(head).await;
            Ok((head.height, false))
        }
    }
}

async fn replay_finalized_block(
    ledger: &LedgerService,
    provider: &RevmContextProvider,
    executor: &RevmExecutor,
    block: &Block,
    block_index: &BlockIndex,
) -> anyhow::Result<()> {
    let digest = block.commitment();
    if ledger.query_state_root(digest).await.is_some() {
        return Ok(());
    }

    let parent_digest = block.parent();
    let parent_snapshot = ledger.parent_snapshot(parent_digest).await.with_context(|| {
        format!("missing parent snapshot while replaying height {}", block.height)
    })?;
    let block_context = provider.context(block);
    let execution = BlockExecution::execute(&parent_snapshot, executor, &block_context, &block.txs)
        .await
        .with_context(|| format!("failed to replay finalized block at height {}", block.height))?;
    let state_root = ledger
        .compute_root_from_store(parent_digest, &execution.outcome.changes)
        .await
        .with_context(|| format!("failed to compute replay root at height {}", block.height))?;
    anyhow::ensure!(
        state_root == block.state_root,
        "replayed root mismatch at height {}: expected {:?}, computed {:?}",
        block.height,
        block.state_root,
        state_root
    );

    // Re-index the block with the real gas_used from execution so that
    // subsequent blocks can derive their EIP-1559 base fee correctly.
    // The initial `index_recovered_block` call stored gas_used=0 because
    // the archive does not include execution results.
    let tx_bytes_total: u64 = block.txs.iter().map(|tx| tx.bytes.len() as u64).sum();
    let indexed_block = IndexedBlock {
        hash: block.id().0,
        number: block.height,
        parent_hash: block.parent.0,
        state_root: block.state_root.0,
        transactions_root: EMPTY_ROOT_HASH,
        receipts_root: EMPTY_ROOT_HASH,
        timestamp: block_context.header.timestamp,
        gas_limit: block_context.header.gas_limit,
        gas_used: execution.outcome.gas_used,
        base_fee_per_gas: block_context.header.base_fee_per_gas,
        mix_hash: block.prevrandao,
        logs_bloom: alloy_primitives::Bloom::ZERO,
        size: 508 + tx_bytes_total,
        transaction_hashes: block.txs.iter().map(|tx| keccak256(&tx.bytes)).collect(),
    };
    block_index.insert_block(indexed_block, Vec::new(), Vec::new());

    let merged_changes = parent_snapshot.state.merge_changes(execution.outcome.changes.clone());
    let next_state = kora_overlay::OverlayState::new(parent_snapshot.state.base(), merged_changes);
    ledger
        .insert_snapshot(
            digest,
            parent_digest,
            next_state,
            state_root,
            execution.outcome.changes,
            &block.txs,
        )
        .await;
    Ok(())
}

/// Pre-populate the in-memory snapshot cache by restoring recent finalized
/// blocks from the archive.
///
/// After a restart, only the HEAD snapshot is in the cache. The consensus
/// engine's ancestry walk (`verify`) stops when it hits a block whose
/// `state_root` is already known. By restoring snapshots for the last N
/// blocks, the ancestry walk terminates earlier and fewer blocks need to be
/// re-verified. Any blocks whose parent snapshot is genuinely missing (due
/// to gaps larger than the prepopulation window) are handled by the
/// catch-up trust mechanism in `verify_block`.
async fn prepopulate_snapshot_cache<FB>(
    ledger: &LedgerService,
    finalized_blocks: &FB,
    head_height: u64,
    count: u64,
) where
    FB: Archive<Key = ConsensusDigest, Value = Block>,
{
    if head_height == 0 || count == 0 {
        return;
    }

    // Restore blocks from (head_height - count) to (head_height - 1).
    // HEAD itself is already restored by `recover_finalized_state`.
    let start_height = head_height.saturating_sub(count);
    if start_height == head_height {
        return;
    }

    let mut populated = 0u64;
    for height in start_height..head_height {
        match finalized_blocks.get(ArchiveId::Index(height)).await {
            Ok(Some(block)) => {
                let digest = block.commitment();
                // Skip if already in the cache.
                if ledger.query_state_root(digest).await.is_some() {
                    continue;
                }
                ledger.restore_persisted_snapshot(&block).await;
                populated += 1;
            }
            Ok(None) => {
                debug!(height, "prepopulate: no block at height, stopping");
                break;
            }
            Err(err) => {
                warn!(height, error = ?err, "prepopulate: failed to load block");
                break;
            }
        }
    }

    if populated > 0 {
        info!(
            populated,
            range_start = start_height,
            head_height,
            "pre-populated snapshot cache with recent finalized blocks"
        );
    }
}

#[derive(Clone)]
struct ConstantSchemeProvider(Arc<ThresholdScheme>);

impl commonware_cryptography::certificate::Provider for ConstantSchemeProvider {
    type Scope = Epoch;
    type Scheme = ThresholdScheme;

    fn scoped(&self, _epoch: Epoch) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }

    fn all(&self) -> Option<Arc<Self::Scheme>> {
        Some(self.0.clone())
    }
}

impl From<ThresholdScheme> for ConstantSchemeProvider {
    fn from(scheme: ThresholdScheme) -> Self {
        Self(Arc::new(scheme))
    }
}

#[derive(Clone, Debug)]
struct RevmContextProvider {
    gas_limit: u64,
    fee_recipient: Address,
    block_index: Arc<BlockIndex>,
}

impl RevmContextProvider {
    /// Collect recent block hashes from the block index for the BLOCKHASH opcode.
    fn recent_block_hashes(&self, current_height: u64) -> std::collections::HashMap<u64, B256> {
        self.block_index.recent_block_hashes(current_height)
    }
}

impl BlockContextProvider for RevmContextProvider {
    fn context(&self, block: &Block) -> BlockContext {
        // Compute EIP-1559 base fee from the parent block's gas usage.
        // The parent should already be indexed when finalizing in order.
        // Fall back to INITIAL_BASE_FEE for genesis (height 0) or if the
        // parent is not yet indexed (e.g. during catch-up).
        let base_fee = if block.height == 0 {
            kora_config::INITIAL_BASE_FEE
        } else {
            self.block_index
                .get_block_by_number(block.height - 1)
                .map(|parent| {
                    calculate_base_fee(
                        parent.base_fee_per_gas.unwrap_or(kora_config::INITIAL_BASE_FEE),
                        parent.gas_used,
                        parent.gas_limit,
                        &BaseFeeParams::DEFAULT,
                    )
                })
                .unwrap_or(kora_config::INITIAL_BASE_FEE)
        };

        let header = Header {
            number: block.height,
            timestamp: block.timestamp,
            gas_limit: self.gas_limit,
            beneficiary: self.fee_recipient,
            base_fee_per_gas: Some(base_fee),
            ..Default::default()
        };
        let recent_hashes = self.recent_block_hashes(block.height);
        BlockContext::new(header, B256::ZERO, block.prevrandao)
            .with_recent_block_hashes(recent_hashes)
    }
}

fn spawn_ledger_observers<S: Spawner>(service: LedgerService, spawner: S, data_dir: PathBuf) {
    let mut receiver = service.subscribe();
    spawner.shared(true).spawn(move |_| async move {
        while let Some(event) = receiver.next().await {
            match event {
                LedgerEvent::TransactionSubmitted(id) => {
                    trace!(tx=?id, "mempool accepted transaction");
                }
                LedgerEvent::SeedUpdated(digest, seed) => {
                    debug!(digest=?digest, seed=?seed, "seed cache refreshed");
                }
                LedgerEvent::SnapshotPersisted(digest) => {
                    trace!(?digest, "snapshot persisted");
                    if let Err(e) = crate::commit_marker::write_commit_marker(&data_dir, &digest) {
                        warn!(
                            error = %e,
                            ?digest,
                            "failed to write commit marker after persist"
                        );
                    }
                }
            }
        }
    });
}

fn spawn_txpool_cleanup(pool: TransactionPool, context: cw_tokio::Context) {
    context.child("txpool_cleanup").shared(false).spawn(move |ctx| async move {
        loop {
            ctx.sleep(TXPOOL_CLEANUP_INTERVAL).await;
            let removed = pool.cleanup();
            if removed > 0 {
                debug!(removed, "expired transactions cleaned from txpool");
            }
        }
    });
}

/// Bounded seen-set for transaction gossip de-duplication.
///
/// Tracks the hashes of recently seen transactions so we neither re-broadcast
/// locally originated transactions that come back from peers nor re-insert
/// gossipped transactions we already have.  When the set exceeds
/// [`TX_GOSSIP_SEEN_SET_CAPACITY`] it is cleared wholesale -- this is cheaper
/// than an LRU and perfectly safe because the txpool itself provides the
/// ultimate dedup (via `AlreadyExists` / `NonceAlreadyInPool`).
type SeenSet = Arc<parking_lot::Mutex<HashSet<B256>>>;

fn new_seen_set() -> SeenSet {
    Arc::new(parking_lot::Mutex::new(HashSet::with_capacity(1024)))
}

/// Returns `true` if the hash was **not** previously present (i.e. it is new).
fn mark_seen(seen: &SeenSet, hash: B256) -> bool {
    let mut set = seen.lock();
    if set.len() >= TX_GOSSIP_SEEN_SET_CAPACITY {
        debug!(capacity = TX_GOSSIP_SEEN_SET_CAPACITY, "tx gossip seen-set full, clearing");
        set.clear();
    }
    set.insert(hash)
}

/// Periodically check peer connectivity and log warnings when the network
/// appears degraded or partitioned.
///
/// This task reads the peer count from `NodeState` every
/// [`PARTITION_CHECK_INTERVAL`] and compares it against the expected peer
/// count to determine partition status. Warnings and errors are emitted so
/// operators (and log-based alerting) can detect connectivity issues even
/// without Prometheus.
fn spawn_partition_monitor(node_state: kora_rpc::NodeState, context: cw_tokio::Context) {
    context.child("partition_monitor").shared(false).spawn(move |ctx| async move {
        loop {
            ctx.sleep(PARTITION_CHECK_INTERVAL).await;
            let status = node_state.status();
            match status.partition_status {
                kora_rpc::PartitionStatus::Healthy => {
                    trace!(
                        peer_count = status.peer_count,
                        expected = status.total_expected_peers,
                        "partition check: healthy"
                    );
                }
                kora_rpc::PartitionStatus::Degraded => {
                    warn!(
                        peer_count = status.peer_count,
                        expected = status.total_expected_peers,
                        "partition check: DEGRADED — some peers missing but quorum still possible"
                    );
                }
                kora_rpc::PartitionStatus::Partitioned => {
                    error!(
                        peer_count = status.peer_count,
                        expected = status.total_expected_peers,
                        "partition check: PARTITIONED — below quorum threshold, consensus cannot progress"
                    );
                }
            }
        }
    });
}

/// Monitor critical consensus infrastructure tasks for unexpected termination.
///
/// Each of the three handles (`engine`, `marshal`, `broadcast`) wraps a
/// long-lived actor that must never exit while the node is running.  If any of
/// them resolves it means the actor either panicked (the commonware runtime
/// catches panics and returns [`commonware_runtime::Error::Exited`]) or the
/// runtime context was shut down.  In either case the node can no longer make
/// progress on consensus, so we log an error and abort the process.
fn spawn_consensus_monitor(
    context: cw_tokio::Context,
    engine_handle: RuntimeHandle<()>,
    marshal_handle: RuntimeHandle<()>,
    broadcast_handle: RuntimeHandle<()>,
) {
    spawn_task_watchdog(&context, "consensus_engine", engine_handle);
    spawn_task_watchdog(&context, "marshal_actor", marshal_handle);
    spawn_task_watchdog(&context, "broadcast_engine", broadcast_handle);
}

/// Spawn a watchdog that awaits a critical task handle and aborts the process
/// if the task ever terminates.  Under normal operation the handle never
/// resolves; if it does, consensus is irrecoverably broken.
///
/// Before aborting, the watchdog sleeps briefly to allow the tracing subscriber
/// to flush buffered log output.  This makes post-mortem diagnosis possible
/// even when the process is restarted by a supervisor immediately.
fn spawn_task_watchdog(context: &cw_tokio::Context, name: &'static str, handle: RuntimeHandle<()>) {
    context.child(name).shared(true).spawn(move |ctx| async move {
        let reason = match handle.await {
            Ok(()) => {
                error!(task = name, "critical task exited cleanly — this should never happen for a long-lived consensus actor");
                "exited cleanly (unexpected)"
            }
            Err(commonware_runtime::Error::Exited) => {
                error!(task = name, "critical task panicked (runtime caught panic and returned Error::Exited)");
                "panicked (Error::Exited)"
            }
            Err(commonware_runtime::Error::Closed) => {
                // Runtime context was shut down (e.g. SIGTERM). This is normal
                // shutdown -- do NOT abort, just let the process exit cleanly so
                // any in-progress cleanup (QMDB flush, log drain) can complete.
                info!(task = name, "task stopped (runtime context closed during shutdown)");
                return;
            }
            Err(ref e) => {
                error!(task = name, error = %e, error_debug = ?e, "critical task failed with unexpected error");
                "unexpected error"
            }
        };
        info!(
            task = name,
            reason,
            "consensus infrastructure is dead — aborting process for supervisor restart"
        );
        // Brief delay so the tracing subscriber can flush the log messages above.
        ctx.sleep(Duration::from_millis(100)).await;
        std::process::abort();
    });
}

/// Production validator node runner.
#[derive(Clone, Debug)]
pub struct ProductionRunner {
    /// Threshold signing scheme.
    pub scheme: ThresholdScheme,
    /// Chain ID.
    pub chain_id: u64,
    /// Bootstrap configuration.
    pub bootstrap: BootstrapConfig,
    /// Storage partition prefix.
    pub partition_prefix: String,
    /// Optional RPC configuration (state, bind address).
    pub rpc_config: Option<(kora_rpc::NodeState, std::net::SocketAddr)>,
    /// Optional Prometheus metrics server address.
    pub metrics_addr: Option<std::net::SocketAddr>,
    /// Secondary peers authorized to follow validator traffic without participating in consensus.
    pub secondary_peers: Vec<Peer>,
}

impl ProductionRunner {
    /// Create a new production runner.
    ///
    /// The gas limit is sourced exclusively from `config.execution.gas_limit`
    /// at runtime, so it is not accepted here.
    pub fn new(scheme: ThresholdScheme, chain_id: u64, bootstrap: BootstrapConfig) -> Self {
        Self {
            scheme,
            chain_id,
            bootstrap,
            partition_prefix: PARTITION_PREFIX.to_string(),
            rpc_config: None,
            metrics_addr: None,
            secondary_peers: Vec::new(),
        }
    }

    /// Configure RPC server.
    #[must_use]
    pub fn with_rpc(mut self, state: kora_rpc::NodeState, addr: std::net::SocketAddr) -> Self {
        self.rpc_config = Some((state, addr));
        self
    }

    /// Configure Prometheus metrics server address.
    #[must_use]
    pub const fn with_metrics_addr(mut self, addr: std::net::SocketAddr) -> Self {
        self.metrics_addr = Some(addr);
        self
    }

    /// Configure secondary peers that should be tracked by the P2P oracle.
    #[must_use]
    pub fn with_secondary_peers(mut self, peers: Vec<Peer>) -> Self {
        self.secondary_peers = peers;
        self
    }
}

impl ProductionRunner {
    /// Run the validator as a standalone process.
    pub fn run_standalone(self, config: kora_config::NodeConfig) -> Result<(), RunnerError> {
        use commonware_runtime::Runner;
        use kora_transport::NetworkConfigExt;

        let runtime_dir = runtime_storage_directory(&config.data_dir);
        info!(
            runtime_dir = %runtime_dir.display(),
            worker_threads = config.worker_threads,
            "Starting Commonware runtime"
        );
        let executor = cw_tokio::Runner::new(
            cw_tokio::Config::default()
                .with_storage_directory(runtime_dir)
                .with_worker_threads(config.worker_threads),
        );
        executor.start(|context| async move {
            let validator_key = config
                .validator_key()
                .map_err(|e| anyhow::anyhow!("failed to load validator key: {}", e))?;

            let transport = config
                .network
                .build_local_transport(validator_key, context.child("transport"))
                .map_err(|e| anyhow::anyhow!("failed to build transport: {}", e))?;

            let ctx =
                kora_service::NodeRunContext::new(context, std::sync::Arc::new(config), transport);

            let _ledger = self.run(ctx).await?;

            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
            info!("Received shutdown signal, initiating graceful shutdown...");

            // Allow a brief window for in-flight QMDB commits and log drains
            // to complete before the runtime drops all task contexts. The
            // watchdog no longer calls abort() on `Error::Closed`, so these
            // tasks will terminate cleanly when their contexts are dropped.
            tokio::time::sleep(Duration::from_millis(200)).await;

            info!("Graceful shutdown complete");
            Ok::<(), RunnerError>(())
        })
    }
}

impl NodeRunner for ProductionRunner {
    type Transport = NetworkTransport<Peer, cw_tokio::Context>;
    type Handle = LedgerService;
    type Error = RunnerError;

    async fn run(&self, ctx: NodeRunContext<Self::Transport>) -> Result<Self::Handle, Self::Error> {
        let (context, config, mut transport) = ctx.into_parts();
        let gas_limit = config.execution.gas_limit;
        let simplex_config = config.consensus.simplex;

        info!(chain_id = self.chain_id, "Starting production validator");

        let validators = self.scheme.participants().clone();
        let secondary = Set::from_iter_dedup(self.secondary_peers.iter().cloned());
        let secondary_count = secondary.len();
        transport.oracle.track(0, TrackedPeers::new(validators, secondary));
        info!(
            validators = self.scheme.participants().len(),
            secondary_peers = secondary_count,
            "Registered primary and secondary peers with oracle"
        );

        let page_cache = default_page_cache(&context);
        let block_cfg = block_codec_cfg(&config.consensus.block_codec);
        let partition_prefix = &self.partition_prefix;
        // Use a single Rayon worker thread for BLS signature verification.
        // Rayon's work-stealing scheduler busy-waits (sched_yield) when idle,
        // and BLS batches are small enough (~6-10 msgs at 30 blocks/s) that
        // parallelism across 2 threads provides negligible speedup.  With
        // Docker CPU limits (0.75-1.2 cores), the second idle thread wastes
        // ~0.21 cores of CPU in spin loops and inflates involuntary context
        // switches by 100K+/5min.
        let strategy = context
            .create_strategy(NZUsize!(1))
            .map_err(|e| anyhow::anyhow!("failed to create signature strategy: {e}"))?;
        let checkpoint_interval = checkpoint_interval();
        info!(checkpoint_interval, "configured finalized archive and QMDB checkpoint interval");

        // Migrate any legacy immutable archive partitions left over from
        // before the switch to prunable archives. The old backend used
        // different partition names, so its data is silently orphaned on
        // upgrade. This detects, warns, and removes the stale partitions.
        let finalizations_prefix = format!("{partition_prefix}-finalizations-by-height");
        let blocks_prefix = format!("{partition_prefix}-finalized-blocks");
        ArchiveInitializer::migrate_from_immutable(&context, &finalizations_prefix).await;
        ArchiveInitializer::migrate_from_immutable(&context, &blocks_prefix).await;

        <ThresholdScheme as commonware_cryptography::certificate::Scheme>::certificate_codec_config_unbounded();
        let finalizations_by_height =
            ArchiveInitializer::init_prunable_checkpointed::<_, ConsensusDigest, CertArchive>(
                context.child("finalizations_by_height"),
                finalizations_prefix,
                (),
                checkpoint_interval,
            )
            .await
            .context("init finalizations archive")?;

        let finalized_blocks =
            ArchiveInitializer::init_prunable_checkpointed::<_, ConsensusDigest, Block>(
                context.child("finalized_blocks"),
                blocks_prefix,
                block_cfg,
                checkpoint_interval,
            )
            .await
            .context("init blocks archive")?;

        let has_finalized_history = finalized_blocks.last_index().is_some();
        let state = LedgerView::init_with_genesis_options(
            context.child("state"),
            format!("{}-qmdb", self.partition_prefix),
            self.bootstrap.genesis_alloc.clone(),
            !has_finalized_history,
            self.bootstrap.genesis_timestamp,
        )
        .await
        .context("init qmdb")?;

        let pending_tx_broadcast =
            self.rpc_config.as_ref().map(|_| kora_rpc::pending_tx_channel().0);
        let mempool_broadcast =
            self.rpc_config.as_ref().map(|_| kora_rpc::mempool_event_channel().0);
        let ledger = LedgerService::new(state.clone());
        let block_index = Arc::new(BlockIndex::new());
        seed_genesis_block_index(&block_index, &ledger.genesis_block(), gas_limit);
        spawn_ledger_observers(
            ledger.clone(),
            context.child("ledger_observers"),
            config.data_dir.clone(),
        );
        let txpool = ledger.txpool().await;
        spawn_txpool_cleanup(txpool.clone(), context.child("txpool"));

        // Initialize application-level Prometheus metrics and register them
        // with the commonware runtime so they appear on the /metrics endpoint.
        let app_metrics = AppMetrics::new();
        app_metrics.register(&RuntimeMetrics(&context));
        txpool.set_metrics(app_metrics.clone());
        // -- Transaction gossip infrastructure --
        let (gossip_outbound_tx, gossip_seen): (
            Option<tokio::sync::mpsc::Sender<alloy_primitives::Bytes>>,
            Option<SeenSet>,
        ) = if config.network.tx_gossip {
            let (tx_gossip_sender, tx_gossip_receiver) = transport.tx_gossip.channel;
            let seen = new_seen_set();
            let (outbound_tx, gossip_outbound_rx) =
                tokio::sync::mpsc::channel::<alloy_primitives::Bytes>(TX_GOSSIP_OUTBOUND_BUFFER);

            // Outbound: read from internal channel, broadcast via P2P.
            {
                let seen = seen.clone();
                let mut sender = tx_gossip_sender;
                let out_metrics = app_metrics.clone();
                context.child("tx_gossip_out").shared(true).spawn(move |_| async move {
                    let mut rx = gossip_outbound_rx;
                    while let Some(raw) = rx.recv().await {
                        let hash = keccak256(&raw);
                        if !mark_seen(&seen, hash) {
                            continue;
                        }
                        let msg = bytes::Bytes::copy_from_slice(&raw);
                        let recipients = sender.send(Recipients::All, msg, false);
                        if recipients.is_empty() {
                            warn!("tx gossip: failed to broadcast transaction");
                            out_metrics.gossip_tx_broadcast_failed.inc();
                        } else {
                            trace!(
                                ?hash,
                                recipients = recipients.len(),
                                "tx gossip: broadcast transaction to peers"
                            );
                            out_metrics.gossip_tx_broadcast.inc();
                        }
                    }
                    debug!("tx gossip outbound channel closed");
                });
            }

            // Inbound: read from P2P, validate, insert into local pool.
            {
                let seen = seen.clone();
                let gossip_ledger = ledger.clone();
                let gossip_chain_id = self.chain_id;
                let gossip_pool = txpool.clone();
                let mut receiver = tx_gossip_receiver;
                let in_metrics = app_metrics.clone();
                context.child("tx_gossip_in").shared(true).spawn(move |_| async move {
                    loop {
                        let (peer, raw) = match receiver.recv().await {
                            Ok(msg) => msg,
                            Err(e) => {
                                warn!(error = %e, "tx gossip: receive error, stopping inbound handler");
                                break;
                            }
                        };

                        in_metrics.gossip_tx_received.inc();
                        let hash = keccak256(&raw);
                        if !mark_seen(&seen, hash) {
                            trace!(?hash, ?peer, "tx gossip: skipping already-seen transaction");
                            continue;
                        }

                        let data = alloy_primitives::Bytes::copy_from_slice(raw.as_ref());
                        let tx = Tx::new(data);
                        let tx_id = tx.id();

                        // Fetch the latest state on each validation so nonce
                        // and balance checks reflect finalized blocks.  The
                        // previous code captured state once at startup, making
                        // gossip validation increasingly stale.
                        let current_state = gossip_ledger.latest_state().await;
                        let validator = TransactionValidator::new(
                            gossip_chain_id,
                            current_state,
                            PoolConfig::default(),
                        )
                        .with_pool(gossip_pool.clone());
                        if let Err(e) = validator.validate(tx.clone()).await {
                            trace!(?tx_id, ?peer, error = %e, "tx gossip: peer tx failed validation");
                            in_metrics.gossip_tx_invalid.inc();
                            continue;
                        }

                        if gossip_ledger.submit_tx(tx).await {
                            debug!(?tx_id, ?peer, "tx gossip: accepted transaction from peer");
                        } else {
                            trace!(?tx_id, ?peer, "tx gossip: ledger rejected transaction (duplicate)");
                        }
                    }
                });
            }

            info!("Transaction gossip enabled");
            (Some(outbound_tx), Some(seen))
        } else {
            // Drop the gossip channel - we won't use it
            drop(transport.tx_gossip);
            info!(
                "Transaction gossip disabled (enable with network.tx_gossip = true or --tx-gossip)"
            );
            (None, None)
        };

        let fee_recipient = config.execution.fee_recipient.unwrap_or(Address::ZERO);
        let context_provider =
            RevmContextProvider { gas_limit, fee_recipient, block_index: block_index.clone() };
        let recovered_head_height = recover_finalized_state(
            &ledger,
            &block_index,
            &finalized_blocks,
            &finalizations_by_height,
            &context_provider,
            &config.data_dir,
            self.chain_id,
        )
        .await
        .context("recover finalized state")?;

        // Pre-populate the snapshot cache with the last N blocks so that
        // blocks arriving shortly after restart can find their parent
        // snapshot. Without this, only the HEAD snapshot exists after
        // recovery, and verify_block would fail for any block whose parent
        // is not HEAD.
        if let Some((head_height, replayed_tail)) = recovered_head_height
            && !replayed_tail
        {
            prepopulate_snapshot_cache(
                &ledger,
                &finalized_blocks,
                head_height,
                SNAPSHOT_PREPOPULATE_COUNT,
            )
            .await;
        }

        if let Some((node_state, addr)) = &self.rpc_config {
            let peer_count = self.scheme.participants().len().saturating_sub(1) as u64;
            node_state.set_peer_count(peer_count);

            // Restore finalized height from archive so the proposal lag guard
            // in RevmApplication does not reject proposals after a restart.
            if let Some(last) = finalized_blocks.last_index() {
                node_state.set_finalized_height(last);
            }

            // Use LiveState so RPC queries read from the latest in-memory
            // overlay rather than the persisted QMDB checkpoint (which can lag
            // up to 256 blocks behind head).
            let live_state = LiveState::new(ledger.clone());
            let rpc_executor = Arc::new(RevmExecutor::new(self.chain_id));
            let indexed_provider = kora_rpc::IndexedStateProvider::new(
                block_index.clone(),
                live_state,
                rpc_executor,
                fee_recipient,
            );
            let tx_ledger = ledger.clone();
            let chain_id = self.chain_id;
            let tx_pool = txpool.clone();
            let gossip_tx = gossip_outbound_tx.clone();
            let gossip_seen_rpc = gossip_seen.clone();
            let tx_submit: kora_rpc::TxSubmitCallback = Arc::new(move |data| {
                let ledger = tx_ledger.clone();
                let pool = tx_pool.clone();
                let gossip = gossip_tx.clone();
                let seen = gossip_seen_rpc.clone();
                Box::pin(async move {
                    let tx = Tx::new(data.clone());
                    let tx_id = tx.id();
                    let state = ledger.latest_state().await;
                    let validator =
                        TransactionValidator::new(chain_id, state, PoolConfig::default())
                            .with_pool(pool);
                    validator.validate(tx.clone()).await.map_err(|err| {
                        warn!(?tx_id, error = %err, "rpc submit: validator rejected tx");
                        kora_rpc::RpcError::InvalidTransaction(err.to_string())
                    })?;
                    if ledger.submit_tx(tx).await {
                        debug!(?tx_id, "rpc submit: tx inserted into mempool");
                        // Forward to gossip if enabled.
                        if let (Some(gossip), Some(seen)) = (&gossip, &seen) {
                            let hash = keccak256(&data);
                            mark_seen(seen, hash);
                            if let Err(e) = gossip.try_send(data) {
                                warn!(error = %e, "tx gossip: outbound channel full, skipping broadcast");
                            }
                        }
                        Ok(())
                    } else {
                        warn!(
                            ?tx_id,
                            "rpc submit: ledger.submit_tx returned false (duplicate or pool error)"
                        );
                        Err(kora_rpc::RpcError::InvalidTransaction(
                            "transaction rejected by mempool".to_string(),
                        ))
                    }
                })
            });
            let mut rpc = kora_rpc::RpcServer::with_state_provider(
                node_state.clone(),
                *addr,
                self.chain_id,
                indexed_provider,
            )
            .with_tx_submit(tx_submit)
            .with_txpool(txpool.clone())
            .with_peer_count(peer_count)
            .with_rpc_requests_counter(app_metrics.rpc_requests_total.clone());
            if let Some(sender) = pending_tx_broadcast.clone() {
                rpc = rpc.with_pending_tx_broadcast(sender);
            }
            if let Some(sender) = mempool_broadcast.clone() {
                rpc = rpc.with_mempool_broadcast(sender);
            }
            // Keep the RPC handle alive so the HTTP and JSON-RPC tasks are not
            // cancelled immediately.  The handle is dropped when `run()` returns
            // (i.e. after the signal handler completes), which cleanly stops the
            // RPC servers during shutdown.
            let _rpc_handle = rpc.start();
            info!(addr = %addr, "RPC server started with live state provider");

            spawn_partition_monitor(node_state.clone(), context.child("partition"));
        }

        if let Some(metrics_addr) = self.metrics_addr {
            let metrics_context = Arc::new(context.child("metrics_endpoint"));
            context.child("metrics").shared(true).spawn(move |_| async move {
                let app = axum::Router::new().route(
                    "/metrics",
                    axum::routing::get(move || {
                        let metrics_context = metrics_context.clone();
                        async move {
                            let body = metrics_context.encode();
                            (
                                axum::http::StatusCode::OK,
                                [(
                                    axum::http::header::CONTENT_TYPE,
                                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                                )],
                                body,
                            )
                        }
                    }),
                );

                let listener = match tokio::net::TcpListener::bind(metrics_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!(addr = %metrics_addr, error = %e, "Failed to bind metrics server");
                        return;
                    }
                };

                info!(addr = %metrics_addr, "Starting metrics server");
                if let Err(e) = axum::serve(listener, app).await {
                    error!(error = %e, "Metrics server error");
                }
            });
        }

        let validator_key = config
            .validator_key()
            .map_err(|e| anyhow::anyhow!("failed to load validator key: {}", e))?;
        let my_pk = commonware_cryptography::Signer::public_key(&validator_key);

        let finalized_executor = RevmExecutor::new(self.chain_id);
        let mut finalized_reporter = FinalizedReporter::new(
            ledger.clone(),
            context.child("finalized_reporter"),
            finalized_executor,
            context_provider,
        )
        .with_block_index(block_index.clone())
        .with_metrics(app_metrics.clone())
        .with_checkpoint_interval(checkpoint_interval);
        if let Some((state, _)) = &self.rpc_config {
            finalized_reporter = finalized_reporter.with_node_state(state.clone());
        }
        if let Some(sender) = mempool_broadcast {
            finalized_reporter = finalized_reporter.with_mempool_broadcast(sender);
        }

        // Initialize the selfdestruct GC log for tracking orphaned storage.
        match kora_reporters::SelfdestructGcLog::open(&config.data_dir) {
            Ok(gc_log) => {
                info!(
                    path = %config.data_dir.display(),
                    "Opened selfdestruct GC log for tracking orphaned storage"
                );
                finalized_reporter = finalized_reporter.with_gc_log(Arc::new(gc_log));
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to open selfdestruct GC log; selfdestructed addresses will not be tracked"
                );
            }
        }

        let scheme_provider = ConstantSchemeProvider::from(self.scheme.clone());

        // Suppress resolver peer-bans during catch-up to avoid blocking peers
        // that serve historical data which fails local verification due to
        // missing parent snapshots. The simplex engine uses the real oracle
        // blocker unconditionally since it only bans for genuine equivocation.
        let resolver_catching_up = Arc::new(AtomicBool::new(recovered_head_height.is_some()));
        let resolver_blocker =
            GraduatedBlocker::new(transport.oracle.clone(), resolver_catching_up);

        let resolver = PeerInitializer::init::<_, _, _, Block, _, _, _>(
            context.child("resolver"),
            my_pk.clone(),
            transport.oracle.clone(),
            resolver_blocker,
            transport.marshal.backfill,
        );

        let (broadcast_engine, buffer) = BroadcastInitializer::init::<_, Peer, Block, _>(
            context.child("broadcast"),
            my_pk.clone(),
            transport.oracle.clone(),
            block_cfg,
        );
        let broadcast_handle = broadcast_engine.start(transport.marshal.blocks);

        let scratch_context = NoSyncStorage::new(context.child("scratch"), checkpoint_interval);
        let (actor, marshal_mailbox, _last_processed_height) =
            kora_marshal::ActorInitializer::init_with_strategy::<_, Block, _, _, _, Exact, _>(
                scratch_context.clone(),
                finalizations_by_height,
                finalized_blocks,
                scheme_provider,
                commonware_consensus::marshal::Start::Genesis(ledger.genesis_block()),
                page_cache.clone(),
                block_cfg,
                strategy.clone(),
            )
            .await;
        let marshal_handle = actor.start(finalized_reporter, buffer, resolver);

        let epocher = FixedEpocher::new(NZU64!(EPOCH_LENGTH));
        let executor = RevmExecutor::new(self.chain_id);
        let mut app = RevmApplication::<ThresholdScheme, _>::new(
            ledger.clone(),
            executor,
            block_cfg.max_txs,
            gas_limit,
            fee_recipient,
        );
        app = app.with_metrics(app_metrics.clone());
        if let Some((height, _)) = recovered_head_height {
            app = app.with_recovered_height(height);
            // Seed the block-fee cache from the block index so that the
            // first blocks after restart can compute a correct EIP-1559
            // base fee.  We seed the last few blocks to cover the parent
            // of the next proposed/verified block.
            seed_block_fee_cache(&app, &block_index, height);
            if let Some((state, _)) = &self.rpc_config {
                state.set_recovered_height(height);
            }
        }
        if let Some((state, _)) = &self.rpc_config {
            app = app.with_node_state(state.clone());
        }
        let marshaled =
            Inline::new(scratch_context.child("marshaled"), app, marshal_mailbox.clone(), epocher);

        let seed_reporter = SeedReporter::<MinSig>::new(ledger.clone());
        let node_state_reporter = self.rpc_config.as_ref().map(|(state, _)| {
            NodeStateReporter::<ThresholdScheme>::new(state.clone()).with_metrics(app_metrics)
        });
        let inner_reporters: Reporters<_, MarshalMailbox, Option<NodeStateRptr>> =
            Reporters::from((marshal_mailbox.clone(), node_state_reporter));
        let reporter = Reporters::from((seed_reporter, inner_reporters));

        for tx in &self.bootstrap.bootstrap_txs {
            if !ledger.submit_tx(tx.clone()).await {
                warn!("failed to submit bootstrap transaction to mempool");
            }
        }

        let engine = simplex::Engine::new(
            scratch_context.child("engine"),
            simplex::Config {
                scheme: self.scheme.clone(),
                elector: Random,
                blocker: transport.oracle.clone(),
                automaton: marshaled.clone(),
                relay: marshaled,
                reporter,
                strategy,
                partition: self.partition_prefix.clone(),
                mailbox_size: NZUsize!(MAILBOX_SIZE),
                epoch: Epoch::zero(),
                floor: simplex::Floor::Genesis(ledger.genesis_block().commitment()),
                replay_buffer: simplex_config.replay_buffer_bytes,
                write_buffer: simplex_config.write_buffer_bytes,
                leader_timeout: Duration::from_secs(simplex_config.leader_timeout_secs.get()),
                certification_timeout: Duration::from_secs(
                    simplex_config.certification_timeout_secs.get(),
                ),
                timeout_retry: Duration::from_secs(simplex_config.timeout_retry_secs.get()),
                fetch_timeout: Duration::from_secs(simplex_config.fetch_timeout_secs.get()),
                activity_timeout: ViewDelta::new(simplex_config.activity_timeout_views.get()),
                skip_timeout: ViewDelta::new(simplex_config.skip_timeout_views.get()),
                fetch_concurrent: simplex_config.fetch_concurrent,
                page_cache,
                forwarding: simplex::ForwardingPolicy::SilentLeader,
            },
        );
        let engine_handle = engine.start(
            transport.simplex.votes,
            transport.simplex.certs,
            transport.simplex.resolver,
        );

        spawn_consensus_monitor(context, engine_handle, marshal_handle, broadcast_handle);

        info!("Validator started successfully");
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use kora_config::ConsensusBlockCodecConfig;
    use kora_domain::{BlockId, StateRoot};

    use super::*;

    #[test]
    fn seed_genesis_block_index_indexes_real_genesis_metadata() {
        let index = BlockIndex::new();
        let genesis = Block::new(
            BlockId(B256::repeat_byte(0x11)),
            0,
            0,
            B256::repeat_byte(0x22),
            StateRoot(B256::repeat_byte(0x33)),
            Vec::new(),
        );
        let gas_limit = 45_000_000;

        seed_genesis_block_index(&index, &genesis, gas_limit);

        let indexed = index.get_block_by_number(0).expect("genesis indexed");
        assert_eq!(indexed.hash, genesis.id().0);
        assert_eq!(indexed.number, 0);
        assert_eq!(indexed.parent_hash, genesis.parent.0);
        assert_eq!(indexed.state_root, genesis.state_root.0);
        assert_eq!(indexed.timestamp, 0);
        assert_eq!(indexed.gas_limit, gas_limit);
        assert_eq!(indexed.gas_used, 0);
        assert_eq!(indexed.base_fee_per_gas, Some(kora_config::INITIAL_BASE_FEE));
        assert_eq!(indexed.transaction_hashes, Vec::<B256>::new());
        assert_eq!(index.get_block_by_hash(&genesis.id().0).expect("genesis by hash").number, 0);
    }

    #[test]
    fn seed_genesis_block_index_uses_genesis_timestamp() {
        let index = BlockIndex::new();
        let genesis = Block::new(
            BlockId(B256::ZERO),
            0,
            1_700_000_000,
            B256::ZERO,
            StateRoot(B256::ZERO),
            Vec::new(),
        );

        seed_genesis_block_index(&index, &genesis, 30_000_000);

        let indexed = index.get_block_by_number(0).expect("genesis indexed");
        assert_eq!(indexed.timestamp, 1_700_000_000);
    }

    #[test]
    fn block_codec_cfg_uses_consensus_config() {
        let config = ConsensusBlockCodecConfig {
            max_txs: NonZeroUsize::new(512).unwrap(),
            max_tx_bytes: NonZeroUsize::new(4096).unwrap(),
        };

        let block_cfg = block_codec_cfg(&config);

        assert_eq!(block_cfg.max_txs, 512);
        assert_eq!(block_cfg.tx.max_tx_bytes, 4096);
    }

    #[test]
    fn runtime_storage_directory_defaults_under_data_dir() {
        let data_dir = PathBuf::from("/var/lib/kora");

        assert_eq!(
            runtime_storage_directory_from(&data_dir, None),
            PathBuf::from("/var/lib/kora/runtime")
        );
    }

    #[test]
    fn runtime_storage_directory_ignores_empty_override() {
        let data_dir = PathBuf::from("/var/lib/kora");

        assert_eq!(
            runtime_storage_directory_from(&data_dir, Some(OsString::new())),
            PathBuf::from("/var/lib/kora/runtime")
        );
    }

    #[test]
    fn runtime_storage_directory_uses_override() {
        let data_dir = PathBuf::from("/var/lib/kora");

        assert_eq!(
            runtime_storage_directory_from(&data_dir, Some(OsString::from("/runtime"))),
            PathBuf::from("/runtime")
        );
    }
}
