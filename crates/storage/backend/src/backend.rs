//! Commonware-based QMDB backend implementation.

use alloy_primitives::{B256, U256};
use async_trait::async_trait;
use commonware_codec::RangeCfg;
use commonware_cryptography::sha256::Digest as QmdbDigest;
use commonware_parallel::Sequential;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef};
use commonware_storage::{
    journal::contiguous::variable::Config as JournalConfig, merkle::full::Config as MerkleConfig,
    qmdb::any::VariableConfig, translator::EightCap,
};
use commonware_utils::{NZU64, NZUsize};
use kora_handlers::{HandleError, RootProvider};
use kora_qmdb::{ChangeSet, PartitionCommitSeqs, QmdbStore, StateRoot};
use tracing::{error, info};

use crate::{
    AccountStore, BackendError, CodeStore, QmdbBackendConfig, StorageStore,
    accounts::AccountStoreDirty, code::CodeStoreDirty, storage::StorageStoreDirty, types::Context,
};

const CODE_MAX_BYTES: usize = 24_576;

/// Commonware-based QMDB backend.
///
/// Provides storage for accounts, storage slots, and code using
/// commonware-storage primitives.
pub struct CommonwareBackend {
    accounts: AccountStore,
    storage: StorageStore,
    code: CodeStore,
    context: Context,
    config: QmdbBackendConfig,
}

/// Root provider that computes state roots from commonware-storage partitions.
pub struct CommonwareRootProvider {
    context: Context,
    config: QmdbBackendConfig,
}

impl std::fmt::Debug for CommonwareBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonwareBackend").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CommonwareRootProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonwareRootProvider").finish_non_exhaustive()
    }
}

impl CommonwareRootProvider {
    /// Create a new root provider from the given context and config.
    #[must_use]
    pub const fn new(context: Context, config: QmdbBackendConfig) -> Self {
        Self { context, config }
    }
}

impl CommonwareBackend {
    /// Open a backend with the given configuration.
    pub async fn open(context: Context, config: QmdbBackendConfig) -> Result<Self, BackendError> {
        let stores = open_stores(&context, &config).await?;
        Ok(Self {
            accounts: stores.accounts,
            storage: stores.storage,
            code: stores.code,
            context,
            config,
        })
    }

    /// Get a reference to the accounts store.
    #[must_use]
    pub const fn accounts(&self) -> &AccountStore {
        &self.accounts
    }

    /// Get a mutable reference to the accounts store.
    #[must_use]
    pub const fn accounts_mut(&mut self) -> &mut AccountStore {
        &mut self.accounts
    }

    /// Get a reference to the storage store.
    #[must_use]
    pub const fn storage(&self) -> &StorageStore {
        &self.storage
    }

    /// Get a mutable reference to the storage store.
    #[must_use]
    pub const fn storage_mut(&mut self) -> &mut StorageStore {
        &mut self.storage
    }

    /// Get a reference to the code store.
    #[must_use]
    pub const fn code(&self) -> &CodeStore {
        &self.code
    }

    /// Get a mutable reference to the code store.
    #[must_use]
    pub const fn code_mut(&mut self) -> &mut CodeStore {
        &mut self.code
    }

    /// Consume the backend and return the underlying stores.
    pub fn into_stores(self) -> (AccountStore, StorageStore, CodeStore) {
        (self.accounts, self.storage, self.code)
    }

    /// Build a root provider for this backend configuration.
    pub fn root_provider(&self) -> CommonwareRootProvider {
        CommonwareRootProvider::new(self.context.child("root_provider"), self.config.clone())
    }

    /// Get the current state root.
    pub fn state_root(&self) -> Result<B256, BackendError> {
        state_root_from_stores(&self.accounts, &self.storage, &self.code)
    }

    /// Check cross-partition commit sequence consistency and repair if needed.
    ///
    /// Reads the commit sequence marker from each QMDB partition and verifies
    /// they all agree. If no markers exist (backward-compatible with pre-fix
    /// databases), the check passes.
    ///
    /// If markers are present but differ (indicating a partial commit from a
    /// previous crash), this method attempts automatic recovery by writing the
    /// sentinel marker to any partition that is behind, bringing all partitions
    /// up to the maximum observed sequence. This avoids permanently bricking
    /// the node after a crash during the commit window.
    ///
    /// Returns the [`PartitionCommitSeqs`] on success so the caller can
    /// initialize the `QmdbStore` with the correct starting sequence.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError::InconsistentPartitions`] if repair fails,
    /// or a storage error if reading/writing the markers fails.
    pub async fn verify_partition_consistency(
        &mut self,
    ) -> Result<PartitionCommitSeqs, BackendError> {
        let seqs = read_partition_commit_seqs(&self.accounts, &self.storage, &self.code).await?;

        if seqs.is_consistent() {
            info!(
                commit_seq = ?seqs.accounts.unwrap_or(0),
                "QMDB partition consistency check passed"
            );
            return Ok(seqs);
        }

        // Partitions are inconsistent -- attempt recovery by advancing behind
        // partitions to the max observed sequence.
        let target = seqs.max_seq().expect("inconsistent implies at least one Some");

        tracing::warn!(
            accounts_seq = ?seqs.accounts,
            storage_seq = ?seqs.storage,
            code_seq = ?seqs.code,
            target_seq = target,
            "QMDB partition inconsistency detected, repairing"
        );

        repair_partition_seqs(&mut self.accounts, &mut self.storage, &mut self.code, &seqs, target)
            .await?;

        // Re-read to confirm repair succeeded.
        let repaired =
            read_partition_commit_seqs(&self.accounts, &self.storage, &self.code).await?;

        if let Some(msg) = repaired.inconsistency_message() {
            error!(
                accounts_seq = ?repaired.accounts,
                storage_seq = ?repaired.storage,
                code_seq = ?repaired.code,
                "QMDB partition repair FAILED -- partitions still inconsistent"
            );
            return Err(BackendError::InconsistentPartitions(msg));
        }

        info!(commit_seq = target, "QMDB partition inconsistency repaired successfully");
        Ok(repaired)
    }
}

#[async_trait]
impl RootProvider for CommonwareRootProvider {
    async fn state_root(&self) -> Result<B256, HandleError> {
        let stores = open_stores(&self.context, &self.config)
            .await
            .map_err(|e| HandleError::RootComputation(e.to_string()))?;
        state_root_from_stores(&stores.accounts, &stores.storage, &stores.code)
            .map_err(|e| HandleError::RootComputation(e.to_string()))
    }

    async fn compute_root(&mut self, changes: &ChangeSet) -> Result<B256, HandleError> {
        if changes.is_empty() {
            return self.state_root().await;
        }

        let stores = open_dirty_stores(&self.context, &self.config)
            .await
            .map_err(|e| HandleError::RootComputation(e.to_string()))?;
        let mut qmdb = QmdbStore::new(stores.accounts, stores.storage, stores.code);
        qmdb.commit_changes(changes.clone())
            .await
            .map_err(|e| HandleError::RootComputation(e.to_string()))?;
        let stores = qmdb.take_stores().map_err(|e| HandleError::RootComputation(e.to_string()))?;
        let accounts = stores.accounts.root();
        let storage = stores.storage.root();
        let code = stores.code.root();
        Ok(state_root_from_roots(accounts, storage, code))
    }

    async fn commit_and_get_root(&mut self) -> Result<B256, HandleError> {
        self.state_root().await
    }
}

struct Stores {
    accounts: AccountStore,
    storage: StorageStore,
    code: CodeStore,
}

struct DirtyStores {
    accounts: AccountStoreDirty,
    storage: StorageStoreDirty,
    code: CodeStoreDirty,
}

fn store_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
    log_codec_config: C,
) -> VariableConfig<EightCap, ((), C), Sequential> {
    VariableConfig {
        merkle_config: MerkleConfig {
            journal_partition: format!("{prefix}-{name}-mmr"),
            metadata_partition: format!("{prefix}-{name}-mmr-meta"),
            items_per_blob: NZU64!(128),
            write_buffer: NZUsize!(1024 * 1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: JournalConfig {
            partition: format!("{prefix}-{name}-log"),
            items_per_section: NZU64!(128),
            compression: None,
            codec_config: ((), log_codec_config),
            page_cache,
            write_buffer: NZUsize!(1024 * 1024),
        },
        translator: EightCap,
    }
}

async fn open_stores(
    context: &Context,
    config: &QmdbBackendConfig,
) -> Result<Stores, BackendError> {
    let page_cache = CacheRef::from_pooler(context, config.page_size, config.page_cache_size);

    let accounts = AccountStore::init(
        context.child("accounts"),
        store_config(&config.partition_prefix, "accounts", page_cache.clone(), ()),
    )
    .await
    .map_err(|e| BackendError::Storage(e.to_string()))?;

    let storage = StorageStore::init(
        context.child("storage"),
        store_config(&config.partition_prefix, "storage", page_cache.clone(), ()),
    )
    .await
    .map_err(|e| BackendError::Storage(e.to_string()))?;

    let code = CodeStore::init(
        context.child("code"),
        store_config(
            &config.partition_prefix,
            "code",
            page_cache,
            (RangeCfg::new(0..=CODE_MAX_BYTES), ()),
        ),
    )
    .await
    .map_err(|e| BackendError::Storage(e.to_string()))?;

    Ok(Stores { accounts, storage, code })
}

async fn open_dirty_stores(
    context: &Context,
    config: &QmdbBackendConfig,
) -> Result<DirtyStores, BackendError> {
    let stores = open_stores(context, config).await?;
    Ok(DirtyStores {
        accounts: stores.accounts.into_dirty()?,
        storage: stores.storage.into_dirty()?,
        code: stores.code.into_dirty()?,
    })
}

/// Read commit sequence markers from all three partitions.
///
/// This is a standalone helper so it can operate on borrowed stores without
/// taking ownership. The function uses the well-known sentinel keys defined
/// in [`kora_qmdb`] to retrieve the sequence numbers.
async fn read_partition_commit_seqs(
    accounts: &AccountStore,
    storage: &StorageStore,
    code: &CodeStore,
) -> Result<PartitionCommitSeqs, BackendError> {
    use kora_qmdb::{
        AccountEncoding, COMMIT_SEQ_ACCOUNT_KEY, COMMIT_SEQ_CODE_KEY, COMMIT_SEQ_STORAGE_KEY,
        QmdbGettable,
    };

    let accounts_seq = match accounts.get(&COMMIT_SEQ_ACCOUNT_KEY).await {
        Ok(Some(bytes)) => AccountEncoding::decode(&bytes).map(|(nonce, _, _, _)| nonce),
        Ok(None) => None,
        Err(e) => return Err(BackendError::Storage(e.to_string())),
    };

    let storage_seq = match storage.get(&COMMIT_SEQ_STORAGE_KEY).await {
        Ok(Some(value)) => {
            let limbs: [u64; 4] = value.into_limbs();
            if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 { Some(limbs[0]) } else { None }
        }
        Ok(None) => None,
        Err(e) => return Err(BackendError::Storage(e.to_string())),
    };

    let code_seq = match code.get(&COMMIT_SEQ_CODE_KEY).await {
        Ok(Some(bytes)) => {
            if bytes.len() >= 8 {
                bytes[..8].try_into().ok().map(u64::from_be_bytes)
            } else {
                None
            }
        }
        Ok(None) => None,
        Err(e) => return Err(BackendError::Storage(e.to_string())),
    };

    Ok(PartitionCommitSeqs { accounts: accounts_seq, storage: storage_seq, code: code_seq })
}

/// Repair inconsistent partition commit sequences by writing the sentinel
/// marker to any partition whose sequence is behind `target`.
///
/// This is the recovery counterpart to [`read_partition_commit_seqs`]. Each
/// write is idempotent -- writing the same sentinel value twice is safe.
async fn repair_partition_seqs(
    accounts: &mut AccountStore,
    storage: &mut StorageStore,
    code: &mut CodeStore,
    seqs: &PartitionCommitSeqs,
    target: u64,
) -> Result<(), BackendError> {
    use kora_qmdb::{
        COMMIT_SEQ_ACCOUNT_KEY, COMMIT_SEQ_CODE_KEY, COMMIT_SEQ_STORAGE_KEY, QmdbBatchable,
        encode_commit_seq_account, encode_commit_seq_code,
    };

    if seqs.accounts != Some(target) {
        accounts
            .write_batch(vec![(COMMIT_SEQ_ACCOUNT_KEY, Some(encode_commit_seq_account(target)))])
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
    }

    if seqs.storage != Some(target) {
        storage
            .write_batch(vec![(COMMIT_SEQ_STORAGE_KEY, Some(U256::from(target)))])
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
    }

    if seqs.code != Some(target) {
        code.write_batch(vec![(COMMIT_SEQ_CODE_KEY, Some(encode_commit_seq_code(target)))])
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
    }

    Ok(())
}

fn state_root_from_stores(
    accounts: &AccountStore,
    storage: &StorageStore,
    code: &CodeStore,
) -> Result<B256, BackendError> {
    Ok(state_root_from_roots(accounts.root()?, storage.root()?, code.root()?))
}

fn state_root_from_roots(accounts: QmdbDigest, storage: QmdbDigest, code: QmdbDigest) -> B256 {
    StateRoot::compute(
        B256::from_slice(accounts.as_ref()),
        B256::from_slice(storage.as_ref()),
        B256::from_slice(code.as_ref()),
    )
}
