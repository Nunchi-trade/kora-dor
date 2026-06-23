use std::sync::Arc;

use alloy_primitives::{Address, U256};
use commonware_runtime::{Supervisor as _, tokio::Context};
use kora_backend::{
    AccountStore, CodeStore, CommonwareBackend, CommonwareRootProvider, QmdbBackendConfig,
    StorageStore,
};
use kora_domain::StateRoot;
use kora_handlers::{HandleError, QmdbHandle, QmdbRefDb as HandlerQmdbRefDb};
use kora_traits::{StateDb, StateDbWrite};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

/// QMDB configuration for the backend.
pub type QmdbConfig = QmdbBackendConfig;
/// QMDB change set type.
pub type QmdbChangeSet = kora_qmdb::ChangeSet;
/// QMDB handle type used as a state database.
pub type QmdbState = QmdbHandle<AccountStore, StorageStore, CodeStore>;
/// Tokio-backed REVM database wrapper for QMDB handles.
pub type QmdbRefDb = HandlerQmdbRefDb<AccountStore, StorageStore, CodeStore>;

type Handle = QmdbState;

/// QMDB ledger service backed by kora storage crates.
#[derive(Clone, Debug)]
pub struct QmdbLedger {
    handle: Handle,
}

/// Errors for QMDB ledger operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Backend error while opening QMDB storage.
    #[error("backend error: {0}")]
    Backend(#[from] kora_backend::BackendError),
    /// Handler error while applying state changes.
    #[error("handler error: {0}")]
    Handler(#[from] HandleError),
    /// State database error while computing or committing roots.
    #[error("state db error: {0}")]
    StateDb(#[from] kora_traits::StateDbError),
    /// Missing Tokio runtime needed for sync REVM database access.
    #[error("missing tokio runtime for async db bridge")]
    MissingRuntime,
}

impl QmdbLedger {
    /// Initializes the QMDB partitions and populates the genesis allocation.
    pub async fn init(
        context: Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
    ) -> Result<Self, Error> {
        Self::init_with_genesis(context, config, genesis_alloc, true).await
    }

    /// Initializes the QMDB partitions, optionally applying the genesis allocation.
    ///
    /// Runs a cross-partition consistency check before proceeding. If the
    /// partitions have mismatched commit sequences (indicating a partial commit
    /// from a previous crash), initialization will fail with an error.
    pub async fn init_with_genesis(
        context: Context,
        config: QmdbConfig,
        genesis_alloc: Vec<(Address, U256)>,
        apply_genesis: bool,
    ) -> Result<Self, Error> {
        let backend = CommonwareBackend::open(context.child("backend"), config.clone()).await?;

        // Verify cross-partition consistency before consuming the backend.
        let seqs = backend.verify_partition_consistency().await?;
        let starting_seq = seqs.accounts.unwrap_or(0);
        info!(commit_seq = starting_seq, "QMDB partition consistency verified");

        let root_provider = CommonwareRootProvider::new(context.child("root_provider"), config);
        let (accounts, storage, code) = backend.into_stores();

        // Create a QmdbStore with the persisted commit sequence so that
        // subsequent commits continue the monotonic sequence.
        let mut store = kora_qmdb::QmdbStore::new(accounts, storage, code);
        store.set_commit_seq(starting_seq);
        let handle =
            Handle::from_store(store).with_root_provider(Arc::new(RwLock::new(root_provider)));

        if apply_genesis && starting_seq == 0 {
            handle.init_genesis(genesis_alloc).await?;
        }
        Ok(Self { handle })
    }

    /// Exposes a synchronous REVM database view backed by QMDB.
    pub fn database(&self) -> Result<QmdbRefDb, Error> {
        QmdbRefDb::new(self.handle.clone()).ok_or(Error::MissingRuntime)
    }

    /// Exposes the async state handle used by the block executor.
    pub fn state(&self) -> QmdbState {
        self.handle.clone()
    }

    /// Computes the root for a change set without committing.
    pub async fn compute_root(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        let root = StateDbWrite::compute_root(&self.handle, &changes).await?;
        Ok(StateRoot(root))
    }

    /// Commits the provided changes to QMDB and returns the resulting root.
    ///
    /// Delegates to [`StateDbWrite::commit`] on the underlying handle so there
    /// is exactly one code path that acquires the storage-access mutex and the
    /// store write lock.
    pub async fn commit_changes(&self, changes: QmdbChangeSet) -> Result<StateRoot, Error> {
        let root = StateDbWrite::commit(&self.handle, changes).await?;
        Ok(StateRoot(root))
    }

    /// Returns the current authenticated root stored in QMDB.
    pub async fn root(&self) -> Result<StateRoot, Error> {
        let root = StateDb::state_root(&self.handle).await?;
        Ok(StateRoot(root))
    }
}
