//! Account store bindings for commonware-storage.

use alloy_primitives::Address;
use commonware_cryptography::sha256::Digest as QmdbDigest;
use commonware_parallel::Sequential;
use commonware_storage::{qmdb::any::VariableConfig, translator::EightCap};
use kora_qmdb::{AccountEncoding, QmdbBatchable, QmdbGettable};

use crate::{
    BackendError,
    types::{AccountDb, AccountKey, AccountValue, Context, StoreSlot},
};

/// Account partition backed by commonware-storage.
///
/// Stores account state including nonce, balance, code hash, and generation number.
/// Each account is keyed by its 20-byte address and encoded as a fixed 80-byte value
/// using [`AccountEncoding`](kora_qmdb::AccountEncoding).
///
/// Implements [`QmdbGettable`] for reads and [`QmdbBatchable`] for batch writes.
/// All writes are atomic and update the authenticated Merkle root.
pub struct AccountStore {
    inner: StoreSlot<AccountDb>,
}

pub(crate) struct AccountStoreDirty {
    inner: AccountDb,
}

impl AccountStore {
    /// Initialize the account store.
    pub async fn init(
        context: Context,
        config: VariableConfig<EightCap, ((), ()), Sequential>,
    ) -> Result<Self, BackendError> {
        let inner = AccountDb::init(context, config)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(Self { inner: StoreSlot::new(inner) })
    }

    /// Return the current authenticated root for the account partition.
    pub fn root(&self) -> Result<QmdbDigest, BackendError> {
        Ok(self.inner.get()?.root())
    }

    pub(crate) fn into_dirty(self) -> Result<AccountStoreDirty, BackendError> {
        Ok(AccountStoreDirty { inner: self.inner.into_inner()? })
    }
}

impl AccountStoreDirty {
    pub(crate) fn root(self) -> QmdbDigest {
        self.inner.root()
    }
}

impl std::fmt::Debug for AccountStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountStore").finish_non_exhaustive()
    }
}

/// Error type for account store operations.
pub type AccountStoreError = BackendError;

const fn account_key(address: Address) -> AccountKey {
    AccountKey::new(address.into_array())
}

impl QmdbGettable for AccountStore {
    type Key = Address;
    type Value = [u8; AccountEncoding::SIZE];
    type Error = AccountStoreError;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        let record = self
            .inner
            .get()?
            .get(&account_key(*key))
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(record.map(|value| value.0))
    }
}

impl QmdbBatchable for AccountStore {
    async fn write_batch<I>(&mut self, ops: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Self::Key, Option<Self::Value>)> + Send,
        I::IntoIter: Send,
    {
        let mut guard = self.inner.guard()?;
        let mut batch = guard.as_ref().new_batch();
        for (address, value) in ops {
            batch = batch.write(account_key(address), value.map(AccountValue));
        }
        let merkleized = batch
            .merkleize(guard.as_ref(), None)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        guard
            .as_mut()
            .apply_batch(merkleized)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        guard.as_ref().commit().await.map_err(|e| BackendError::Storage(e.to_string()))?;
        guard.as_ref().sync().await.map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(())
    }
}

impl QmdbGettable for AccountStoreDirty {
    type Key = Address;
    type Value = [u8; AccountEncoding::SIZE];
    type Error = AccountStoreError;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        let record = self
            .inner
            .get(&account_key(*key))
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(record.map(|value| value.0))
    }
}

impl QmdbBatchable for AccountStoreDirty {
    async fn write_batch<I>(&mut self, ops: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = (Self::Key, Option<Self::Value>)> + Send,
        I::IntoIter: Send,
    {
        let mut batch = self.inner.new_batch();
        for (address, value) in ops {
            batch = batch.write(account_key(address), value.map(AccountValue));
        }
        let merkleized = batch
            .merkleize(&self.inner, None)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        self.inner
            .apply_batch(merkleized)
            .await
            .map(|_| ())
            .map_err(|e| BackendError::Storage(e.to_string()))
    }
}
