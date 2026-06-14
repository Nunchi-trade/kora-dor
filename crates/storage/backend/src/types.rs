//! Commonware QMDB type aliases and codecs.

use alloy_primitives::U256;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, Write};
use commonware_cryptography::sha256::Sha256 as QmdbHasher;
use commonware_parallel::Sequential;
use commonware_runtime::tokio;
use commonware_storage::{merkle::mmr, qmdb::any, translator::EightCap};
use commonware_utils::sequence::FixedBytes;
use kora_qmdb::AccountEncoding;

use crate::BackendError;

pub(crate) type Context = tokio::Context;
pub(crate) type AccountKey = FixedBytes<20>;
pub(crate) type StorageKey = FixedBytes<60>;
pub(crate) type CodeKey = FixedBytes<32>;

#[derive(Clone, Debug)]
pub(crate) struct AccountValue(pub [u8; AccountEncoding::SIZE]);

impl Write for AccountValue {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0);
    }
}

impl EncodeSize for AccountValue {
    fn encode_size(&self) -> usize {
        AccountEncoding::SIZE
    }
}

impl Read for AccountValue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < AccountEncoding::SIZE {
            return Err(CodecError::EndOfBuffer);
        }
        let mut out = [0u8; AccountEncoding::SIZE];
        buf.copy_to_slice(&mut out);
        Ok(Self(out))
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct StorageValue(pub U256);

impl Write for StorageValue {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.0.to_be_bytes::<32>());
    }
}

impl EncodeSize for StorageValue {
    fn encode_size(&self) -> usize {
        32
    }
}

impl Read for StorageValue {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < 32 {
            return Err(CodecError::EndOfBuffer);
        }
        let mut out = [0u8; 32];
        buf.copy_to_slice(&mut out);
        Ok(Self(U256::from_be_bytes(out)))
    }
}

pub(crate) type AccountDb = any::unordered::variable::Db<
    mmr::Family,
    Context,
    AccountKey,
    AccountValue,
    QmdbHasher,
    EightCap,
    Sequential,
>;
pub(crate) type StorageDb = any::unordered::variable::Db<
    mmr::Family,
    Context,
    StorageKey,
    StorageValue,
    QmdbHasher,
    EightCap,
    Sequential,
>;
pub(crate) type CodeDb = any::unordered::variable::Db<
    mmr::Family,
    Context,
    CodeKey,
    Vec<u8>,
    QmdbHasher,
    EightCap,
    Sequential,
>;
pub(crate) type CodeConfig =
    any::VariableConfig<EightCap, ((), (commonware_codec::RangeCfg<usize>, ())), Sequential>;

pub(crate) struct StoreSlot<T>(Option<T>);

impl<T> StoreSlot<T> {
    pub(crate) const fn new(inner: T) -> Self {
        Self(Some(inner))
    }

    pub(crate) fn get(&self) -> Result<&T, BackendError> {
        self.0.as_ref().ok_or(BackendError::NotInitialized)
    }

    /// Temporarily take ownership via an RAII guard.
    ///
    /// The guard restores the inner value on drop (including on panic/unwind),
    /// preventing the slot from being left permanently empty.
    pub(crate) fn guard(&mut self) -> Result<StoreGuard<'_, T>, BackendError> {
        let inner = self.0.take().ok_or(BackendError::NotInitialized)?;
        Ok(StoreGuard { slot: self, inner: Some(inner) })
    }

    pub(crate) fn into_inner(self) -> Result<T, BackendError> {
        self.0.ok_or(BackendError::NotInitialized)
    }
}

/// RAII guard that restores the inner value to a [`StoreSlot`] on drop.
///
/// This prevents the slot from being left in a permanent `None` state if a
/// panic occurs between take and restore during batch writes.
pub(crate) struct StoreGuard<'a, T> {
    slot: &'a mut StoreSlot<T>,
    inner: Option<T>,
}

impl<T> StoreGuard<'_, T> {
    #[allow(clippy::missing_const_for_fn)] // expect() is not const-stable
    pub(crate) fn as_ref(&self) -> &T {
        self.inner.as_ref().expect("StoreGuard inner is always Some while guard is live")
    }

    #[allow(clippy::missing_const_for_fn)] // expect() is not const-stable
    pub(crate) fn as_mut(&mut self) -> &mut T {
        self.inner.as_mut().expect("StoreGuard inner is always Some while guard is live")
    }
}

impl<T> Drop for StoreGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            self.slot.0 = Some(inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt, Encode};

    use super::*;

    #[test]
    fn test_account_value_roundtrip() {
        let mut data = [0u8; AccountEncoding::SIZE];
        data[0] = 0x42;
        data[79] = 0xFF;
        let value = AccountValue(data);

        let encoded = value.encode();
        let decoded = AccountValue::decode(encoded).unwrap();
        assert_eq!(decoded.0, data);
    }

    #[test]
    fn test_account_value_encode_size() {
        let value = AccountValue([0u8; AccountEncoding::SIZE]);
        assert_eq!(value.encode_size(), AccountEncoding::SIZE);
    }

    #[test]
    fn test_storage_value_roundtrip() {
        let value = StorageValue(U256::from(12345678u64));
        let encoded = value.encode();
        let decoded = StorageValue::decode(encoded).unwrap();
        assert_eq!(decoded.0, value.0);
    }

    #[test]
    fn test_storage_value_max() {
        let value = StorageValue(U256::MAX);
        let encoded = value.encode();
        let decoded = StorageValue::decode(encoded).unwrap();
        assert_eq!(decoded.0, U256::MAX);
    }

    #[test]
    fn test_storage_value_encode_size() {
        let value = StorageValue(U256::ZERO);
        assert_eq!(value.encode_size(), 32);
    }

    #[test]
    fn test_store_slot_get_succeeds() {
        let slot = StoreSlot::new(42);
        assert_eq!(*slot.get().unwrap(), 42);
    }

    #[test]
    fn test_store_slot_guard_borrows_value() {
        let mut slot = StoreSlot::new(42);
        {
            let guard = slot.guard().unwrap();
            assert_eq!(*guard.as_ref(), 42);
        }
        // Value is restored after guard is dropped.
        assert_eq!(*slot.get().unwrap(), 42);
    }

    #[test]
    fn test_store_slot_guard_restores_on_drop() {
        let mut slot = StoreSlot::new(42);
        {
            let mut guard = slot.guard().unwrap();
            *guard.as_mut() = 100;
        }
        assert_eq!(*slot.get().unwrap(), 100);
    }

    #[test]
    fn test_store_slot_guard_twice_fails() {
        let mut slot = StoreSlot::new(42);
        let _guard = slot.guard().unwrap();
        // Cannot call guard again while the first guard is live (borrow checker prevents this).
    }

    #[test]
    fn test_store_slot_into_inner_succeeds() {
        let slot = StoreSlot::new(42);
        assert_eq!(slot.into_inner().unwrap(), 42);
    }

    #[test]
    fn test_store_slot_into_inner_after_guard_succeeds() {
        let mut slot = StoreSlot::new(42);
        {
            let _guard = slot.guard().unwrap();
            // Guard restores value on drop
        }
        assert_eq!(slot.into_inner().unwrap(), 42);
    }
}
