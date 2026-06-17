use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, B256, Bytes, U256};
use kora_qmdb::ChangeSet;
use kora_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};

/// State overlay that layers pending changes on top of a base state database.
///
/// Bytecode is deduplicated in an internal `code_by_hash` index keyed by code
/// hash.  This gives O(1) code lookups (instead of the previous O(N) linear
/// scan) and ensures that identical bytecodes deployed by different accounts
/// are stored only once.
///
/// The overlay changeset is stored with code bytes stripped out of individual
/// [`AccountUpdate`]s -- the authoritative copy lives in the code index.
/// This makes cloning the changeset (needed during `commit` / `compute_root`)
/// significantly cheaper because bytecode (often many KB) is no longer
/// deep-copied per account.
#[derive(Clone, Debug)]
pub struct OverlayState<S> {
    base: S,
    /// Account-level changes **without** inline code bytes.  Code is stored
    /// separately in `code_by_hash`.
    changes: Arc<ChangeSet>,
    /// Deduplicated code index: code_hash -> bytecode.
    ///
    /// `Bytes` is internally reference-counted, so cloning this map is cheap.
    code_by_hash: Arc<HashMap<B256, Bytes>>,
}

/// Build the deduplicated code index from a [`ChangeSet`], stripping the
/// `code` field from each [`AccountUpdate`] in the process.
fn build_code_index(changes: &mut ChangeSet) -> HashMap<B256, Bytes> {
    let mut index = HashMap::new();
    for update in changes.accounts.values_mut() {
        if let Some(code) = update.code.take() {
            // Only insert if we haven't seen this code hash yet -- this is
            // where deduplication happens (issue #144).
            index.entry(update.code_hash).or_insert_with(|| Bytes::from(code));
        }
    }
    index
}

/// Re-attach code bytes from the code index into the changeset's account
/// updates so downstream consumers (e.g. the base `StateDbWrite`) see the
/// full data.
fn reattach_code(changes: &mut ChangeSet, code_index: &HashMap<B256, Bytes>) {
    for update in changes.accounts.values_mut() {
        if update.code.is_none()
            && let Some(bytes) = code_index.get(&update.code_hash)
        {
            update.code = Some(bytes.to_vec());
        }
    }
}

/// Merge the overlay changeset with incoming changes, building a combined
/// code index along the way.
fn merge_and_reattach(
    overlay: &ChangeSet,
    overlay_code: &HashMap<B256, Bytes>,
    mut incoming: ChangeSet,
) -> ChangeSet {
    // Collect code from the incoming changeset into a temporary index.
    let incoming_code = build_code_index(&mut incoming);

    // Clone the overlay changeset -- this is cheap now since code bytes have
    // been stripped out.
    let mut merged = overlay.clone();
    merged.merge(incoming);

    // Build a combined code index (overlay code + incoming code).
    let mut combined_code = overlay_code.clone();
    for (hash, bytes) in &incoming_code {
        combined_code.entry(*hash).or_insert_with(|| bytes.clone());
    }

    // Reattach code into the merged changeset for the downstream base layer.
    reattach_code(&mut merged, &combined_code);
    merged
}

impl<S> OverlayState<S> {
    /// Create a new overlay from a base state and a change set.
    ///
    /// Bytecodes are extracted from the changeset into a deduplicated index
    /// keyed by code hash, and the `code` field on individual account updates
    /// is cleared.
    #[must_use]
    pub fn new(base: S, mut changes: ChangeSet) -> Self {
        let code_by_hash = build_code_index(&mut changes);
        Self { base, changes: Arc::new(changes), code_by_hash: Arc::new(code_by_hash) }
    }

    /// Return the number of accounts in the overlay change set.
    #[must_use]
    pub fn change_len(&self) -> usize {
        self.changes.len()
    }

    /// Return whether the overlay change set is empty.
    #[must_use]
    pub fn changes_is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Merge the current overlay changes with a newer change set.
    ///
    /// The returned changeset has code bytes attached to every account that
    /// deployed code.
    pub fn merge_changes(&self, newer: ChangeSet) -> ChangeSet {
        if self.changes.is_empty() {
            return newer;
        }
        merge_and_reattach(&self.changes, &self.code_by_hash, newer)
    }
}

impl<S: Clone> OverlayState<S> {
    /// Return a clone of the base state handle.
    pub fn base(&self) -> S {
        self.base.clone()
    }
}

impl<S: StateDbRead> StateDbRead for OverlayState<S> {
    fn nonce(
        &self,
        address: &Address,
    ) -> impl std::future::Future<Output = Result<u64, StateDbError>> + Send {
        let address = *address;
        let base = self.base.clone();
        let changes = Arc::clone(&self.changes);
        async move {
            if let Some(update) = changes.accounts.get(&address) {
                return Ok(update.nonce);
            }
            base.nonce(&address).await
        }
    }

    fn balance(
        &self,
        address: &Address,
    ) -> impl std::future::Future<Output = Result<U256, StateDbError>> + Send {
        let address = *address;
        let base = self.base.clone();
        let changes = Arc::clone(&self.changes);
        async move {
            if let Some(update) = changes.accounts.get(&address) {
                return Ok(update.balance);
            }
            base.balance(&address).await
        }
    }

    fn code_hash(
        &self,
        address: &Address,
    ) -> impl std::future::Future<Output = Result<B256, StateDbError>> + Send {
        let address = *address;
        let base = self.base.clone();
        let changes = Arc::clone(&self.changes);
        async move {
            if let Some(update) = changes.accounts.get(&address) {
                return Ok(update.code_hash);
            }
            base.code_hash(&address).await
        }
    }

    /// O(1) code lookup via the deduplicated `code_by_hash` index.
    ///
    /// Previously this was an O(N) linear scan over every changed account.
    fn code(
        &self,
        code_hash: &B256,
    ) -> impl std::future::Future<Output = Result<Bytes, StateDbError>> + Send {
        let code_hash = *code_hash;
        let base = self.base.clone();
        let code_index = Arc::clone(&self.code_by_hash);
        async move {
            // O(1) HashMap lookup instead of O(N) linear scan.
            if let Some(code) = code_index.get(&code_hash) {
                return Ok(code.clone()); // Bytes::clone is Arc-increment, not a copy.
            }
            base.code(&code_hash).await
        }
    }

    fn storage(
        &self,
        address: &Address,
        slot: &U256,
    ) -> impl std::future::Future<Output = Result<U256, StateDbError>> + Send {
        let address = *address;
        let slot = *slot;
        let base = self.base.clone();
        let changes = Arc::clone(&self.changes);
        async move {
            if let Some(update) = changes.accounts.get(&address) {
                if update.selfdestructed {
                    return Ok(U256::ZERO);
                }
                if let Some(value) = update.storage.get(&slot) {
                    return Ok(*value);
                }
                if update.created {
                    return Ok(U256::ZERO);
                }
            }
            base.storage(&address, &slot).await
        }
    }
}

impl<S: StateDbWrite> StateDbWrite for OverlayState<S> {
    fn commit(
        &self,
        changes: ChangeSet,
    ) -> impl std::future::Future<Output = Result<B256, StateDbError>> + Send {
        let base = self.base.clone();
        let overlay = Arc::clone(&self.changes);
        let overlay_code = Arc::clone(&self.code_by_hash);
        async move {
            // Fast path: if overlay is empty, skip cloning entirely.
            if overlay.is_empty() {
                return base.commit(changes).await;
            }
            // Fast path: if incoming changes are empty, reattach code and
            // commit the overlay as-is.
            if changes.is_empty() {
                let mut overlay_owned = (*overlay).clone();
                reattach_code(&mut overlay_owned, &overlay_code);
                return base.commit(overlay_owned).await;
            }
            let merged = merge_and_reattach(&overlay, &overlay_code, changes);
            base.commit(merged).await
        }
    }

    fn compute_root(
        &self,
        changes: &ChangeSet,
    ) -> impl std::future::Future<Output = Result<B256, StateDbError>> + Send {
        let base = self.base.clone();
        let overlay = Arc::clone(&self.changes);
        let overlay_code = Arc::clone(&self.code_by_hash);
        let changes = changes.clone();
        async move {
            // Fast path: if overlay is empty, pass incoming changes directly.
            if overlay.is_empty() {
                return base.compute_root(&changes).await;
            }
            // Fast path: if incoming changes are empty, reattach code to
            // overlay and compute root without merging.
            if changes.is_empty() {
                let mut overlay_owned = (*overlay).clone();
                reattach_code(&mut overlay_owned, &overlay_code);
                return base.compute_root(&overlay_owned).await;
            }
            let merged = merge_and_reattach(&overlay, &overlay_code, changes);
            base.compute_root(&merged).await
        }
    }

    fn merge_changes(&self, older: ChangeSet, newer: ChangeSet) -> ChangeSet {
        self.base.merge_changes(older, newer)
    }
}

impl<S: StateDb> StateDb for OverlayState<S> {
    fn state_root(&self) -> impl std::future::Future<Output = Result<B256, StateDbError>> + Send {
        let base = self.base.clone();
        async move { base.state_root().await }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use kora_qmdb::AccountUpdate;

    use super::*;

    #[derive(Clone, Debug)]
    struct MockStateDb {
        accounts: BTreeMap<Address, AccountUpdate>,
    }

    impl MockStateDb {
        fn new() -> Self {
            Self { accounts: BTreeMap::new() }
        }

        fn with_account(mut self, address: Address, update: AccountUpdate) -> Self {
            self.accounts.insert(address, update);
            self
        }
    }

    impl StateDbRead for MockStateDb {
        fn nonce(
            &self,
            address: &Address,
        ) -> impl std::future::Future<Output = Result<u64, StateDbError>> + Send {
            let nonce = self.accounts.get(address).map(|a| a.nonce).unwrap_or(0);
            async move { Ok(nonce) }
        }

        fn balance(
            &self,
            address: &Address,
        ) -> impl std::future::Future<Output = Result<U256, StateDbError>> + Send {
            let balance = self.accounts.get(address).map(|a| a.balance).unwrap_or(U256::ZERO);
            async move { Ok(balance) }
        }

        fn code_hash(
            &self,
            address: &Address,
        ) -> impl std::future::Future<Output = Result<B256, StateDbError>> + Send {
            let hash = self.accounts.get(address).map(|a| a.code_hash).unwrap_or(B256::ZERO);
            async move { Ok(hash) }
        }

        fn code(
            &self,
            code_hash: &B256,
        ) -> impl std::future::Future<Output = Result<Bytes, StateDbError>> + Send {
            let code_hash = *code_hash;
            let code = self
                .accounts
                .values()
                .find(|a| a.code_hash == code_hash)
                .and_then(|a| a.code.clone())
                .map(Bytes::from)
                .unwrap_or_default();
            async move { Ok(code) }
        }

        fn storage(
            &self,
            address: &Address,
            slot: &U256,
        ) -> impl std::future::Future<Output = Result<U256, StateDbError>> + Send {
            let value = self
                .accounts
                .get(address)
                .and_then(|a| a.storage.get(slot).copied())
                .unwrap_or(U256::ZERO);
            async move { Ok(value) }
        }
    }

    fn test_account(nonce: u64, balance: u64) -> AccountUpdate {
        AccountUpdate {
            created: false,
            selfdestructed: false,
            nonce,
            balance: U256::from(balance),
            code_hash: B256::ZERO,
            code: None,
            storage: BTreeMap::new(),
        }
    }

    fn test_account_with_storage(
        nonce: u64,
        balance: u64,
        slot: U256,
        value: U256,
    ) -> AccountUpdate {
        let mut storage = BTreeMap::new();
        storage.insert(slot, value);
        AccountUpdate {
            created: false,
            selfdestructed: false,
            nonce,
            balance: U256::from(balance),
            code_hash: B256::ZERO,
            code: None,
            storage,
        }
    }

    #[tokio::test]
    async fn test_overlay_returns_base_when_no_changes() {
        let addr = Address::repeat_byte(0x01);
        let base = MockStateDb::new().with_account(addr, test_account(5, 1000));
        let overlay = OverlayState::new(base, ChangeSet::new());

        assert_eq!(overlay.nonce(&addr).await.unwrap(), 5);
        assert_eq!(overlay.balance(&addr).await.unwrap(), U256::from(1000));
    }

    #[tokio::test]
    async fn test_overlay_returns_changes_over_base() {
        let addr = Address::repeat_byte(0x01);
        let base = MockStateDb::new().with_account(addr, test_account(5, 1000));

        let mut changes = ChangeSet::new();
        changes.accounts.insert(addr, test_account(10, 2000));

        let overlay = OverlayState::new(base, changes);

        assert_eq!(overlay.nonce(&addr).await.unwrap(), 10);
        assert_eq!(overlay.balance(&addr).await.unwrap(), U256::from(2000));
    }

    #[tokio::test]
    async fn test_overlay_storage_from_changes() {
        let addr = Address::repeat_byte(0x02);
        let slot = U256::from(42);
        let value = U256::from(999);

        let base = MockStateDb::new();
        let mut changes = ChangeSet::new();
        changes.accounts.insert(addr, test_account_with_storage(1, 100, slot, value));

        let overlay = OverlayState::new(base, changes);

        assert_eq!(overlay.storage(&addr, &slot).await.unwrap(), value);
    }

    #[tokio::test]
    async fn test_overlay_storage_falls_back_to_base() {
        let addr = Address::repeat_byte(0x03);
        let slot = U256::from(10);
        let value = U256::from(555);

        let base =
            MockStateDb::new().with_account(addr, test_account_with_storage(1, 100, slot, value));
        let overlay = OverlayState::new(base, ChangeSet::new());

        assert_eq!(overlay.storage(&addr, &slot).await.unwrap(), value);
    }

    #[tokio::test]
    async fn test_overlay_selfdestructed_returns_zero_storage() {
        let addr = Address::repeat_byte(0x04);
        let slot = U256::from(1);

        let base = MockStateDb::new()
            .with_account(addr, test_account_with_storage(1, 100, slot, U256::from(777)));

        let mut changes = ChangeSet::new();
        changes.accounts.insert(
            addr,
            AccountUpdate {
                created: false,
                selfdestructed: true,
                nonce: 0,
                balance: U256::ZERO,
                code_hash: B256::ZERO,
                code: None,
                storage: BTreeMap::new(),
            },
        );

        let overlay = OverlayState::new(base, changes);

        assert_eq!(overlay.storage(&addr, &slot).await.unwrap(), U256::ZERO);
    }

    #[tokio::test]
    async fn test_overlay_created_account_returns_zero_for_missing_storage() {
        let addr = Address::repeat_byte(0x05);
        let slot = U256::from(99);

        let base = MockStateDb::new()
            .with_account(addr, test_account_with_storage(1, 100, slot, U256::from(123)));

        let mut changes = ChangeSet::new();
        changes.accounts.insert(
            addr,
            AccountUpdate {
                created: true,
                selfdestructed: false,
                nonce: 0,
                balance: U256::ZERO,
                code_hash: B256::ZERO,
                code: None,
                storage: BTreeMap::new(),
            },
        );

        let overlay = OverlayState::new(base, changes);

        assert_eq!(overlay.storage(&addr, &slot).await.unwrap(), U256::ZERO);
    }

    #[test]
    fn test_merge_changes_combines_changesets() {
        let addr1 = Address::repeat_byte(0x01);
        let addr2 = Address::repeat_byte(0x02);

        let mut cs1 = ChangeSet::new();
        cs1.accounts.insert(addr1, test_account(1, 100));

        let mut cs2 = ChangeSet::new();
        cs2.accounts.insert(addr2, test_account(2, 200));

        let base = MockStateDb::new();
        let overlay = OverlayState::new(base, cs1);
        let merged = overlay.merge_changes(cs2);

        assert!(merged.accounts.contains_key(&addr1));
        assert!(merged.accounts.contains_key(&addr2));
    }

    #[test]
    fn test_base_accessor() {
        let base = MockStateDb::new();
        let overlay = OverlayState::new(base, ChangeSet::new());
        let _ = overlay.base();
    }

    #[test]
    fn test_changes_is_empty_and_change_len() {
        let addr = Address::repeat_byte(0x0A);
        let base = MockStateDb::new();

        let empty_overlay = OverlayState::new(base.clone(), ChangeSet::new());
        assert!(empty_overlay.changes_is_empty());
        assert_eq!(empty_overlay.change_len(), 0);

        let mut changes = ChangeSet::new();
        changes.accounts.insert(addr, test_account(1, 100));
        let non_empty_overlay = OverlayState::new(base, changes);
        assert!(!non_empty_overlay.changes_is_empty());
        assert_eq!(non_empty_overlay.change_len(), 1);
    }

    #[tokio::test]
    async fn test_overlay_code_hash_from_changes() {
        let addr = Address::repeat_byte(0x06);
        let code_hash = B256::repeat_byte(0xAB);

        let base = MockStateDb::new();
        let mut changes = ChangeSet::new();
        changes.accounts.insert(
            addr,
            AccountUpdate {
                created: true,
                selfdestructed: false,
                nonce: 1,
                balance: U256::from(500),
                code_hash,
                code: Some(vec![0x60, 0x00]),
                storage: BTreeMap::new(),
            },
        );

        let overlay = OverlayState::new(base, changes);

        assert_eq!(overlay.code_hash(&addr).await.unwrap(), code_hash);
    }

    #[tokio::test]
    async fn test_overlay_code_hash_falls_back_to_base() {
        let addr = Address::repeat_byte(0x07);
        let code_hash = B256::repeat_byte(0xCD);

        let base = MockStateDb::new().with_account(
            addr,
            AccountUpdate {
                created: false,
                selfdestructed: false,
                nonce: 0,
                balance: U256::ZERO,
                code_hash,
                code: None,
                storage: BTreeMap::new(),
            },
        );
        let overlay = OverlayState::new(base, ChangeSet::new());

        assert_eq!(overlay.code_hash(&addr).await.unwrap(), code_hash);
    }

    #[tokio::test]
    async fn test_overlay_code_from_changes() {
        let addr = Address::repeat_byte(0x08);
        let code_hash = B256::repeat_byte(0xEF);
        let code_bytes = vec![0x60, 0x00, 0x60, 0x00];

        let base = MockStateDb::new();
        let mut changes = ChangeSet::new();
        changes.accounts.insert(
            addr,
            AccountUpdate {
                created: true,
                selfdestructed: false,
                nonce: 1,
                balance: U256::from(100),
                code_hash,
                code: Some(code_bytes.clone()),
                storage: BTreeMap::new(),
            },
        );

        let overlay = OverlayState::new(base, changes);

        assert_eq!(overlay.code(&code_hash).await.unwrap(), Bytes::from(code_bytes));
    }

    #[tokio::test]
    async fn test_overlay_code_falls_back_to_base() {
        let addr = Address::repeat_byte(0x09);
        let code_hash = B256::repeat_byte(0x12);
        let code_bytes = vec![0x61, 0x02, 0x03];

        let base = MockStateDb::new().with_account(
            addr,
            AccountUpdate {
                created: false,
                selfdestructed: false,
                nonce: 0,
                balance: U256::ZERO,
                code_hash,
                code: Some(code_bytes.clone()),
                storage: BTreeMap::new(),
            },
        );
        let overlay = OverlayState::new(base, ChangeSet::new());

        assert_eq!(overlay.code(&code_hash).await.unwrap(), Bytes::from(code_bytes));
    }

    #[tokio::test]
    async fn test_overlay_code_returns_empty_for_unknown_hash() {
        let base = MockStateDb::new();
        let overlay = OverlayState::new(base, ChangeSet::new());
        let unknown_hash = B256::repeat_byte(0xFF);

        assert_eq!(overlay.code(&unknown_hash).await.unwrap(), Bytes::new());
    }

    // --- New tests for the three performance fixes ---

    #[tokio::test]
    async fn test_code_deduplication_across_accounts() {
        // Two accounts deploying identical bytecode should result in a single
        // entry in the code index (issue #144).
        let addr1 = Address::repeat_byte(0x10);
        let addr2 = Address::repeat_byte(0x11);
        let code_hash = B256::repeat_byte(0xDE);
        let code_bytes = vec![0x60, 0x00, 0x60, 0x00, 0xFD];

        let base = MockStateDb::new();
        let mut changes = ChangeSet::new();
        changes.accounts.insert(
            addr1,
            AccountUpdate {
                created: true,
                selfdestructed: false,
                nonce: 1,
                balance: U256::ZERO,
                code_hash,
                code: Some(code_bytes.clone()),
                storage: BTreeMap::new(),
            },
        );
        changes.accounts.insert(
            addr2,
            AccountUpdate {
                created: true,
                selfdestructed: false,
                nonce: 1,
                balance: U256::ZERO,
                code_hash,
                code: Some(code_bytes.clone()),
                storage: BTreeMap::new(),
            },
        );

        let overlay = OverlayState::new(base, changes);

        // Code index should have exactly one entry for this hash.
        assert_eq!(overlay.code_by_hash.len(), 1);

        // Both accounts should resolve to the same bytecode via the index.
        assert_eq!(overlay.code(&code_hash).await.unwrap(), Bytes::from(code_bytes));
    }

    #[test]
    fn test_code_stripped_from_changeset_accounts() {
        // After construction, account updates in the changeset should have
        // their code field set to None (moved into the code index).
        let addr = Address::repeat_byte(0x20);
        let code_hash = B256::repeat_byte(0xAA);

        let mut changes = ChangeSet::new();
        changes.accounts.insert(
            addr,
            AccountUpdate {
                created: true,
                selfdestructed: false,
                nonce: 1,
                balance: U256::ZERO,
                code_hash,
                code: Some(vec![0x60, 0x00]),
                storage: BTreeMap::new(),
            },
        );

        let overlay = OverlayState::new(MockStateDb::new(), changes);

        // Code should be stripped from the account update.
        assert!(overlay.changes.accounts.get(&addr).unwrap().code.is_none());
        // But present in the code index.
        assert!(overlay.code_by_hash.contains_key(&code_hash));
    }

    #[test]
    fn test_merge_changes_reattaches_code() {
        // merge_changes should produce a ChangeSet with code bytes reattached
        // from the code index.
        let addr = Address::repeat_byte(0x30);
        let code_hash = B256::repeat_byte(0xBB);
        let code_bytes = vec![0x60, 0x01];

        let mut changes = ChangeSet::new();
        changes.accounts.insert(
            addr,
            AccountUpdate {
                created: true,
                selfdestructed: false,
                nonce: 1,
                balance: U256::ZERO,
                code_hash,
                code: Some(code_bytes.clone()),
                storage: BTreeMap::new(),
            },
        );

        let overlay = OverlayState::new(MockStateDb::new(), changes);
        let merged = overlay.merge_changes(ChangeSet::new());

        // The merged changeset should have code bytes reattached.
        let update = merged.accounts.get(&addr).unwrap();
        assert_eq!(update.code.as_deref(), Some(code_bytes.as_slice()));
    }

    #[test]
    fn test_merge_changes_empty_overlay_returns_newer() {
        // When the overlay is empty, merge_changes should return the newer
        // changeset directly without cloning (fast path for issue #039).
        let addr = Address::repeat_byte(0x40);
        let mut newer = ChangeSet::new();
        newer.accounts.insert(addr, test_account(5, 500));

        let overlay = OverlayState::new(MockStateDb::new(), ChangeSet::new());
        let merged = overlay.merge_changes(newer);

        assert!(merged.accounts.contains_key(&addr));
        assert_eq!(merged.accounts.get(&addr).unwrap().nonce, 5);
    }
}
