//! In-memory snapshot store implementation.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};

use kora_qmdb::ChangeSet;
use kora_traits::StateDb;
use parking_lot::RwLock;
use tracing::debug;

use crate::{
    ConsensusError,
    traits::{Digest, Snapshot, SnapshotStore},
};

/// Default maximum number of persisted snapshots to retain in memory.
///
/// Once more than this many snapshots have been persisted, the oldest are
/// evicted from the in-memory store. The `persisted` marker is kept so that
/// ancestor chain-walking terminates correctly, but the heavy snapshot data
/// (state overlay, change set, tx IDs) is freed.
const DEFAULT_MAX_PERSISTED_RETAINED: usize = 256;

/// In-memory snapshot store with bounded retention of persisted snapshots.
///
/// Snapshots that have been persisted to the underlying state database are
/// evicted (oldest-first) once the number of retained persisted entries
/// exceeds `max_persisted_retained`. This prevents unbounded memory growth
/// on long-running nodes.
#[derive(Debug)]
pub struct InMemorySnapshotStore<S> {
    snapshots: Arc<RwLock<BTreeMap<Digest, Snapshot<S>>>>,
    persisted: Arc<RwLock<BTreeSet<Digest>>>,
    persisting: Arc<RwLock<BTreeSet<Digest>>>,
    /// Insertion-ordered queue of persisted digests, used for oldest-first eviction.
    persisted_order: Arc<RwLock<VecDeque<Digest>>>,
    /// Maximum number of persisted snapshots to retain in memory.
    max_persisted_retained: usize,
}

impl<S> Clone for InMemorySnapshotStore<S> {
    fn clone(&self) -> Self {
        Self {
            snapshots: Arc::clone(&self.snapshots),
            persisted: Arc::clone(&self.persisted),
            persisting: Arc::clone(&self.persisting),
            persisted_order: Arc::clone(&self.persisted_order),
            max_persisted_retained: self.max_persisted_retained,
        }
    }
}

impl<S> InMemorySnapshotStore<S> {
    /// Create a new empty snapshot store with the default retention limit.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_persisted_retained(DEFAULT_MAX_PERSISTED_RETAINED)
    }

    /// Create a new empty snapshot store that retains at most
    /// `max_persisted_retained` persisted snapshots in memory.
    #[must_use]
    pub fn with_max_persisted_retained(max_persisted_retained: usize) -> Self {
        Self {
            snapshots: Arc::new(RwLock::new(BTreeMap::new())),
            persisted: Arc::new(RwLock::new(BTreeSet::new())),
            persisting: Arc::new(RwLock::new(BTreeSet::new())),
            persisted_order: Arc::new(RwLock::new(VecDeque::new())),
            max_persisted_retained,
        }
    }

    /// Return the number of snapshots currently held in memory.
    pub fn len(&self) -> usize {
        self.snapshots.read().len()
    }

    /// Return true if the store contains no snapshots.
    pub fn is_empty(&self) -> bool {
        self.snapshots.read().is_empty()
    }

    /// Return the number of digests currently marked as persisted.
    pub fn persisted_count(&self) -> usize {
        self.persisted.read().len()
    }

    /// Return the number of snapshots that have not yet been persisted.
    ///
    /// This is the count of entries in the snapshot map whose digest is not
    /// in the persisted set.  A rising value under steady-state operation
    /// indicates the persistence pipeline is falling behind block production.
    ///
    /// Lock ordering: `persisted(R)` -> `snapshots(R)`.
    pub fn unpersisted_count(&self) -> usize {
        let persisted = self.persisted.read();
        let snapshots = self.snapshots.read();
        snapshots.keys().filter(|d| !persisted.contains(d)).count()
    }
}

impl<S> InMemorySnapshotStore<S> {
    /// Returns true if every digest in the chain is neither persisted nor in-flight.
    pub fn can_persist_chain(&self, chain: &[Digest]) -> bool {
        let persisted = self.persisted.read();
        let persisting = self.persisting.read();
        chain.iter().all(|digest| !persisted.contains(digest) && !persisting.contains(digest))
    }

    /// Mark a chain as being persisted.
    pub fn mark_persisting_chain(&self, chain: &[Digest]) {
        let mut persisting = self.persisting.write();
        for digest in chain {
            persisting.insert(*digest);
        }
    }

    /// Clear the in-flight markers for a chain.
    pub fn clear_persisting_chain(&self, chain: &[Digest]) {
        let mut persisting = self.persisting.write();
        for digest in chain {
            persisting.remove(digest);
        }
    }

    /// Evict the oldest persisted snapshots that exceed the retention limit.
    ///
    /// After a successful `persist_snapshot` call, this method should be invoked
    /// to free memory held by snapshots whose state has already been committed
    /// to the persistent store (QMDB).
    ///
    /// The `persisted` marker is intentionally **kept** for evicted digests so
    /// that ancestor chain-walking (`merged_changes`, `changes_for_persist`,
    /// `collect_pending_tx_ids`) still terminates correctly at persisted
    /// boundaries.
    ///
    /// Returns the number of snapshots evicted.
    ///
    /// # Lock ordering
    ///
    /// All methods that acquire multiple locks follow the canonical order:
    /// `persisted` -> `persisted_order` -> `snapshots`.  This method
    /// acquires `persisted(R)` then `persisted_order(W)` then
    /// `snapshots(W)`, which is consistent with this ordering and prevents
    /// deadlocks with concurrent calls to `mark_persisted`,
    /// `unpersisted_count`, `merged_changes`, and `changes_for_persist`.
    pub fn evict_persisted(&self) -> usize {
        // Fast path: check with a read lock to avoid write-lock contention
        // when no eviction is needed (the common case).
        if self.persisted_order.read().len() <= self.max_persisted_retained {
            return 0;
        }

        // Acquire locks in canonical order: persisted -> persisted_order -> snapshots.
        let persisted = self.persisted.read();
        let mut order = self.persisted_order.write();
        let mut snapshots = self.snapshots.write();

        let mut evicted = 0usize;
        while order.len() > self.max_persisted_retained {
            let Some(oldest) = order.pop_front() else {
                break;
            };
            // Only remove snapshot data if it is actually persisted.
            // (Guards against stale entries in the order queue.)
            if persisted.contains(&oldest) && snapshots.remove(&oldest).is_some() {
                evicted += 1;
            }
        }

        if evicted > 0 {
            debug!(
                evicted,
                retained = snapshots.len(),
                persisted = persisted.len(),
                "evicted persisted snapshots"
            );
        }

        evicted
    }
}

impl<S> Default for InMemorySnapshotStore<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: StateDb> SnapshotStore<S> for InMemorySnapshotStore<S> {
    fn get(&self, digest: &Digest) -> Option<Snapshot<S>> {
        self.snapshots.read().get(digest).cloned()
    }

    fn insert(&self, digest: Digest, snapshot: Snapshot<S>) {
        self.snapshots.write().insert(digest, snapshot);
    }

    fn is_persisted(&self, digest: &Digest) -> bool {
        self.persisted.read().contains(digest)
    }

    fn mark_persisted(&self, digests: &[Digest]) {
        let mut persisted = self.persisted.write();
        let mut order = self.persisted_order.write();
        for digest in digests {
            if persisted.insert(*digest) {
                order.push_back(*digest);
            }
        }
    }

    /// Lock ordering: `persisted(R)` -> `snapshots(R)`.
    fn merged_changes(
        &self,
        parent: Digest,
        new_changes: ChangeSet,
    ) -> Result<ChangeSet, ConsensusError> {
        let persisted = self.persisted.read();
        let snapshots = self.snapshots.read();

        // Walk back to find all unpersisted ancestors
        let mut chain = Vec::new();
        let mut current = Some(parent);

        while let Some(digest) = current {
            if persisted.contains(&digest) {
                break;
            }

            let snapshot =
                snapshots.get(&digest).ok_or(ConsensusError::SnapshotNotFound(digest))?;

            chain.push(snapshot.changes.clone());
            current = snapshot.parent;
        }

        // Merge in reverse order (oldest first)
        let mut merged = ChangeSet::new();
        for changes in chain.into_iter().rev() {
            merged.merge(changes);
        }
        merged.merge(new_changes);

        Ok(merged)
    }

    /// Lock ordering: `persisted(R)` -> `snapshots(R)`.
    fn changes_for_persist(
        &self,
        digest: Digest,
    ) -> Result<(Vec<Digest>, ChangeSet), ConsensusError> {
        let persisted = self.persisted.read();
        let snapshots = self.snapshots.read();

        let mut chain = Vec::new();
        let mut changes_chain = Vec::new();
        let mut current = Some(digest);

        while let Some(d) = current {
            if persisted.contains(&d) {
                break;
            }

            let snapshot = snapshots.get(&d).ok_or(ConsensusError::SnapshotNotFound(d))?;

            chain.push(d);
            changes_chain.push(snapshot.changes.clone());
            current = snapshot.parent;
        }

        // Reverse to get oldest-first order
        chain.reverse();
        changes_chain.reverse();

        let mut merged = ChangeSet::new();
        for changes in changes_chain {
            merged.merge(changes);
        }

        Ok((chain, merged))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use alloy_primitives::B256;
    use kora_domain::StateRoot;

    use super::*;

    // Mock StateDb for testing
    #[derive(Clone, Debug)]
    struct MockStateDb;

    impl kora_traits::StateDbRead for MockStateDb {
        async fn nonce(
            &self,
            _address: &alloy_primitives::Address,
        ) -> Result<u64, kora_traits::StateDbError> {
            Ok(0)
        }

        async fn balance(
            &self,
            _address: &alloy_primitives::Address,
        ) -> Result<alloy_primitives::U256, kora_traits::StateDbError> {
            Ok(alloy_primitives::U256::ZERO)
        }

        async fn code_hash(
            &self,
            _address: &alloy_primitives::Address,
        ) -> Result<B256, kora_traits::StateDbError> {
            Ok(B256::ZERO)
        }

        async fn code(
            &self,
            _code_hash: &B256,
        ) -> Result<alloy_primitives::Bytes, kora_traits::StateDbError> {
            Ok(alloy_primitives::Bytes::new())
        }

        async fn storage(
            &self,
            _address: &alloy_primitives::Address,
            _slot: &alloy_primitives::U256,
        ) -> Result<alloy_primitives::U256, kora_traits::StateDbError> {
            Ok(alloy_primitives::U256::ZERO)
        }
    }

    impl kora_traits::StateDbWrite for MockStateDb {
        async fn commit(&self, _changes: ChangeSet) -> Result<B256, kora_traits::StateDbError> {
            Ok(B256::ZERO)
        }

        async fn compute_root(
            &self,
            _changes: &ChangeSet,
        ) -> Result<B256, kora_traits::StateDbError> {
            Ok(B256::ZERO)
        }

        fn merge_changes(&self, mut older: ChangeSet, newer: ChangeSet) -> ChangeSet {
            older.merge(newer);
            older
        }
    }

    impl kora_traits::StateDb for MockStateDb {
        async fn state_root(&self) -> Result<B256, kora_traits::StateDbError> {
            Ok(B256::ZERO)
        }
    }

    #[test]
    fn snapshot_store_insert_and_get() {
        let store = InMemorySnapshotStore::<MockStateDb>::new();

        let digest = Digest::from([0x01u8; 32]);
        let snapshot = Snapshot::new(
            None,
            MockStateDb,
            StateRoot(B256::ZERO),
            ChangeSet::new(),
            BTreeSet::new(),
        );

        assert!(store.get(&digest).is_none());

        store.insert(digest, snapshot);
        assert!(store.get(&digest).is_some());
    }

    #[test]
    fn snapshot_store_persisted() {
        let store = InMemorySnapshotStore::<MockStateDb>::new();

        let digest = Digest::from([0x01u8; 32]);
        assert!(!store.is_persisted(&digest));

        store.mark_persisted(&[digest]);
        assert!(store.is_persisted(&digest));
    }

    #[test]
    fn snapshot_store_persisting_guard() {
        let store = InMemorySnapshotStore::<MockStateDb>::new();

        let digest = Digest::from([0x02u8; 32]);
        assert!(store.can_persist_chain(&[digest]));

        store.mark_persisting_chain(&[digest]);
        assert!(!store.can_persist_chain(&[digest]));

        store.clear_persisting_chain(&[digest]);
        assert!(store.can_persist_chain(&[digest]));

        store.mark_persisted(&[digest]);
        assert!(!store.can_persist_chain(&[digest]));
    }

    fn make_digest(byte: u8) -> Digest {
        Digest::from([byte; 32])
    }

    fn make_snapshot(parent: Option<Digest>) -> Snapshot<MockStateDb> {
        Snapshot::new(parent, MockStateDb, StateRoot(B256::ZERO), ChangeSet::new(), BTreeSet::new())
    }

    #[test]
    fn evict_persisted_removes_oldest_snapshots() {
        // Retain at most 2 persisted snapshots.
        let store = InMemorySnapshotStore::<MockStateDb>::with_max_persisted_retained(2);

        let d1 = make_digest(0x01);
        let d2 = make_digest(0x02);
        let d3 = make_digest(0x03);
        let d4 = make_digest(0x04);

        store.insert(d1, make_snapshot(None));
        store.insert(d2, make_snapshot(Some(d1)));
        store.insert(d3, make_snapshot(Some(d2)));
        store.insert(d4, make_snapshot(Some(d3)));

        // Persist d1 and d2, then evict -- both are within the limit.
        store.mark_persisted(&[d1, d2]);
        assert_eq!(store.evict_persisted(), 0);
        assert_eq!(store.len(), 4);

        // Persist d3 -- now 3 persisted, limit is 2, so d1 should be evicted.
        store.mark_persisted(&[d3]);
        assert_eq!(store.evict_persisted(), 1);
        assert!(store.get(&d1).is_none(), "d1 should have been evicted");
        assert!(store.get(&d2).is_some(), "d2 should still be retained");
        assert!(store.get(&d3).is_some(), "d3 should still be retained");
        assert!(store.get(&d4).is_some(), "d4 is not persisted, should be retained");

        // The persisted marker for d1 should still be present (for chain-walking).
        assert!(store.is_persisted(&d1));
    }

    #[test]
    fn evict_persisted_does_not_remove_unpersisted() {
        let store = InMemorySnapshotStore::<MockStateDb>::with_max_persisted_retained(1);

        let d1 = make_digest(0x01);
        let d2 = make_digest(0x02);
        let d3 = make_digest(0x03);

        store.insert(d1, make_snapshot(None));
        store.insert(d2, make_snapshot(Some(d1)));
        store.insert(d3, make_snapshot(Some(d2)));

        // Only persist d1 -- within limit, no eviction.
        store.mark_persisted(&[d1]);
        assert_eq!(store.evict_persisted(), 0);

        // Persist d2 -- now 2 persisted, limit is 1, evict d1.
        store.mark_persisted(&[d2]);
        assert_eq!(store.evict_persisted(), 1);
        assert!(store.get(&d1).is_none());
        assert!(store.get(&d2).is_some());
        // d3 is not persisted, must not be evicted.
        assert!(store.get(&d3).is_some());
    }

    #[test]
    fn evict_persisted_with_zero_retention_evicts_all() {
        let store = InMemorySnapshotStore::<MockStateDb>::with_max_persisted_retained(0);

        let d1 = make_digest(0x01);
        let d2 = make_digest(0x02);

        store.insert(d1, make_snapshot(None));
        store.insert(d2, make_snapshot(Some(d1)));

        store.mark_persisted(&[d1, d2]);
        let evicted = store.evict_persisted();
        assert_eq!(evicted, 2);
        assert!(store.get(&d1).is_none());
        assert!(store.get(&d2).is_none());
        // Persisted markers are kept.
        assert!(store.is_persisted(&d1));
        assert!(store.is_persisted(&d2));
    }

    #[test]
    fn len_and_persisted_count_track_correctly() {
        let store = InMemorySnapshotStore::<MockStateDb>::with_max_persisted_retained(1);

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert_eq!(store.persisted_count(), 0);

        let d1 = make_digest(0x01);
        let d2 = make_digest(0x02);

        store.insert(d1, make_snapshot(None));
        assert_eq!(store.len(), 1);

        store.insert(d2, make_snapshot(Some(d1)));
        assert_eq!(store.len(), 2);

        store.mark_persisted(&[d1, d2]);
        assert_eq!(store.persisted_count(), 2);

        store.evict_persisted();
        // d1 evicted from snapshots, d2 retained.
        assert_eq!(store.len(), 1);
        // Both remain in persisted set.
        assert_eq!(store.persisted_count(), 2);
    }

    #[test]
    fn evict_persisted_is_noop_within_limit() {
        // Retention limit of 4, persist exactly 4 -- no eviction should happen.
        let store = InMemorySnapshotStore::<MockStateDb>::with_max_persisted_retained(4);

        let d1 = make_digest(0x01);
        let d2 = make_digest(0x02);
        let d3 = make_digest(0x03);
        let d4 = make_digest(0x04);

        store.insert(d1, make_snapshot(None));
        store.insert(d2, make_snapshot(Some(d1)));
        store.insert(d3, make_snapshot(Some(d2)));
        store.insert(d4, make_snapshot(Some(d3)));

        store.mark_persisted(&[d1, d2, d3, d4]);
        assert_eq!(store.persisted_count(), 4);

        // Eviction should be a no-op: exactly at the limit.
        assert_eq!(store.evict_persisted(), 0);

        // All snapshots remain in memory.
        assert_eq!(store.len(), 4);
        assert!(store.get(&d1).is_some());
        assert!(store.get(&d2).is_some());
        assert!(store.get(&d3).is_some());
        assert!(store.get(&d4).is_some());
    }

    #[test]
    fn mark_persisted_is_idempotent_for_order_tracking() {
        let store = InMemorySnapshotStore::<MockStateDb>::with_max_persisted_retained(1);

        let d1 = make_digest(0x01);
        store.insert(d1, make_snapshot(None));

        // Mark persisted twice -- should not duplicate in the order queue.
        store.mark_persisted(&[d1]);
        store.mark_persisted(&[d1]);

        assert_eq!(store.persisted_count(), 1);
        // Eviction with only 1 persisted and limit 1 should evict nothing.
        assert_eq!(store.evict_persisted(), 0);
    }

    #[test]
    fn unpersisted_count_tracks_correctly() {
        let store = InMemorySnapshotStore::<MockStateDb>::with_max_persisted_retained(4);

        let d1 = make_digest(0x01);
        let d2 = make_digest(0x02);
        let d3 = make_digest(0x03);

        // Empty store has zero unpersisted.
        assert_eq!(store.unpersisted_count(), 0);

        // Insert three snapshots -- all unpersisted.
        store.insert(d1, make_snapshot(None));
        store.insert(d2, make_snapshot(Some(d1)));
        store.insert(d3, make_snapshot(Some(d2)));
        assert_eq!(store.unpersisted_count(), 3);
        assert_eq!(store.len(), 3);

        // Persist d1 -- two unpersisted remain.
        store.mark_persisted(&[d1]);
        assert_eq!(store.unpersisted_count(), 2);

        // Persist all -- zero unpersisted.
        store.mark_persisted(&[d2, d3]);
        assert_eq!(store.unpersisted_count(), 0);
    }
}
