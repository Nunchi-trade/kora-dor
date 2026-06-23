//! Runtime wrapper for non-durable consensus scratch storage.

use std::{
    collections::BTreeMap,
    future::Future,
    ops::RangeInclusive,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, SystemTime},
};

use commonware_runtime::{
    Blob, BufferPool, BufferPooler, Clock, Error, Handle, IoBufs, IoBufsMut, Metrics, Spawner,
    Storage, Supervisor, Tracing, iobuf, signal,
    telemetry::metrics::{Metric, Registered},
};
use rand::{CryptoRng, RngCore};

type PartitionMap = BTreeMap<String, BTreeMap<Vec<u8>, Arc<RwLock<Vec<u8>>>>>;

/// Wraps a runtime context with in-memory storage for consensus scratch data.
///
/// Finalized archives and QMDB still use the normal runtime context. This
/// wrapper is only used for state that can be reconstructed from finalized
/// blocks, so it avoids Docker-volume write latency without putting durable
/// state on tmpfs.
pub(crate) struct NoSyncStorage<C> {
    inner: C,
    partitions: Arc<Mutex<PartitionMap>>,
    checkpoint_interval: u64,
}

impl<C> NoSyncStorage<C> {
    /// Create a wrapper around an existing context.
    pub(crate) fn new(inner: C, checkpoint_interval: u64) -> Self {
        Self {
            inner,
            partitions: Arc::new(Mutex::new(BTreeMap::new())),
            checkpoint_interval: checkpoint_interval.max(1),
        }
    }
}

impl<C> Clone for NoSyncStorage<C>
where
    C: Supervisor,
{
    fn clone(&self) -> Self {
        // Use `child()` with a stable label instead of creating a new child
        // on every clone. The Commonware `Context` type does not implement
        // `Clone`, so `child()` is the only way to obtain a second handle.
        // Using a fixed label prevents the label chain from growing on
        // successive clones (see issue #108). The `Supervisor::child` API
        // always appends, so repeated clones of a clone will still grow by
        // one segment per generation, but this is bounded by the clone
        // depth rather than the total clone count.
        Self {
            inner: self.inner.child("nosync_storage"),
            partitions: self.partitions.clone(),
            checkpoint_interval: self.checkpoint_interval,
        }
    }
}

impl<C> std::fmt::Debug for NoSyncStorage<C>
where
    C: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoSyncStorage")
            .field("inner", &self.inner)
            .field("checkpoint_interval", &self.checkpoint_interval)
            .finish_non_exhaustive()
    }
}

/// Blob backed either by scratch memory or by the underlying persistent runtime.
#[derive(Clone, Debug)]
pub(crate) enum NoSyncBlob<B> {
    Memory {
        content: Arc<RwLock<Vec<u8>>>,
        pool: BufferPool,
    },
    /// Direct passthrough to underlying blob — no shadow, no interception.
    Passthrough(B),
}

/// Returns `true` if this partition MUST be written to disk.
///
/// The marshal's application-metadata partition is the only one that needs
/// durability through NoSyncStorage — it tracks the last acknowledged height
/// so the marshal knows which blocks to redeliver on restart.  Everything
/// else (consensus caches, marshal freezer data, journals) can live in memory
/// because it is either reconstructed from the finalized block archive on
/// startup or is transient consensus state.
///
/// The finalized block archives and QMDB bypass NoSyncStorage entirely (they
/// use the raw runtime context), so durability of actual block data and state
/// is not affected by this function.
fn is_durable_partition(partition: &str) -> bool {
    partition.ends_with("-application-metadata")
}

impl<C> Supervisor for NoSyncStorage<C>
where
    C: Supervisor,
{
    fn name(&self) -> commonware_runtime::Name {
        self.inner.name()
    }

    fn child(&self, label: &'static str) -> Self {
        Self {
            inner: self.inner.child(label),
            partitions: self.partitions.clone(),
            checkpoint_interval: self.checkpoint_interval,
        }
    }

    fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
        Self {
            inner: self.inner.with_attribute(key, value),
            partitions: self.partitions,
            checkpoint_interval: self.checkpoint_interval,
        }
    }
}

impl<C> Spawner for NoSyncStorage<C>
where
    C: Spawner,
{
    fn shared(self, blocking: bool) -> Self {
        Self {
            inner: self.inner.shared(blocking),
            partitions: self.partitions,
            checkpoint_interval: self.checkpoint_interval,
        }
    }

    fn dedicated(self) -> Self {
        Self {
            inner: self.inner.dedicated(),
            partitions: self.partitions,
            checkpoint_interval: self.checkpoint_interval,
        }
    }

    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let partitions = self.partitions;
        let checkpoint_interval = self.checkpoint_interval;
        self.inner.spawn(move |context| f(Self { inner: context, partitions, checkpoint_interval }))
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.inner.stop(value, timeout).await
    }

    fn stopped(&self) -> signal::Signal {
        self.inner.stopped()
    }
}

impl<C> Metrics for NoSyncStorage<C>
where
    C: Metrics,
{
    fn register<N, H, M>(&self, name: N, help: H, metric: M) -> Registered<M>
    where
        N: Into<String>,
        H: Into<String>,
        M: Metric,
    {
        self.inner.register(name, help, metric)
    }

    fn encode(&self) -> String {
        self.inner.encode()
    }
}

impl<C> Tracing for NoSyncStorage<C>
where
    C: Tracing,
{
    fn with_span(self) -> Self {
        Self {
            inner: self.inner.with_span(),
            partitions: self.partitions,
            checkpoint_interval: self.checkpoint_interval,
        }
    }
}

impl<C> governor::clock::Clock for NoSyncStorage<C>
where
    C: governor::clock::Clock<Instant = SystemTime>,
{
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.inner.now()
    }
}

impl<C> governor::clock::ReasonablyRealtime for NoSyncStorage<C> where
    C: governor::clock::ReasonablyRealtime + governor::clock::Clock<Instant = SystemTime>
{
}

impl<C> Clock for NoSyncStorage<C>
where
    C: Clock,
{
    fn current(&self) -> SystemTime {
        self.inner.current()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        self.inner.sleep(duration)
    }

    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        self.inner.sleep_until(deadline)
    }
}

impl<C> BufferPooler for NoSyncStorage<C>
where
    C: BufferPooler,
{
    fn network_buffer_pool(&self) -> &BufferPool {
        self.inner.network_buffer_pool()
    }

    fn storage_buffer_pool(&self) -> &BufferPool {
        self.inner.storage_buffer_pool()
    }
}

impl<C> RngCore for NoSyncStorage<C>
where
    C: RngCore,
{
    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl<C> CryptoRng for NoSyncStorage<C> where C: CryptoRng + RngCore {}

impl<C> Storage for NoSyncStorage<C>
where
    C: BufferPooler + Storage,
{
    type Blob = NoSyncBlob<C::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        if is_durable_partition(partition) {
            let (blob, size, version) =
                self.inner.open_versioned(partition, name, versions).await?;
            return Ok((NoSyncBlob::Passthrough(blob), size, version));
        }

        let mut partitions = self.partitions.lock().expect("scratch storage mutex poisoned");
        let content = partitions
            .entry(partition.to_string())
            .or_default()
            .entry(name.to_vec())
            .or_default()
            .clone();
        let size = content.read().expect("scratch blob lock poisoned").len() as u64;
        let version = *versions.end();
        Ok((
            NoSyncBlob::Memory { content, pool: self.storage_buffer_pool().clone() },
            size,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        if is_durable_partition(partition) {
            return self.inner.remove(partition, name).await;
        }

        let mut partitions = self.partitions.lock().expect("scratch storage mutex poisoned");
        match name {
            Some(name) => {
                if let Some(partition) = partitions.get_mut(partition) {
                    partition.remove(name);
                }
            }
            None => {
                partitions.remove(partition);
            }
        }
        Ok(())
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        if is_durable_partition(partition) {
            return self.inner.scan(partition).await;
        }

        let partitions = self.partitions.lock().expect("scratch storage mutex poisoned");
        let mut names = partitions
            .get(partition)
            .map(|partition| partition.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        names.sort();
        Ok(names)
    }
}

impl<B> Blob for NoSyncBlob<B>
where
    B: Blob,
{
    fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<iobuf::IoBufsMut> + Send,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        async move {
            match self {
                Self::Memory { content, .. } => {
                    let offset: usize = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
                    let content = content.read().expect("scratch blob lock poisoned");
                    let end = offset.checked_add(len).ok_or(Error::OffsetOverflow)?;
                    if end > content.len() {
                        return Err(Error::BlobInsufficientLength);
                    }
                    let _: iobuf::IoBufsMut = bufs.into();
                    Ok(content[offset..end].to_vec().into())
                }
                Self::Passthrough(blob) => blob.read_at_buf(offset, len, bufs).await,
            }
        }
    }

    fn read_at(
        &self,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        async move {
            match self {
                Self::Memory { pool, .. } => self.read_at_buf(offset, len, pool.alloc(len)).await,
                Self::Passthrough(blob) => blob.read_at(offset, len).await,
            }
        }
    }

    fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        async move {
            match self {
                Self::Memory { content, .. } => {
                    let buf = bufs.into().coalesce();
                    let offset: usize = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
                    let end = offset.checked_add(buf.len()).ok_or(Error::OffsetOverflow)?;
                    let mut content = content.write().expect("scratch blob lock poisoned");
                    if end > content.len() {
                        content.resize(end, 0);
                    }
                    content[offset..end].copy_from_slice(buf.as_ref());
                    Ok(())
                }
                Self::Passthrough(blob) => blob.write_at(offset, bufs).await,
            }
        }
    }

    fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        async move {
            match self {
                Self::Memory { content, .. } => {
                    let buf = bufs.into().coalesce();
                    let offset: usize = offset.try_into().map_err(|_| Error::OffsetOverflow)?;
                    let end = offset.checked_add(buf.len()).ok_or(Error::OffsetOverflow)?;
                    let mut content = content.write().expect("scratch blob lock poisoned");
                    if end > content.len() {
                        content.resize(end, 0);
                    }
                    content[offset..end].copy_from_slice(buf.as_ref());
                    Ok(())
                }
                Self::Passthrough(blob) => blob.write_at_sync(offset, bufs).await,
            }
        }
    }

    fn resize(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send {
        async move {
            match self {
                Self::Memory { content, .. } => {
                    let len: usize = len.try_into().map_err(|_| Error::OffsetOverflow)?;
                    content.write().expect("scratch blob lock poisoned").resize(len, 0);
                    Ok(())
                }
                Self::Passthrough(blob) => blob.resize(len).await,
            }
        }
    }

    async fn sync(&self) -> Result<(), Error> {
        match self {
            Self::Memory { .. } => Ok(()),
            Self::Passthrough(blob) => blob.sync().await,
        }
    }
}
