//! Simulated transport context wrapper.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime},
};

use commonware_runtime::{self, tokio};
use governor::clock::{Clock as GovernorClock, ReasonablyRealtime};
use rand::{RngCore, rngs::OsRng};

const PORT_BASE_MIN: u16 = 40_000;
const PORT_BASE_MAX: u16 = 65_535 - 1_024;

const fn remap_socket(socket: SocketAddr, port_offset: u16) -> SocketAddr {
    let port = socket.port();
    if port >= 1024 {
        return socket;
    }
    let remapped = port + port_offset;
    match socket.ip() {
        IpAddr::V4(ip) => SocketAddr::new(IpAddr::V4(ip), remapped),
        IpAddr::V6(ip) => SocketAddr::new(IpAddr::V6(ip), remapped),
    }
}

/// Tokio context wrapper for simulated networking.
///
/// Forces binding to localhost with randomized port offsets to allow
/// multiple simulated nodes to run in the same process without port conflicts.
pub struct SimContext {
    inner: tokio::Context,
    force_base_addr: bool,
    base_addr: Ipv4Addr,
    port_offset: u16,
}

impl fmt::Debug for SimContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimContext")
            .field("base_addr", &self.base_addr)
            .field("port_offset", &self.port_offset)
            .field("force_base_addr", &self.force_base_addr)
            .finish_non_exhaustive()
    }
}

impl SimContext {
    /// Create a new simulation context wrapping a tokio context.
    ///
    /// On Linux the entire `127.0.0.0/8` subnet is routable via the loopback
    /// interface, so we randomize the base address for isolation between
    /// parallel test processes.  On macOS only `127.0.0.1` is configured on
    /// `lo0`, so binding to any other `127.x.x.x` address fails with
    /// `BindFailed`.  We fall back to `127.0.0.1` there and rely solely on
    /// the randomized port offset for isolation.
    pub fn new(inner: tokio::Context) -> Self {
        let mut rng = OsRng;
        let span = u32::from(PORT_BASE_MAX - PORT_BASE_MIN + 1);
        let base = PORT_BASE_MIN + (rng.next_u32() % span) as u16;

        #[cfg(target_os = "macos")]
        let base_addr = Ipv4Addr::LOCALHOST;

        #[cfg(not(target_os = "macos"))]
        let base_addr = {
            let seed = rng.next_u32() ^ std::process::id();
            Ipv4Addr::new(127, (seed >> 16) as u8, (seed >> 8) as u8, seed as u8)
        };

        Self { inner, force_base_addr: true, base_addr, port_offset: base }
    }
}

impl Clone for SimContext {
    fn clone(&self) -> Self {
        Self {
            inner: commonware_runtime::Supervisor::child(&self.inner, "sim_context"),
            force_base_addr: false,
            base_addr: self.base_addr,
            port_offset: self.port_offset,
        }
    }
}

impl GovernorClock for SimContext {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        <tokio::Context as GovernorClock>::now(&self.inner)
    }
}

impl ReasonablyRealtime for SimContext {}

impl commonware_runtime::Clock for SimContext {
    fn current(&self) -> SystemTime {
        self.inner.current()
    }

    fn sleep(&self, duration: Duration) -> impl std::future::Future<Output = ()> + Send + 'static {
        self.inner.sleep(duration)
    }

    fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        self.inner.sleep_until(deadline)
    }
}

impl commonware_runtime::Supervisor for SimContext {
    fn name(&self) -> commonware_runtime::Name {
        self.inner.name()
    }

    fn child(&self, label: &'static str) -> Self {
        Self {
            inner: self.inner.child(label),
            force_base_addr: false,
            base_addr: self.base_addr,
            port_offset: self.port_offset,
        }
    }

    fn with_attribute(self, key: &'static str, value: impl fmt::Display) -> Self {
        Self {
            inner: self.inner.with_attribute(key, value),
            force_base_addr: false,
            base_addr: self.base_addr,
            port_offset: self.port_offset,
        }
    }
}

impl commonware_runtime::Tracing for SimContext {
    fn with_span(self) -> Self {
        Self {
            inner: self.inner.with_span(),
            force_base_addr: false,
            base_addr: self.base_addr,
            port_offset: self.port_offset,
        }
    }
}

impl commonware_runtime::Metrics for SimContext {
    fn register<N, H, M>(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> commonware_runtime::telemetry::metrics::Registered<M>
    where
        N: Into<String>,
        H: Into<String>,
        M: commonware_runtime::telemetry::metrics::Metric,
    {
        self.inner.register(name, help, metric)
    }

    fn encode(&self) -> String {
        self.inner.encode()
    }
}

impl commonware_runtime::Spawner for SimContext {
    fn shared(mut self, blocking: bool) -> Self {
        self.inner = self.inner.shared(blocking);
        self
    }

    fn dedicated(mut self) -> Self {
        self.inner = self.inner.dedicated();
        self
    }

    fn spawn<F, Fut, T>(self, f: F) -> commonware_runtime::Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let port_offset = self.port_offset;
        let base_addr = self.base_addr;
        self.inner.spawn(move |context| {
            let context = Self { inner: context, force_base_addr: false, base_addr, port_offset };
            f(context)
        })
    }

    fn stop(
        self,
        value: i32,
        timeout: Option<Duration>,
    ) -> impl std::future::Future<Output = Result<(), commonware_runtime::Error>> + Send {
        self.inner.stop(value, timeout)
    }

    fn stopped(&self) -> commonware_runtime::signal::Signal {
        self.inner.stopped()
    }
}

impl commonware_runtime::Network for SimContext {
    type Listener = <tokio::Context as commonware_runtime::Network>::Listener;

    fn bind(
        &self,
        socket: SocketAddr,
    ) -> impl std::future::Future<Output = Result<Self::Listener, commonware_runtime::Error>> + Send
    {
        self.inner.bind(remap_socket(socket, self.port_offset))
    }

    fn dial(
        &self,
        socket: SocketAddr,
    ) -> impl std::future::Future<
        Output = Result<
            (commonware_runtime::SinkOf<Self>, commonware_runtime::StreamOf<Self>),
            commonware_runtime::Error,
        >,
    > + Send {
        self.inner.dial(remap_socket(socket, self.port_offset))
    }
}

impl RngCore for SimContext {
    fn next_u32(&mut self) -> u32 {
        if self.force_base_addr {
            self.force_base_addr = false;
            return self.base_addr.to_bits();
        }
        let mut rng = OsRng;
        RngCore::next_u32(&mut rng)
    }

    fn next_u64(&mut self) -> u64 {
        let mut rng = OsRng;
        RngCore::next_u64(&mut rng)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut rng = OsRng;
        RngCore::fill_bytes(&mut rng, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        let mut rng = OsRng;
        RngCore::try_fill_bytes(&mut rng, dest)
    }
}
