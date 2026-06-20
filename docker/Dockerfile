# ═══════════════════════════════════════════════════════════════════════════
# Kora Node Docker Image
# Multi-stage build with cargo-chef for optimal layer caching
# ═══════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────
# Stage 1: Chef - Install cargo-chef for dependency caching
# ───────────────────────────────────────────────────────────────────────────
FROM rustlang/rust:nightly-bookworm AS chef

RUN cargo install cargo-chef --locked
WORKDIR /app

# ───────────────────────────────────────────────────────────────────────────
# Stage 2: Planner - Analyze dependencies and create recipe
# ───────────────────────────────────────────────────────────────────────────
FROM chef AS planner

COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ───────────────────────────────────────────────────────────────────────────
# Stage 3: Builder - Build dependencies (cached) then application
# ───────────────────────────────────────────────────────────────────────────
FROM chef AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy recipe and build dependencies (this layer is cached)
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Copy source and build application
COPY . .

# Build production binaries (loadgen excluded from production image)
RUN cargo build --release -p kora -p keygen

# ───────────────────────────────────────────────────────────────────────────
# Stage 4: Runtime - Minimal production image
# ───────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    netcat-openbsd \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash kora && \
    mkdir -p /var/lib/kora /etc/kora /data /shared /runtime && \
    chown -R kora:kora /var/lib/kora /etc/kora /data /shared /runtime

# Copy binaries from builder (loadgen excluded from production image)
COPY --from=builder /app/target/release/kora /usr/local/bin/
COPY --from=builder /app/target/release/keygen /usr/local/bin/

# Copy entrypoint scripts
COPY docker/scripts/ /scripts/
RUN chmod +x /scripts/*.sh

# Switch to non-root user
USER kora
WORKDIR /data

# Expose ports
# 30303 - P2P networking
# 8545  - HTTP JSON-RPC (reserved for Phase 3)
# 8546  - WebSocket JSON-RPC (reserved for Phase 3)
# 9002  - Prometheus metrics
EXPOSE 30303 8545 8546 9002

# Default volumes
VOLUME ["/data", "/shared"]

# Runtime health check shared with Compose. Override HEALTHCHECK_MODE to
# switch the check: dkg (share.key + output.json exist), p2p (port 30303),
# ready (eth_blockNumber + stall detection). Default mode is p2p.
# The compose file overrides these timings; these are conservative defaults.
HEALTHCHECK --interval=30s --timeout=10s --retries=6 --start-period=120s \
    CMD /scripts/healthcheck.sh

# Default entrypoint - can be overridden for different modes
ENTRYPOINT ["/scripts/entrypoint.sh"]
CMD ["validator"]
