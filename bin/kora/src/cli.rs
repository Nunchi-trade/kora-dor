use std::{path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use commonware_runtime::Supervisor as _;
use commonware_utils::{Faults, N3f1};
use kora_config::NodeConfig;
use kora_domain::BootstrapConfig;
use kora_rpc::NodeState;
use kora_runner::{ProductionRunner, load_threshold_scheme, runtime_storage_directory};
use kora_service::LegacyNodeService;

#[derive(Parser, Debug)]
#[command(name = "kora")]
#[command(about = "A minimal commonware + revm execution client")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(short, long, value_name = "FILE", global = true)]
    pub config: Option<PathBuf>,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(long, global = true)]
    pub chain_id: Option<u64>,

    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    Dkg(DkgArgs),
    Validator(ValidatorArgs),
    Secondary(SecondaryArgs),
}

#[derive(clap::Args, Debug)]
pub(crate) struct DkgArgs {
    /// Path to peers.json file containing participant information.
    #[arg(long)]
    pub peers: PathBuf,

    /// Force restart the DKG ceremony, ignoring any persisted state.
    #[arg(long, default_value = "false")]
    pub force_restart: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct ValidatorArgs {
    #[arg(long)]
    pub peers: Option<PathBuf>,

    /// Prometheus metrics server bind address.
    #[arg(long, default_value = "0.0.0.0:9002")]
    pub metrics_addr: String,

    /// Enable P2P transaction gossip between validators.
    #[arg(long, default_value = "false")]
    pub tx_gossip: bool,
}

#[derive(clap::Args, Debug)]
pub(crate) struct SecondaryArgs {
    /// Path to peers.json file containing primary and secondary peer information.
    #[arg(long)]
    pub peers: PathBuf,

    /// JSON-RPC server bind address (reserved for future read-only RPC).
    #[arg(long, default_value = "0.0.0.0:8545")]
    pub rpc_addr: String,

    /// Prometheus metrics server bind address.
    #[arg(long, default_value = "0.0.0.0:9002")]
    pub metrics_addr: String,
}

impl Cli {
    pub(crate) fn load_config(&self) -> eyre::Result<NodeConfig> {
        let mut config = NodeConfig::load(self.config.as_deref())?;

        if let Some(chain_id) = self.chain_id {
            config.chain_id = chain_id;
        }
        if let Some(ref data_dir) = self.data_dir {
            config.data_dir = data_dir.clone();
        }

        Ok(config)
    }

    pub(crate) fn run(self) -> eyre::Result<()> {
        match &self.command {
            Some(Commands::Dkg(args)) => self.run_dkg(args),
            Some(Commands::Validator(args)) => self.run_validator(args),
            Some(Commands::Secondary(args)) => self.run_secondary(args),
            None => self.run_legacy(),
        }
    }

    fn run_dkg(&self, args: &DkgArgs) -> eyre::Result<()> {
        use kora_dkg::{DkgCeremony, DkgConfig};

        let node_config = self.load_config()?;
        tracing::info!(chain_id = node_config.chain_id, "Starting DKG ceremony");

        let peers = load_peers(&args.peers)?;
        let identity_key = node_config.validator_key()?;
        let my_pk = commonware_cryptography::Signer::public_key(&identity_key);

        let validator_index = peers
            .participants
            .iter()
            .position(|pk| *pk == my_pk)
            .ok_or_else(|| eyre::eyre!("Our public key not found in participants list"))?;

        let n = peers.participants.len();
        let quorum = N3f1::quorum(n);
        tracing::info!(
            n = n,
            quorum = quorum,
            max_faulty = n as u32 - quorum,
            "Consensus quorum determined by N3f1: need {} of {} validators active",
            quorum,
            n
        );

        let dkg_config = DkgConfig {
            identity_key,
            validator_index,
            participants: peers.participants,
            chain_id: node_config.chain_id,
            data_dir: node_config.data_dir.clone(),
            listen_addr: node_config.network.listen_addr.parse()?,
            bootstrap_peers: peers.bootstrappers,
            timeout: std::time::Duration::from_secs(300),
        };

        let ceremony = if args.force_restart {
            DkgCeremony::new_with_force_restart(dkg_config, true)
        } else {
            DkgCeremony::new(dkg_config)
        };

        let rt = tokio::runtime::Runtime::new()?;
        let output = rt.block_on(ceremony.run())?;

        tracing::info!(share_index = output.share_index, "DKG ceremony completed successfully");

        Ok(())
    }

    fn run_validator(&self, args: &ValidatorArgs) -> eyre::Result<()> {
        let mut config = self.load_config()?;

        if args.tx_gossip {
            config.network.tx_gossip = true;
        }

        tracing::info!(chain_id = config.chain_id, "Starting validator");

        if !kora_dkg::DkgOutput::exists(&config.data_dir) {
            return Err(eyre::eyre!(
                "DKG output not found. Run 'kora dkg' first to generate threshold shares."
            ));
        }

        let dkg_output = kora_dkg::DkgOutput::load(&config.data_dir)?;
        tracing::info!(share_index = dkg_output.share_index, "Loaded DKG output");

        let scheme = load_threshold_scheme(&config.data_dir)
            .map_err(|e| eyre::eyre!("Failed to load threshold scheme: {}", e))?;
        tracing::info!("Loaded threshold signing scheme");

        let mut secondary_participants = Vec::new();
        if let Some(ref peers_path) = args.peers {
            let peers = load_peers(peers_path)?;
            config.network.bootstrap_peers = format_bootstrappers(&peers.bootstrappers);
            tracing::info!(
                bootstrap_peers = config.network.bootstrap_peers.len(),
                "Loaded bootstrap peers from peers.json"
            );

            // Cross-validate: DKG participant count must match peers.json
            let dkg_n = dkg_output.participants;
            let peers_n = peers.participants.len();
            if dkg_n != peers_n {
                return Err(eyre::eyre!(
                    "DKG output has {} participants but peers.json has {} participants. \
                     Ensure both files are from the same DKG ceremony.",
                    dkg_n,
                    peers_n
                ));
            }

            secondary_participants = peers.secondary_participants;
        }

        let genesis_path = config.data_dir.join("genesis.json");
        let bootstrap = BootstrapConfig::load(&genesis_path)
            .map_err(|e| eyre::eyre!("Failed to load genesis: {}", e))?;
        tracing::info!(allocations = bootstrap.genesis_alloc.len(), "Loaded genesis configuration");

        if bootstrap.chain_id != config.chain_id {
            return Err(eyre::eyre!(
                "genesis.json chain_id ({}) does not match node chain_id ({})",
                bootstrap.chain_id,
                config.chain_id
            ));
        }

        let rpc_addr: std::net::SocketAddr = config.rpc.http_addr.parse().map_err(|err| {
            eyre::eyre!("invalid rpc.http_addr '{}': {}", config.rpc.http_addr, err)
        })?;
        let validator_count = u32::try_from(dkg_output.participants).map_err(|_| {
            eyre::eyre!("DKG participant count {} exceeds u32::MAX", dkg_output.participants)
        })?;
        if validator_count == 0 {
            return Err(eyre::eyre!("DKG participant count must be non-zero"));
        }
        let validator_index = dkg_output.share_index;
        if validator_index >= validator_count {
            return Err(eyre::eyre!(
                "DKG share_index ({validator_index}) must be less than participant count ({validator_count})"
            ));
        }

        let quorum = N3f1::quorum(validator_count as usize);
        tracing::info!(
            validator_count = validator_count,
            quorum = quorum,
            max_faulty = validator_count - quorum,
            "Consensus requires {} of {} validators active (N3f1 BFT)",
            quorum,
            validator_count
        );

        let node_state =
            NodeState::with_validator_count(config.chain_id, validator_index, validator_count);

        let metrics_addr: std::net::SocketAddr = args.metrics_addr.parse().map_err(|err| {
            eyre::eyre!("invalid --metrics-addr '{}': {}", args.metrics_addr, err)
        })?;
        let runner = ProductionRunner::new(scheme, config.chain_id, bootstrap)
            .with_rpc(node_state, rpc_addr)
            .with_metrics_addr(metrics_addr)
            .with_secondary_peers(secondary_participants);

        runner.run_standalone(config).map_err(|e| eyre::eyre!("Runner failed: {}", e.0))
    }

    fn run_secondary(&self, args: &SecondaryArgs) -> eyre::Result<()> {
        use commonware_p2p::{Manager, TrackedPeers};
        use commonware_runtime::{Clock as _, Metrics as _, Runner, Spawner};
        use commonware_utils::ordered::Set;
        use kora_transport::NetworkConfigExt;

        let mut config = self.load_config()?;
        let peers = load_peers(&args.peers)?;
        config.network.bootstrap_peers = format_bootstrappers(&peers.bootstrappers);

        let identity_key = config.validator_key()?;
        let my_pk = commonware_cryptography::Signer::public_key(&identity_key);
        if !peers.secondary_participants.contains(&my_pk) {
            return Err(eyre::eyre!(
                "secondary identity is not listed in peers.json secondary_participants"
            ));
        }

        let validator_count = peers.participants.len();
        let secondary_count = peers.secondary_participants.len();

        // Parse and validate addresses early so we fail before starting the runtime.
        let metrics_addr: std::net::SocketAddr = args.metrics_addr.parse().map_err(|err| {
            eyre::eyre!("invalid --metrics-addr '{}': {}", args.metrics_addr, err)
        })?;
        let _rpc_addr: std::net::SocketAddr = args
            .rpc_addr
            .parse()
            .map_err(|err| eyre::eyre!("invalid --rpc-addr '{}': {}", args.rpc_addr, err))?;

        tracing::info!(
            chain_id = config.chain_id,
            bootstrap_peers = config.network.bootstrap_peers.len(),
            secondary_peers = secondary_count,
            "Starting secondary peer"
        );
        tracing::warn!("Secondary node is in follower mode - read-only RPC not yet implemented");

        let runtime_dir = runtime_storage_directory(&config.data_dir);
        tracing::info!(
            runtime_dir = %runtime_dir.display(),
            worker_threads = config.worker_threads,
            "Starting Commonware runtime"
        );
        let executor = commonware_runtime::tokio::Runner::new(
            commonware_runtime::tokio::Config::default()
                .with_storage_directory(runtime_dir)
                .with_worker_threads(config.worker_threads),
        );
        executor.start(|context| async move {
            let mut transport = config
                .network
                .build_local_transport(identity_key, context.child("transport"))
                .map_err(|e| eyre::eyre!("failed to build transport: {}", e))?;

            transport
                .oracle
                .track(
                    0,
                    TrackedPeers::new(
                        Set::from_iter_dedup(peers.participants),
                        Set::from_iter_dedup(peers.secondary_participants),
                    ),
                );

            tracing::info!("secondary peer joined network");

            // Spawn a metrics server so Prometheus can scrape this node.
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
                        tracing::error!(addr = %metrics_addr, error = %e, "Failed to bind metrics server");
                        return;
                    }
                };

                tracing::info!(addr = %metrics_addr, "Starting metrics server");
                if let Err(e) = axum::serve(listener, app).await {
                    tracing::error!(error = %e, "Metrics server error");
                }
            });

            // Spawn periodic health logging.
            context.child("health").shared(true).spawn(move |ctx| async move {
                let interval = std::time::Duration::from_secs(30);
                loop {
                    ctx.sleep(interval).await;
                    tracing::info!(
                        validators = validator_count,
                        secondary_peers = secondary_count,
                        "Secondary node health: connected to P2P network"
                    );
                }
            });

            // Block until shutdown signal (SIGTERM / SIGINT / Ctrl-C).
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }
            tracing::info!("Received shutdown signal, stopping secondary node...");
            Ok::<(), eyre::Error>(())
        })
    }

    fn run_legacy(&self) -> eyre::Result<()> {
        let config = self.load_config()?;

        tracing::info!(chain_id = config.chain_id, "Starting node (legacy mode)");
        tracing::debug!(?config, "Full configuration");

        LegacyNodeService::new(config).run()
    }
}

#[derive(Debug)]
struct PeersInfo {
    participants: Vec<commonware_cryptography::ed25519::PublicKey>,
    secondary_participants: Vec<commonware_cryptography::ed25519::PublicKey>,
    bootstrappers: Vec<(commonware_cryptography::ed25519::PublicKey, String)>,
}

fn format_bootstrappers(
    bootstrappers: &[(commonware_cryptography::ed25519::PublicKey, String)],
) -> Vec<String> {
    bootstrappers
        .iter()
        .map(|(pk, addr)| format!("{}@{}", hex::encode(pk.as_ref()), addr))
        .collect()
}

/// Load peers configuration from a JSON file.
///
/// Accepts peers.json files with either "quorum" (new format) or "threshold"
/// (legacy format) key -- both are ignored at runtime since the quorum is
/// always computed from the validator count via N3f1.
fn load_peers(path: &PathBuf) -> eyre::Result<PeersInfo> {
    use commonware_codec::ReadExt;

    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let participants_hex: Vec<String> = json["participants"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("missing participants"))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let participants = parse_public_keys(&participants_hex)?;

    let secondary_participants_hex: Vec<String> = json["secondary_participants"]
        .as_array()
        .map(|participants| {
            participants.iter().filter_map(|v| v.as_str().map(String::from)).collect()
        })
        .unwrap_or_default();
    let secondary_participants = parse_public_keys(&secondary_participants_hex)?;

    let bootstrappers_obj =
        json["bootstrappers"].as_object().ok_or_else(|| eyre::eyre!("missing bootstrappers"))?;

    let mut bootstrappers = Vec::new();
    for (pk_hex, addr) in bootstrappers_obj {
        let bytes = hex::decode(pk_hex)?;
        let pk = commonware_cryptography::ed25519::PublicKey::read(&mut bytes.as_slice())?;
        let addr_str = addr.as_str().ok_or_else(|| eyre::eyre!("invalid address"))?;
        bootstrappers.push((pk, addr_str.to_string()));
    }

    Ok(PeersInfo { participants, secondary_participants, bootstrappers })
}

fn parse_public_keys(
    keys: &[String],
) -> eyre::Result<Vec<commonware_cryptography::ed25519::PublicKey>> {
    use commonware_codec::ReadExt;

    let mut public_keys = Vec::with_capacity(keys.len());
    for pk_hex in keys {
        let bytes = hex::decode(pk_hex)?;
        let pk = commonware_cryptography::ed25519::PublicKey::read(&mut bytes.as_slice())?;
        public_keys.push(pk);
    }

    Ok(public_keys)
}
