//! Generates initial configuration for a Kora devnet.

use std::{collections::BTreeMap, fs, io::Write as _, path::PathBuf};

use alloy_primitives::{Address, keccak256};
use clap::Args;
use commonware_codec::{Encode, ReadExt as _};
use commonware_cryptography::{Signer, ed25519};
use commonware_utils::{Faults, N3f1};
use eyre::{Result, WrapErr};
use k256::ecdsa::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const GENESIS_BALANCE: &str = "1000000000000000000000000";
const LOADGEN_ACCOUNT_COUNT: u8 = 50;

#[derive(Args, Debug)]
pub(crate) struct SetupArgs {
    #[arg(long, default_value = "4")]
    pub validators: usize,

    #[arg(long, default_value = "0")]
    pub secondary_peers: usize,

    #[arg(long, default_value = "1337")]
    pub chain_id: u64,

    #[arg(long, default_value = "/shared")]
    pub output_dir: PathBuf,

    #[arg(long, default_value = "30303")]
    pub base_port: u16,
}

#[derive(Serialize, Deserialize)]
struct PeersConfig {
    validators: usize,
    /// Minimum active validators required for consensus (N3f1 quorum).
    /// This value is computed automatically from the validator count and
    /// cannot be overridden -- it is persisted here for operator reference.
    quorum: u32,
    participants: Vec<String>,
    secondary_participants: Vec<String>,
    bootstrappers: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct GenesisConfig {
    chain_id: u64,
    timestamp: u64,
    allocations: Vec<GenesisAllocation>,
}

#[derive(Serialize, Deserialize)]
struct GenesisAllocation {
    address: String,
    balance: String,
}

#[derive(Serialize, Deserialize)]
struct NodeSetupConfig {
    validator_index: usize,
    public_key: String,
    port: u16,
}

fn funded_allocation(address: impl Into<String>) -> GenesisAllocation {
    GenesisAllocation { address: address.into(), balance: GENESIS_BALANCE.to_string() }
}

fn loadgen_address(seed: u8) -> Address {
    let mut secret = [0u8; 32];
    secret[31] = seed;
    let key = SigningKey::from_bytes((&secret).into())
        .expect("loadgen seed should produce valid secp256k1 key");
    let encoded = key.verifying_key().to_encoded_point(false);
    let pubkey = encoded.as_bytes();
    let hash = keccak256(&pubkey[1..]);
    Address::from_slice(&hash[12..])
}

fn funded_loadgen_allocations() -> impl Iterator<Item = GenesisAllocation> {
    (1..=LOADGEN_ACCOUNT_COUNT).map(|seed| funded_allocation(loadgen_address(seed).to_string()))
}

fn private_key_from_seed(seed: [u8; 32]) -> ed25519::PrivateKey {
    ed25519::PrivateKey::read(&mut seed.as_slice()).expect("32-byte ed25519 seed should decode")
}

pub(crate) fn run(args: SetupArgs) -> Result<()> {
    let quorum = N3f1::quorum(args.validators);
    tracing::info!(
        validators = args.validators,
        quorum = quorum,
        max_faulty = args.validators as u32 - quorum,
        chain_id = args.chain_id,
        "Generating devnet configuration (quorum determined by N3f1: need {} of {} validators)",
        quorum,
        args.validators
    );

    fs::create_dir_all(&args.output_dir).wrap_err("Failed to create output directory")?;

    let mut participants = Vec::with_capacity(args.validators);
    let mut secondary_participants = Vec::with_capacity(args.secondary_peers);
    let mut bootstrappers = BTreeMap::new();

    for i in 0..args.validators {
        let node_dir = args.output_dir.join(format!("node{}", i));
        fs::create_dir_all(&node_dir)
            .wrap_err_with(|| format!("Failed to create node{} dir", i))?;

        let key_path = node_dir.join("validator.key");
        let key = if key_path.exists() {
            tracing::info!(node = i, "Loading existing identity key");
            let bytes = fs::read(&key_path)?;
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            private_key_from_seed(seed)
        } else {
            tracing::info!(node = i, "Generating new identity key");
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            write_secret_file(&key_path, &seed)?;
            private_key_from_seed(seed)
        };

        let public_key = key.public_key();
        let pk_hex = hex::encode(Encode::encode(&public_key));

        participants.push(pk_hex.clone());

        let hostname = format!("node{}:{}", i, args.base_port);
        bootstrappers.insert(pk_hex.clone(), hostname);

        let node_config =
            NodeSetupConfig { validator_index: i, public_key: pk_hex, port: args.base_port };
        let config_path = node_dir.join("setup.json");
        fs::write(&config_path, serde_json::to_string_pretty(&node_config)?)?;

        tracing::info!(node = i, path = ?key_path, "Wrote identity key");
    }

    for i in 0..args.secondary_peers {
        let node_dir = args.output_dir.join(format!("secondary{}", i));
        fs::create_dir_all(&node_dir)
            .wrap_err_with(|| format!("Failed to create secondary{} dir", i))?;

        let key_path = node_dir.join("validator.key");
        let key = if key_path.exists() {
            tracing::info!(node = i, "Loading existing secondary identity key");
            let bytes = fs::read(&key_path)?;
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            private_key_from_seed(seed)
        } else {
            tracing::info!(node = i, "Generating new secondary identity key");
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            write_secret_file(&key_path, &seed)?;
            private_key_from_seed(seed)
        };

        let public_key = key.public_key();
        let pk_hex = hex::encode(Encode::encode(&public_key));
        secondary_participants.push(pk_hex.clone());

        let node_config =
            NodeSetupConfig { validator_index: i, public_key: pk_hex, port: args.base_port };
        let config_path = node_dir.join("setup.json");
        fs::write(&config_path, serde_json::to_string_pretty(&node_config)?)?;

        tracing::info!(node = i, path = ?key_path, "Wrote secondary identity key");
    }

    let peers = PeersConfig {
        validators: args.validators,
        quorum,
        participants,
        secondary_participants,
        bootstrappers,
    };
    let peers_path = args.output_dir.join("peers.json");
    fs::write(&peers_path, serde_json::to_string_pretty(&peers)?)?;
    tracing::info!(path = ?peers_path, "Wrote peers configuration");

    let mut allocations = vec![
        funded_allocation("0x0000000000000000000000000000000000000001"),
        funded_allocation("0xEb1Ba7Fc58b3416361a0EE07d140c91410c0AA8c"),
        funded_allocation("0xa883208a74152107475a3Fa6b0c21121894B647F"),
        funded_allocation("0x105be5081ceba05be11976150abc277ee365fc3f"),
        funded_allocation("0x30b68d56AE9173566055a69ee7cCB0E755B6a201"),
        funded_allocation("0xDdE169289B51C512268D0b11EE2b15160b1e1793"),
        funded_allocation("0xde738C4084dDE5083A7959235Fd230e27eAFC63B"),
    ];
    tracing::warn!(
        loadgen_accounts = LOADGEN_ACCOUNT_COUNT,
        "Genesis includes {} accounts with INSECURE deterministic keys \
         (private key = 0x01..0x{:02x}). These keys are publicly known. \
         DO NOT use this genesis on a network with real economic value.",
        LOADGEN_ACCOUNT_COUNT,
        LOADGEN_ACCOUNT_COUNT
    );
    allocations.extend(funded_loadgen_allocations());

    let genesis = GenesisConfig { chain_id: args.chain_id, timestamp: 0, allocations };
    let genesis_path = args.output_dir.join("genesis.json");
    fs::write(&genesis_path, serde_json::to_string_pretty(&genesis)?)?;
    tracing::info!(path = ?genesis_path, "Wrote genesis configuration");

    tracing::info!("Setup complete");
    tracing::info!(
        "  Validators:    {} | Quorum (N3f1): {} (tolerates {} faults)",
        args.validators,
        quorum,
        args.validators as u32 - quorum
    );
    tracing::info!("  Secondary:     {}", args.secondary_peers);
    tracing::info!("  Chain ID:      {}", args.chain_id);

    Ok(())
}

/// Write `data` to `path` with mode `0600` so key material is never world-readable.
fn write_secret_file(path: &std::path::Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .wrap_err_with(|| format!("Failed to create secret file {}", path.display()))?;
    f.write_all(data).wrap_err_with(|| format!("Failed to write secret file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOADGEN_ADDRESS_FIXTURES: &[(u8, &str)] = &[
        (1, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"),
        (2, "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF"),
        (3, "0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69"),
    ];

    #[test]
    fn loadgen_address_matches_seed_fixtures() {
        for &(seed, expected) in LOADGEN_ADDRESS_FIXTURES {
            assert_eq!(loadgen_address(seed).to_string(), expected);
        }
    }

    #[test]
    fn funded_loadgen_allocations_include_expected_seed_addresses() {
        let allocations: Vec<_> = funded_loadgen_allocations().collect();

        assert_eq!(allocations.len(), usize::from(LOADGEN_ACCOUNT_COUNT));
        for &(_, expected) in LOADGEN_ADDRESS_FIXTURES {
            let allocation = allocations
                .iter()
                .find(|allocation| allocation.address == expected)
                .expect("expected loadgen seed address to be funded");
            assert_eq!(allocation.balance, GENESIS_BALANCE);
        }
    }
}
