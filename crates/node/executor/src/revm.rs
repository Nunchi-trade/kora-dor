//! REVM-based block executor.

use std::collections::BTreeMap;

use alloy_consensus::Header;
use alloy_primitives::{B256, Bytes, U256, keccak256};
use kora_qmdb::{AccountUpdate, ChangeSet};
use kora_traits::StateDb;
use revm::{
    Context, DatabaseCommit as _, ExecuteEvm, Journal, MainBuilder,
    bytecode::Bytecode,
    context::{
        block::BlockEnv,
        result::{ExecutionResult, Output},
    },
    context_interface::{
        ContextSetters,
        block::BlobExcessGasAndPrice,
        transaction::{AccessList, AccessListItem},
    },
    database::State,
    primitives::{TxKind, hardfork::SpecId},
    state::{EvmState, EvmStorageSlot},
};
use tracing::{debug, warn};

use crate::{
    BlockContext, BlockExecutor, ExecutionConfig, ExecutionError, ExecutionOutcome,
    ExecutionReceipt, ParentBlock, StateDbAdapter,
};

/// REVM-based block executor.
///
/// This executor uses REVM to execute EVM transactions against a state database.
/// The actual EVM execution is performed via the REVM handler traits.
#[derive(Clone, Debug)]
pub struct RevmExecutor {
    /// Execution configuration.
    config: ExecutionConfig,
}

impl RevmExecutor {
    /// Create a new REVM executor with the given chain ID.
    #[must_use]
    pub const fn new(chain_id: u64) -> Self {
        Self { config: ExecutionConfig::new(chain_id) }
    }

    /// Create a new REVM executor with full configuration.
    #[must_use]
    pub const fn with_config(config: ExecutionConfig) -> Self {
        Self { config }
    }

    /// Get the chain ID.
    pub const fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Get the spec ID.
    pub const fn spec_id(&self) -> SpecId {
        self.config.spec_id
    }

    /// Validate a header against its parent.
    pub fn validate_header_against_parent(
        &self,
        header: &Header,
        parent: &ParentBlock,
    ) -> Result<(), ExecutionError> {
        if header.number != parent.number + 1 {
            return Err(ExecutionError::BlockValidation(format!(
                "block number not sequential: expected {}, got {}",
                parent.number + 1,
                header.number
            )));
        }

        if header.parent_hash != parent.hash {
            return Err(ExecutionError::BlockValidation(format!(
                "parent hash mismatch: expected {}, got {}",
                parent.hash, header.parent_hash
            )));
        }

        if header.timestamp < parent.timestamp {
            return Err(ExecutionError::BlockValidation(format!(
                "timestamp moved backwards: parent {}, current {}",
                parent.timestamp, header.timestamp
            )));
        }

        self.validate_gas_limit(header.gas_limit, parent.gas_limit)?;

        if let Some(parent_base_fee) = parent.base_fee_per_gas {
            self.validate_base_fee(header, parent_base_fee, parent.gas_used, parent.gas_limit)?;
        }

        Ok(())
    }

    fn validate_gas_limit(
        &self,
        gas_limit: u64,
        parent_gas_limit: u64,
    ) -> Result<(), ExecutionError> {
        let bounds = &self.config.gas_limit_bounds;

        if gas_limit < bounds.min {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} below minimum {}",
                gas_limit, bounds.min
            )));
        }

        if gas_limit > bounds.max {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} above maximum {}",
                gas_limit, bounds.max
            )));
        }

        let max_delta = parent_gas_limit / bounds.max_delta_divisor;
        let diff = gas_limit.abs_diff(parent_gas_limit);

        if diff >= max_delta {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit change {} exceeds maximum delta {}",
                diff, max_delta
            )));
        }

        Ok(())
    }

    fn validate_base_fee(
        &self,
        header: &Header,
        parent_base_fee: u64,
        parent_gas_used: u64,
        parent_gas_limit: u64,
    ) -> Result<(), ExecutionError> {
        let expected = calculate_base_fee(
            parent_base_fee,
            parent_gas_used,
            parent_gas_limit,
            &self.config.base_fee_params,
        );

        let actual = header.base_fee_per_gas.ok_or_else(|| {
            ExecutionError::BlockValidation("missing base fee in EIP-1559 block".to_string())
        })?;

        if actual != expected {
            return Err(ExecutionError::BlockValidation(format!(
                "base fee mismatch: expected {}, got {}",
                expected, actual
            )));
        }

        Ok(())
    }
}

impl Default for RevmExecutor {
    fn default() -> Self {
        Self::new(1)
    }
}

/// Parameters for a read-only EVM call (used by `eth_call`/`eth_estimateGas`).
///
/// Mirrors the JSON-RPC `CallRequest` shape but with non-optional defaults
/// resolved, so the executor does not depend on rpc-layer types.
#[derive(Clone, Debug, Default)]
pub struct CallParams {
    /// Caller address (`from`). Defaults to zero address if unspecified.
    pub from: alloy_primitives::Address,
    /// Recipient address. `None` is contract creation (CREATE).
    pub to: Option<alloy_primitives::Address>,
    /// Value to transfer.
    pub value: U256,
    /// Calldata (or initcode for CREATE).
    pub data: Bytes,
    /// Gas limit. `None` falls back to the block gas limit.
    pub gas_limit: Option<u64>,
    /// Effective gas price.
    pub gas_price: u128,
    /// Caller nonce.
    pub nonce: u64,
}

impl RevmExecutor {
    /// Run a read-only call simulation against `state`.
    ///
    /// Mirrors [`BlockExecutor::execute`] for one transaction but discards
    /// the resulting state changes — used to serve `eth_call` and as a
    /// primitive for [`Self::estimate_gas`].
    ///
    /// # Errors
    ///
    /// - [`ExecutionError::Revert`] with the revert output if the call reverted.
    /// - [`ExecutionError::TxExecution`] for halts and revm-internal errors.
    /// - [`ExecutionError::InvalidTx`] if the request fails to build a valid
    ///   `TxEnv` (bad gas/value combination, etc.).
    pub fn simulate_call<S: kora_traits::StateDbRead>(
        &self,
        state: &S,
        params: CallParams,
        context: &BlockContext,
    ) -> Result<Bytes, ExecutionError> {
        let adapter = StateDbAdapter::new(state.clone(), context.recent_block_hashes.clone());
        let db = State::builder().with_database_ref(adapter).build();

        type Db<S> = State<revm::database::WrapDatabaseRef<StateDbAdapter<S>>>;
        let ctx: Context<BlockEnv, _, _, Db<S>, Journal<Db<S>>, ()> =
            Context::new(db, self.config.spec_id);
        let ctx = ctx
            .modify_cfg_chained(|cfg| {
                cfg.chain_id = self.config.chain_id;
                cfg.disable_nonce_check = true;
                cfg.disable_balance_check = true;
                cfg.disable_base_fee = true;
            })
            .modify_block_chained(|blk: &mut BlockEnv| {
                blk.number = U256::from(context.header.number);
                blk.timestamp = U256::from(context.header.timestamp);
                blk.beneficiary = context.header.beneficiary;
                blk.gas_limit = context.header.gas_limit;
                blk.basefee = context.header.base_fee_per_gas.unwrap_or_default();
                blk.prevrandao = Some(context.prevrandao);
                if let Some(blob_base_fee) = context.blob_base_fee {
                    blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice {
                        excess_blob_gas: 0,
                        blob_gasprice: blob_base_fee,
                    });
                }
            });

        let mut evm = ctx.build_mainnet();

        let tx_env =
            call_params_to_tx_env(&params, self.config.chain_id, context.header.gas_limit)?;
        evm.set_tx(tx_env);

        let result_and_state =
            evm.replay().map_err(|e| ExecutionError::TxExecution(format!("{:?}", e)))?;

        match result_and_state.result {
            ExecutionResult::Success { output, .. } => match output {
                Output::Call(bytes) => Ok(bytes),
                Output::Create(bytes, _) => Ok(bytes),
            },
            ExecutionResult::Revert { output, .. } => Err(ExecutionError::Revert(output)),
            ExecutionResult::Halt { reason, .. } => {
                Err(ExecutionError::TxExecution(format!("halt: {:?}", reason)))
            }
        }
    }

    /// Estimate gas via binary search over [`Self::simulate_call`].
    ///
    /// Confirms the call succeeds at the upper bound (request gas or block
    /// gas limit), then binary-searches for the minimum gas at which the
    /// call still succeeds. Bounded to 25 iterations (≈log2(30M)).
    ///
    /// # Errors
    ///
    /// Same as [`Self::simulate_call`] — propagates a revert/halt at the
    /// upper bound; otherwise returns the converged minimum.
    pub fn estimate_gas<S: kora_traits::StateDbRead>(
        &self,
        state: &S,
        mut params: CallParams,
        context: &BlockContext,
    ) -> Result<u64, ExecutionError> {
        let upper =
            params.gas_limit.unwrap_or(context.header.gas_limit).min(context.header.gas_limit);

        // Confirm the call succeeds at the upper bound.
        params.gas_limit = Some(upper);
        self.simulate_call(state, params.clone(), context)?;

        let mut lo = 21_000u64;
        let mut hi = upper;
        let mut best = upper;
        let mut iters = 0u32;
        while lo + 1 < hi && iters < 25 {
            iters += 1;
            let mid = lo + (hi - lo) / 2;
            params.gas_limit = Some(mid);
            match self.simulate_call(state, params.clone(), context) {
                Ok(_) => {
                    best = mid;
                    hi = mid;
                }
                Err(_) => {
                    lo = mid;
                }
            }
        }
        Ok(best)
    }
}

/// Build a revm [`revm::context::TxEnv`] from a [`CallParams`].
///
/// Differs from [`decode_tx_env`] in that there is no signature to recover —
/// caller comes from `params.from` directly.
fn call_params_to_tx_env(
    params: &CallParams,
    chain_id: u64,
    default_gas_limit: u64,
) -> Result<revm::context::TxEnv, ExecutionError> {
    let kind = params.to.map_or(TxKind::Create, TxKind::Call);
    let gas_limit = params.gas_limit.unwrap_or(default_gas_limit);

    revm::context::TxEnv::builder()
        .caller(params.from)
        .gas_limit(gas_limit)
        .gas_price(params.gas_price)
        .value(params.value)
        .data(params.data.clone())
        .nonce(params.nonce)
        .chain_id(Some(chain_id))
        .kind(kind)
        .build()
        .map_err(|e| ExecutionError::InvalidTx(format!("build call tx env: {:?}", e)))
}

/// Calculate the expected base fee for the next block (EIP-1559).
pub fn calculate_base_fee(
    parent_base_fee: u64,
    parent_gas_used: u64,
    parent_gas_limit: u64,
    params: &crate::BaseFeeParams,
) -> u64 {
    let parent_gas_target = parent_gas_limit / params.elasticity_multiplier;

    if parent_gas_used == parent_gas_target {
        return parent_base_fee;
    }

    if parent_gas_used > parent_gas_target {
        let gas_used_delta = parent_gas_used - parent_gas_target;
        let base_fee_delta = (parent_base_fee as u128).saturating_mul(gas_used_delta as u128)
            / (parent_gas_target as u128)
            / (params.max_change_denominator as u128);
        let base_fee_delta = base_fee_delta.max(1) as u64;
        parent_base_fee.saturating_add(base_fee_delta)
    } else {
        let gas_used_delta = parent_gas_target - parent_gas_used;
        let base_fee_delta = (parent_base_fee as u128).saturating_mul(gas_used_delta as u128)
            / (parent_gas_target as u128)
            / (params.max_change_denominator as u128);
        parent_base_fee.saturating_sub(base_fee_delta as u64)
    }
}

impl<S: StateDb> BlockExecutor<S> for RevmExecutor {
    type Tx = Bytes;

    fn execute(
        &self,
        state: &S,
        context: &BlockContext,
        txs: &[Self::Tx],
    ) -> Result<ExecutionOutcome, ExecutionError> {
        // --- pre-execution hook ---
        let pre_changes = self.pre_execute(context, state)?;

        let mut outcome = ExecutionOutcome::new();
        outcome.changes.merge(pre_changes);

        // Empty-block short circuit: skip EVM context construction,
        // state-db adapter cloning, and journal allocation when there
        // are no transactions to execute.  This is the common case on
        // low-load networks and avoids measurable setup overhead per
        // empty block.
        if !txs.is_empty() {
            let adapter = StateDbAdapter::new(state.clone(), context.recent_block_hashes.clone());

            let db = State::builder().with_database_ref(adapter).build();

            type Db<S> = State<revm::database::WrapDatabaseRef<StateDbAdapter<S>>>;
            let ctx: Context<BlockEnv, _, _, Db<S>, Journal<Db<S>>, ()> =
                Context::new(db, self.config.spec_id);
            let ctx = ctx
                .modify_cfg_chained(|cfg| {
                    cfg.chain_id = self.config.chain_id;
                })
                .modify_block_chained(|blk: &mut BlockEnv| {
                    blk.number = U256::from(context.header.number);
                    blk.timestamp = U256::from(context.header.timestamp);
                    blk.beneficiary = context.header.beneficiary;
                    blk.gas_limit = context.header.gas_limit;
                    blk.basefee = context.header.base_fee_per_gas.unwrap_or_default();
                    blk.prevrandao = Some(context.prevrandao);
                    if let Some(blob_base_fee) = context.blob_base_fee {
                        blk.blob_excess_gas_and_price = Some(BlobExcessGasAndPrice {
                            excess_blob_gas: 0,
                            blob_gasprice: blob_base_fee,
                        });
                    }
                });

            let mut evm = ctx.build_mainnet();
            let mut cumulative_gas = 0u64;

            for tx_bytes in txs {
                let tx_hash = keccak256(tx_bytes);

                let tx_env = match decode_tx_env(tx_bytes, self.config.chain_id) {
                    Ok(env) => env,
                    Err(e) => {
                        warn!(hash = ?tx_hash, error = %e, "skipping undecodable transaction");
                        outcome.receipts.push(build_skipped_receipt(tx_hash, cumulative_gas));
                        continue;
                    }
                };

                // Enforce block gas limit: we `break` (not `continue`) because Ethereum
                // semantics stop inclusion at the gas limit — remaining txs are simply not
                // included. Unlike decode failures above, gas-limited txs get no placeholder
                // receipts, so `receipts.len()` may be less than `txs.len()`.
                let tx_gas_limit = tx_env.gas_limit;
                if cumulative_gas.saturating_add(tx_gas_limit) > context.header.gas_limit {
                    break;
                }
                evm.set_tx(tx_env);

                let result_and_state = match evm.replay() {
                    Ok(result) => result,
                    Err(e) => {
                        debug!(hash = ?tx_hash, error = ?e, "skipping unexecutable transaction");
                        outcome.receipts.push(build_skipped_receipt(tx_hash, cumulative_gas));
                        continue;
                    }
                };

                let gas_used = result_and_state.result.tx_gas_used();
                cumulative_gas = cumulative_gas.saturating_add(gas_used);

                let receipt =
                    build_receipt(&result_and_state.result, tx_hash, gas_used, cumulative_gas);
                outcome.receipts.push(receipt);

                let evm_state = result_and_state.state;

                // Collect addresses that were selfdestructed in this transaction.
                // Their storage entries in QMDB become orphaned and need future GC.
                for (address, account) in &evm_state {
                    if account.is_selfdestructed() {
                        outcome.selfdestructed_addresses.push(*address);
                    }
                }

                // Extract changes by reference to avoid cloning the entire
                // EvmState HashMap.  The original is then moved into
                // `db.commit()` which consumes it.
                let changes = extract_changes(&evm_state);
                evm.ctx.modify_db(|db| db.commit(evm_state));

                // Short-circuit: if the commit failed, abort the block
                // immediately rather than executing more transactions against
                // inconsistent state.  Previously this check only ran after the
                // entire block, allowing subsequent transactions to produce
                // incorrect receipts (issue #022).
                if state.take_commit_failure() {
                    return Err(ExecutionError::StateCommit);
                }

                outcome.changes.merge(changes);
            }

            outcome.gas_used = cumulative_gas;
        }

        // --- post-execution hook ---
        let post_changes = self.post_execute(context, state, &outcome.receipts)?;
        outcome.changes.merge(post_changes);

        Ok(outcome)
    }

    fn validate_header(&self, header: &Header) -> Result<(), ExecutionError> {
        if header.gas_limit < self.config.gas_limit_bounds.min {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} below minimum {}",
                header.gas_limit, self.config.gas_limit_bounds.min
            )));
        }

        if header.gas_limit > self.config.gas_limit_bounds.max {
            return Err(ExecutionError::BlockValidation(format!(
                "gas limit {} above maximum {}",
                header.gas_limit, self.config.gas_limit_bounds.max
            )));
        }

        Ok(())
    }
}

/// Decode transaction bytes into a REVM TxEnv.
///
/// Currently supports basic transaction decoding for all Ethereum transaction types.
fn decode_tx_env(tx_bytes: &Bytes, _chain_id: u64) -> Result<revm::context::TxEnv, ExecutionError> {
    use alloy_consensus::TxEnvelope;
    use alloy_eips::eip2718::Decodable2718 as _;

    // Decode both legacy RLP transactions and typed EIP-2718 envelopes.
    let envelope = TxEnvelope::decode_2718(&mut tx_bytes.as_ref())
        .map_err(|e| ExecutionError::TxDecode(format!("{}", e)))?;

    // Build TxEnv using the builder pattern
    let mut builder = revm::context::TxEnv::builder();

    match &envelope {
        TxEnvelope::Legacy(signed) => {
            let tx = signed.tx();
            let caller = signed.recover_signer().map_err(|e| {
                ExecutionError::TxDecode(format!("failed to recover signer: {}", e))
            })?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.gas_price)
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(tx.chain_id)
                .kind(convert_tx_kind(tx.to));
        }
        TxEnvelope::Eip2930(signed) => {
            let tx = signed.tx();
            let caller = signed.recover_signer().map_err(|e| {
                ExecutionError::TxDecode(format!("failed to recover signer: {}", e))
            })?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.gas_price)
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(convert_tx_kind(tx.to))
                .access_list(convert_access_list(&tx.access_list));
        }
        TxEnvelope::Eip1559(signed) => {
            let tx = signed.tx();
            let caller = signed.recover_signer().map_err(|e| {
                ExecutionError::TxDecode(format!("failed to recover signer: {}", e))
            })?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.max_fee_per_gas)
                .gas_priority_fee(Some(tx.max_priority_fee_per_gas))
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(convert_tx_kind(tx.to))
                .access_list(convert_access_list(&tx.access_list));
        }
        TxEnvelope::Eip4844(signed) => {
            let tx = signed.tx().tx();
            let caller = signed.recover_signer().map_err(|e| {
                ExecutionError::TxDecode(format!("failed to recover signer: {}", e))
            })?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.max_fee_per_gas)
                .gas_priority_fee(Some(tx.max_priority_fee_per_gas))
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(TxKind::Call(tx.to))
                .access_list(convert_access_list(&tx.access_list))
                .max_fee_per_blob_gas(tx.max_fee_per_blob_gas)
                .blob_hashes(tx.blob_versioned_hashes.clone());
        }
        TxEnvelope::Eip7702(signed) => {
            let tx = signed.tx();
            let caller = signed.recover_signer().map_err(|e| {
                ExecutionError::TxDecode(format!("failed to recover signer: {}", e))
            })?;

            builder = builder
                .caller(caller)
                .gas_limit(tx.gas_limit)
                .gas_price(tx.max_fee_per_gas)
                .gas_priority_fee(Some(tx.max_priority_fee_per_gas))
                .value(tx.value)
                .data(tx.input.clone())
                .nonce(tx.nonce)
                .chain_id(Some(tx.chain_id))
                .kind(TxKind::Call(tx.to))
                .access_list(convert_access_list(&tx.access_list))
                .authorization_list(convert_authorization_list(&tx.authorization_list));
        }
    }

    builder
        .build()
        .map_err(|e| ExecutionError::TxDecode(format!("failed to build tx env: {:?}", e)))
}

/// Convert alloy TxKind to revm TxKind.
const fn convert_tx_kind(kind: alloy_primitives::TxKind) -> TxKind {
    match kind {
        alloy_primitives::TxKind::Call(addr) => TxKind::Call(addr),
        alloy_primitives::TxKind::Create => TxKind::Create,
    }
}

/// Convert alloy AccessList to revm AccessList.
fn convert_access_list(access_list: &alloy_eips::eip2930::AccessList) -> AccessList {
    AccessList(
        access_list
            .iter()
            .map(|item| AccessListItem {
                address: item.address,
                storage_keys: item.storage_keys.clone(),
            })
            .collect(),
    )
}

/// Convert alloy authorization list to revm authorization list.
fn convert_authorization_list(
    auth_list: &[alloy_eips::eip7702::SignedAuthorization],
) -> Vec<
    revm::context_interface::either::Either<
        revm::context_interface::transaction::SignedAuthorization,
        revm::context_interface::transaction::RecoveredAuthorization,
    >,
> {
    use alloy_eips::eip7702::RecoveredAuthority;

    auth_list
        .iter()
        .map(|auth| {
            // Build the inner authorization
            let inner = revm::context_interface::transaction::Authorization {
                chain_id: *auth.chain_id(),
                address: *auth.address(),
                nonce: auth.nonce(),
            };

            // Convert to recovered authorization - use Valid if recovery succeeds, Invalid otherwise
            let recovered_authority = auth
                .recover_authority()
                .map_or(RecoveredAuthority::Invalid, RecoveredAuthority::Valid);

            revm::context_interface::either::Either::Right(
                revm::context_interface::transaction::RecoveredAuthorization::new_unchecked(
                    inner,
                    recovered_authority,
                ),
            )
        })
        .collect()
}

/// Build a placeholder failed receipt for a skipped transaction.
///
/// This preserves index alignment between transactions and receipts so that
/// downstream code (e.g. reporters) can use the receipt index as the
/// transaction index.
const fn build_skipped_receipt(tx_hash: B256, cumulative_gas_used: u64) -> ExecutionReceipt {
    ExecutionReceipt::new(tx_hash, false, 0, cumulative_gas_used, Vec::new(), None)
}

/// Build a transaction receipt from execution result.
fn build_receipt(
    result: &ExecutionResult,
    tx_hash: B256,
    gas_used: u64,
    cumulative_gas_used: u64,
) -> ExecutionReceipt {
    let (success, logs, contract_address) = match result {
        ExecutionResult::Success { logs, output, .. } => {
            let contract_addr = match output {
                Output::Create(_, addr) => *addr,
                Output::Call(_) => None,
            };
            // REVM logs are already alloy_primitives::Log, just clone them
            (true, logs.clone(), contract_addr)
        }
        ExecutionResult::Revert { .. } => (false, Vec::new(), None),
        ExecutionResult::Halt { .. } => (false, Vec::new(), None),
    };

    ExecutionReceipt::new(tx_hash, success, gas_used, cumulative_gas_used, logs, contract_address)
}

/// Extract state changes from REVM execution state.
///
/// Takes the state by reference to avoid a full `HashMap` clone on the
/// hot path: the caller needs the original `EvmState` for `db.commit()`,
/// and the previous code cloned it before extracting changes.  Iterating
/// by reference copies only the individual field values we need, which is
/// dramatically cheaper than cloning the entire nested structure.
fn extract_changes(state: &EvmState) -> ChangeSet {
    let mut changes = ChangeSet::new();

    for (address, account) in state {
        // Skip untouched accounts
        if !account.is_touched() {
            continue;
        }

        // Extract storage changes (skip read-only SLOAD slots)
        let storage: BTreeMap<U256, U256> = account
            .storage
            .iter()
            .filter(|(_, v)| v.is_changed())
            .map(|(k, v): (&U256, &EvmStorageSlot)| (*k, v.present_value()))
            .collect();

        // Extract code if present
        let code = account.info.code.as_ref().map(|c: &Bytecode| c.bytes().to_vec());

        let update = AccountUpdate {
            created: account.is_created(),
            selfdestructed: account.is_selfdestructed(),
            nonce: account.info.nonce,
            balance: account.info.balance,
            code_hash: account.info.code_hash,
            code,
            storage,
        };

        changes.insert(*address, update);
    }

    changes
}

#[cfg(test)]
mod tests {
    use alloy_consensus::{SignableTransaction as _, TxEip1559, TxEnvelope};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Address, Bytes, KECCAK256_EMPTY, Signature, TxKind as AlTxKind, U256};
    use k256::ecdsa::SigningKey;
    use kora_qmdb::ChangeSet;
    use kora_traits::{StateDb, StateDbError, StateDbRead, StateDbWrite};
    use revm::state::Account;
    use sha3::{Digest as _, Keccak256};

    use super::*;
    use crate::GasLimitBounds;

    #[derive(Clone, Debug, Default)]
    struct MockStateDb;

    impl StateDbRead for MockStateDb {
        async fn nonce(&self, _address: &Address) -> Result<u64, StateDbError> {
            Ok(0)
        }
        async fn balance(&self, _address: &Address) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }
        async fn code_hash(&self, _address: &Address) -> Result<B256, StateDbError> {
            Ok(KECCAK256_EMPTY)
        }
        async fn code(&self, _code_hash: &B256) -> Result<Bytes, StateDbError> {
            Ok(Bytes::new())
        }
        async fn storage(&self, _address: &Address, _slot: &U256) -> Result<U256, StateDbError> {
            Ok(U256::ZERO)
        }
    }

    impl StateDbWrite for MockStateDb {
        async fn commit(&self, _changes: ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        async fn compute_root(&self, _changes: &ChangeSet) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
        fn merge_changes(&self, _older: ChangeSet, newer: ChangeSet) -> ChangeSet {
            newer
        }
    }

    impl StateDb for MockStateDb {
        async fn state_root(&self) -> Result<B256, StateDbError> {
            Ok(B256::ZERO)
        }
    }

    /// Helper: build a signed EIP-1559 transfer and return its raw encoded bytes.
    fn build_valid_tx(chain_id: u64, nonce: u64) -> Bytes {
        let mut secret = [0u8; 32];
        secret[31] = 1; // deterministic key
        let key = SigningKey::from_bytes((&secret).into()).expect("valid key");

        let to = Address::repeat_byte(0xab);
        let tx = TxEip1559 {
            chain_id,
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: AlTxKind::Call(to),
            value: U256::ZERO,
            access_list: Default::default(),
            input: Bytes::new(),
        };

        let digest = Keccak256::new_with_prefix(tx.encoded_for_signing());
        let (sig, recid) = key.sign_digest_recoverable(digest).expect("sign tx");
        let signature = Signature::from((sig, recid));
        let signed = tx.into_signed(signature);
        let envelope = TxEnvelope::from(signed);
        let mut raw = Vec::new();
        envelope.encode_2718(&mut raw);
        Bytes::from(raw)
    }

    /// Helper: create a default block context suitable for tests.
    fn test_block_context() -> BlockContext {
        let header =
            Header { number: 1, timestamp: 1000, gas_limit: 30_000_000, ..Header::default() };
        BlockContext::new(header, B256::ZERO, B256::ZERO)
    }

    #[test]
    fn revm_executor_new() {
        let executor = RevmExecutor::new(1);
        assert_eq!(executor.chain_id(), 1);
    }

    #[test]
    fn revm_executor_default() {
        let executor = RevmExecutor::default();
        assert_eq!(executor.chain_id(), 1);
    }

    #[test]
    fn revm_executor_with_config() {
        let config = ExecutionConfig::new(42).with_spec_id(SpecId::PRAGUE);
        let executor = RevmExecutor::with_config(config);
        assert_eq!(executor.chain_id(), 42);
        assert_eq!(executor.spec_id(), SpecId::PRAGUE);
    }

    #[test]
    fn validate_header_gas_limit_bounds() {
        let executor = RevmExecutor::with_config(ExecutionConfig::new(1).with_gas_limit_bounds(
            GasLimitBounds { min: 5000, max: 30_000_000, max_delta_divisor: 1024 },
        ));

        let mut header = Header { gas_limit: 1000, ..Header::default() };
        assert!(
            <RevmExecutor as BlockExecutor<MockStateDb>>::validate_header(&executor, &header)
                .is_err()
        );

        header.gas_limit = 100_000_000;
        assert!(
            <RevmExecutor as BlockExecutor<MockStateDb>>::validate_header(&executor, &header)
                .is_err()
        );

        header.gas_limit = 15_000_000;
        assert!(
            <RevmExecutor as BlockExecutor<MockStateDb>>::validate_header(&executor, &header)
                .is_ok()
        );
    }

    #[test]
    fn validate_header_against_parent_sequential() {
        let executor = RevmExecutor::new(1);

        let parent = ParentBlock {
            hash: B256::repeat_byte(1),
            number: 100,
            timestamp: 1000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            base_fee_per_gas: None,
        };

        let mut header = Header {
            parent_hash: B256::repeat_byte(1),
            number: 101,
            timestamp: 1001,
            gas_limit: 30_000_000,
            ..Header::default()
        };

        assert!(executor.validate_header_against_parent(&header, &parent).is_ok());

        header.number = 103;
        assert!(executor.validate_header_against_parent(&header, &parent).is_err());
    }

    #[test]
    fn validate_header_against_parent_timestamp() {
        let executor = RevmExecutor::new(1);

        let parent = ParentBlock {
            hash: B256::repeat_byte(1),
            number: 100,
            timestamp: 1000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            base_fee_per_gas: None,
        };

        let mut header = Header {
            parent_hash: B256::repeat_byte(1),
            number: 101,
            timestamp: 999,
            gas_limit: 30_000_000,
            ..Header::default()
        };

        assert!(executor.validate_header_against_parent(&header, &parent).is_err());

        header.timestamp = 1000;
        assert!(executor.validate_header_against_parent(&header, &parent).is_ok());
    }

    #[test]
    fn validate_header_against_parent_gas_limit_delta() {
        let executor = RevmExecutor::new(1);

        let parent = ParentBlock {
            hash: B256::repeat_byte(1),
            number: 100,
            timestamp: 1000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            base_fee_per_gas: None,
        };

        let header = Header {
            parent_hash: B256::repeat_byte(1),
            number: 101,
            timestamp: 1001,
            gas_limit: 35_000_000,
            ..Header::default()
        };

        assert!(executor.validate_header_against_parent(&header, &parent).is_err());
    }

    #[test]
    fn calculate_base_fee_at_target() {
        let params = crate::BaseFeeParams::default();
        let base_fee = calculate_base_fee(1000, 15_000_000, 30_000_000, &params);
        assert_eq!(base_fee, 1000);
    }

    #[test]
    fn calculate_base_fee_above_target() {
        let params = crate::BaseFeeParams::default();
        let base_fee = calculate_base_fee(1000, 20_000_000, 30_000_000, &params);
        assert!(base_fee > 1000);
    }

    #[test]
    fn calculate_base_fee_below_target() {
        let params = crate::BaseFeeParams::default();
        let base_fee = calculate_base_fee(1000, 10_000_000, 30_000_000, &params);
        assert!(base_fee < 1000);
    }

    #[test]
    fn build_receipt_success() {
        let result = ExecutionResult::Success {
            reason: revm::context::result::SuccessReason::Stop,
            gas: revm::context::result::ResultGas::default().with_total_gas_spent(21000),
            logs: vec![],
            output: Output::Call(Bytes::new()),
        };

        let receipt = build_receipt(&result, B256::ZERO, 21000, 21000);
        assert!(receipt.success());
        assert_eq!(receipt.gas_used, 21000);
        assert_eq!(receipt.cumulative_gas_used(), 21000);
        assert!(receipt.logs().is_empty());
        assert!(receipt.contract_address.is_none());
    }

    #[test]
    fn build_receipt_revert() {
        let result = ExecutionResult::Revert {
            gas: revm::context::result::ResultGas::default().with_total_gas_spent(21000),
            logs: vec![],
            output: Bytes::new(),
        };

        let receipt = build_receipt(&result, B256::ZERO, 21000, 21000);
        assert!(!receipt.success());
        assert_eq!(receipt.gas_used, 21000);
    }

    #[test]
    fn build_receipt_halt() {
        let result = ExecutionResult::Halt {
            reason: revm::context::result::HaltReason::OutOfGas(
                revm::context::result::OutOfGasError::Basic,
            ),
            gas: revm::context::result::ResultGas::default().with_total_gas_spent(21000),
            logs: vec![],
        };

        let receipt = build_receipt(&result, B256::ZERO, 21000, 21000);
        assert!(!receipt.success());
        assert_eq!(receipt.gas_used, 21000);
    }

    #[test]
    fn extract_changes_empty() {
        let state = EvmState::default();
        let changes = extract_changes(&state);
        assert!(changes.is_empty());
    }

    #[test]
    fn extract_changes_touched_account() {
        use revm::state::AccountStatus;

        let mut state = EvmState::default();

        let mut account = Account::default();
        account.info.nonce = 1;
        account.info.balance = U256::from(1000);
        account.info.code_hash = KECCAK256_EMPTY;
        account.status = AccountStatus::Touched;

        // Add a storage change
        account
            .storage
            .insert(U256::from(1), EvmStorageSlot::new_changed(U256::ZERO, U256::from(42), 0));

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert_eq!(changes.len(), 1);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert_eq!(update.nonce, 1);
        assert_eq!(update.balance, U256::from(1000));
        assert_eq!(update.storage.get(&U256::from(1)), Some(&U256::from(42)));
    }

    #[test]
    fn extract_changes_untouched_skipped() {
        use revm::state::AccountStatus;

        let mut state = EvmState::default();

        let mut account = Account::default();
        account.info.nonce = 1;
        account.info.balance = U256::from(1000);
        account.status = AccountStatus::empty(); // Not touched

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert!(changes.is_empty());
    }

    #[test]
    fn extract_changes_created_account() {
        use revm::state::AccountStatus;

        let mut state = EvmState::default();

        // Created accounts also need to be touched to be processed
        let account = Account {
            status: AccountStatus::Created | AccountStatus::Touched,
            ..Default::default()
        };

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert_eq!(changes.len(), 1);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert!(update.created);
    }

    #[test]
    fn extract_changes_selfdestructed() {
        use revm::state::AccountStatus;

        let mut state = EvmState::default();

        let mut account = Account::default();
        account.info.nonce = 5;
        account.info.balance = U256::from(100);
        // SelfDestructed accounts also need to be touched to be processed
        account.status = AccountStatus::SelfDestructed | AccountStatus::Touched;

        state.insert(Address::ZERO, account);

        let changes = extract_changes(&state);
        assert_eq!(changes.len(), 1);

        let update = changes.accounts.get(&Address::ZERO).unwrap();
        assert!(update.selfdestructed);
    }

    // --- Tests for invalid transaction skipping ---

    #[test]
    fn execute_skips_garbage_bytes() {
        // A block containing only garbage bytes should succeed with a placeholder
        // failed receipt rather than aborting the entire block.
        let executor = RevmExecutor::new(1);
        let state = MockStateDb;
        let context = test_block_context();

        let garbage = Bytes::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let txs = vec![garbage];

        let outcome = executor.execute(&state, &context, &txs).expect("block should not fail");
        // Receipt count must equal transaction count to preserve index alignment.
        assert_eq!(outcome.receipts.len(), txs.len(), "receipt count must match tx count");
        assert!(!outcome.receipts[0].success(), "skipped tx receipt must be failed");
        assert_eq!(outcome.receipts[0].gas_used, 0, "skipped tx should use no gas");
        assert_eq!(outcome.gas_used, 0, "no gas should be consumed");
    }

    #[test]
    fn execute_skips_invalid_but_processes_valid() {
        // A block with [garbage, valid_tx] should emit a placeholder receipt for
        // the garbage and still execute the valid transaction, preserving indices.
        let executor = RevmExecutor::new(1);
        let state = MockStateDb;
        let context = test_block_context();

        let garbage = Bytes::from(vec![0xff, 0x01, 0x02, 0x03]);
        let valid_tx = build_valid_tx(1, 0);
        let txs = vec![garbage, valid_tx];

        let outcome = executor.execute(&state, &context, &txs).expect("block should not fail");

        // Receipt count must equal transaction count to preserve index alignment.
        assert_eq!(outcome.receipts.len(), txs.len(), "receipt count must match tx count");
        assert!(!outcome.receipts[0].success(), "garbage tx receipt must be failed");
        assert_eq!(outcome.receipts[0].gas_used, 0, "garbage tx should use no gas");
        assert!(outcome.receipts[1].success(), "valid tx receipt must be successful");
        assert!(outcome.gas_used > 0, "valid tx should consume gas");
    }

    #[test]
    fn execute_processes_valid_tx_between_invalid() {
        // A block with [garbage, valid_tx, more_garbage] should produce a receipt
        // for every transaction, preserving index alignment.
        let executor = RevmExecutor::new(1);
        let state = MockStateDb;
        let context = test_block_context();

        let garbage1 = Bytes::from(vec![0xaa, 0xbb]);
        let valid_tx = build_valid_tx(1, 0);
        let garbage2 = Bytes::from(vec![0xcc, 0xdd, 0xee]);
        let txs = vec![garbage1, valid_tx, garbage2];

        let outcome = executor.execute(&state, &context, &txs).expect("block should not fail");

        // Receipt count must equal transaction count to preserve index alignment.
        assert_eq!(outcome.receipts.len(), txs.len(), "receipt count must match tx count");
        assert!(!outcome.receipts[0].success(), "first garbage receipt must be failed");
        assert!(outcome.receipts[1].success(), "valid tx receipt must be successful");
        assert!(!outcome.receipts[2].success(), "second garbage receipt must be failed");
        // Cumulative gas in the last receipt should match total gas used.
        assert_eq!(outcome.receipts[2].cumulative_gas_used(), outcome.gas_used);
    }

    #[test]
    fn execute_empty_block_succeeds() {
        // An empty transaction list should produce an empty outcome.
        let executor = RevmExecutor::new(1);
        let state = MockStateDb;
        let context = test_block_context();

        let outcome = executor.execute(&state, &context, &[]).expect("empty block should succeed");
        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.gas_used, 0);
    }
}
