//! `vrpc_*` JSON-RPC namespace.
//!
//! Registers three new RPC methods on the running Reth node:
//!
//! | Method                       | Description                                          |
//! |------------------------------|------------------------------------------------------|
//! | `vrpc_getBalanceWithProof`   | Balance + EIP-1186 account proof + node signature   |
//! | `vrpc_getStorageAtWithProof` | Storage value + EIP-1186 storage proof + signature  |
//! | `vrpc_getAttestation`        | Raw signed attestation for a given block             |
//! | `vrpc_nodeInfo`              | Node address, chain-id, attestation stats            |
//!
//! ## How proof attachment works
//!
//! 1. The caller provides an address (and optional storage slot) plus a block tag.
//! 2. We resolve the block number, then call
//!    `provider.history_by_block_number(n)?.proof(TrieInput::default(), addr, &slots)`.
//!    Reth already computed this trie; generating a proof is essentially free.
//! 3. We look up the corresponding `SignedStateAttestation` from the shared
//!    `AttestationStore` written by the ExEx.
//! 4. We return value + Merkle proof + signature in a single JSON response.
//!
//! The caller can verify the response entirely client-side:
//!   a) Check the EIP-1186 proof against `attestation.state_root`.
//!   b) Recover the signer from `attestation.signature` and check it matches
//!      `attestation.node_address` (a registered, staked operator).

use std::sync::Arc;

use jsonrpsee::{
    core::RpcResult,
    proc_macros::rpc,
    types::{error::INTERNAL_ERROR_CODE, ErrorObjectOwned},
};
use reth_primitives::SealedBlockWithSenders;
use reth_provider::{
    BlockNumReader, BlockReader, HeaderProvider, StateProofProvider, StateProviderFactory,
};
use reth_trie::TrieInput;
use tracing::{debug, warn};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::{Address, Bytes, B256, U256};

use vrpc_attestation::{NodeInfo, SignedStateAttestation, VerifiedBalance, VerifiedStorageSlot};
use vrpc_exex::{latest_attested, AttestationStore};

// ── RPC trait definition ──────────────────────────────────────────────────────

#[rpc(server, namespace = "vrpc")]
pub trait VerifiableRpcApi {
    /// Returns the ETH balance of `address` at `block`, together with:
    /// - An EIP-1186 Merkle proof of the account against the block's state root
    /// - The node's EIP-712 signed attestation of that state root
    #[method(name = "getBalanceWithProof")]
    async fn get_balance_with_proof(
        &self,
        address: Address,
        block:   BlockNumberOrTag,
    ) -> RpcResult<VerifiedBalance>;

    /// Returns the storage value at `slot` for `address` at `block`, together
    /// with an EIP-1186 storage proof and the node's state-root attestation.
    #[method(name = "getStorageAtWithProof")]
    async fn get_storage_at_with_proof(
        &self,
        address: Address,
        slot:    B256,
        block:   BlockNumberOrTag,
    ) -> RpcResult<VerifiedStorageSlot>;

    /// Returns the raw `SignedStateAttestation` for `block_number`, or null
    /// if this node has not yet attested to that block.
    #[method(name = "getAttestation")]
    async fn get_attestation(
        &self,
        block_number: u64,
    ) -> RpcResult<Option<SignedStateAttestation>>;

    /// Returns metadata about this attesting node.
    #[method(name = "nodeInfo")]
    async fn node_info(&self) -> RpcResult<NodeInfo>;
}

// ── Implementation ────────────────────────────────────────────────────────────

/// The concrete handler that implements the `vrpc_*` namespace.
///
/// `P` is Reth's provider type.  The exact type is inferred by the compiler
/// from the node builder's generic parameters; we only require the traits we
/// actually use.
pub struct VerifiableRpcImpl<P> {
    provider:          P,
    attestation_store: AttestationStore,
    node_address:      Address,
    chain_id:          u64,
    /// Running count of total attestations produced (informational only).
    attest_count:      Arc<std::sync::atomic::AtomicU64>,
}

impl<P: Clone> VerifiableRpcImpl<P> {
    pub fn new(
        provider:          P,
        attestation_store: AttestationStore,
        node_address:      Address,
        chain_id:          u64,
    ) -> Self {
        Self {
            provider,
            attestation_store,
            node_address,
            chain_id,
            attest_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Increment the internal attestation counter (called by ExEx watcher or
    /// can be driven from test harness).
    pub fn inc_attest_count(&self) {
        self.attest_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// ── Trait implementation ──────────────────────────────────────────────────────

#[jsonrpsee::core::async_trait]
impl<P> VerifiableRpcApiServer for VerifiableRpcImpl<P>
where
    P: StateProviderFactory
        + BlockNumReader
        + BlockReader
        + HeaderProvider
        + Clone
        + Unpin
        + Send
        + Sync
        + 'static,
{
    async fn get_balance_with_proof(
        &self,
        address: Address,
        block:   BlockNumberOrTag,
    ) -> RpcResult<VerifiedBalance> {
        let provider = self.provider.clone();
        let store    = self.attestation_store.clone();

        tokio::task::spawn_blocking(move || {
            // 1. Resolve block number
            let block_num = resolve_block_number(&provider, block)?;

            // 2. Get a state snapshot at that block
            let state = provider
                .history_by_block_number(block_num)
                .map_err(reth_to_rpc_err)?;

            // 3. Generate EIP-1186 account proof (no storage slots needed)
            let proof = state
                .proof(TrieInput::default(), address, &[])
                .map_err(reth_to_rpc_err)?;

            // 4. Extract balance from proof (avoids a second DB lookup)
            let (balance, nonce) = proof
                .info
                .as_ref()
                .map(|a| (a.balance, a.nonce))
                .unwrap_or((U256::ZERO, 0));

            // 5. Get the state root from the block header
            let header = provider
                .header_by_number(block_num)
                .map_err(reth_to_rpc_err)?
                .ok_or_else(|| rpc_err("block header not found"))?;

            let state_root = header.state_root;

            // 6. Look up the ExEx-generated attestation
            let attestation = store
                .get(&block_num)
                .map(|a| a.value().clone())
                .ok_or_else(|| {
                    rpc_err(format!(
                        "no attestation for block {block_num} — node may still be syncing"
                    ))
                })?;

            debug!(%address, block_num, "served vrpc_getBalanceWithProof");

            Ok(VerifiedBalance {
                address,
                balance,
                nonce,
                block_number: block_num,
                state_root,
                account_proof: proof.proof,
                attestation,
            })
        })
        .await
        .map_err(|e| rpc_err(e.to_string()))?
    }

    async fn get_storage_at_with_proof(
        &self,
        address: Address,
        slot:    B256,
        block:   BlockNumberOrTag,
    ) -> RpcResult<VerifiedStorageSlot> {
        let provider = self.provider.clone();
        let store    = self.attestation_store.clone();

        tokio::task::spawn_blocking(move || {
            let block_num = resolve_block_number(&provider, block)?;

            let state = provider
                .history_by_block_number(block_num)
                .map_err(reth_to_rpc_err)?;

            // Pass the target storage slot so the proof covers it
            let proof = state
                .proof(TrieInput::default(), address, &[slot])
                .map_err(reth_to_rpc_err)?;

            let header = provider
                .header_by_number(block_num)
                .map_err(reth_to_rpc_err)?
                .ok_or_else(|| rpc_err("block header not found"))?;

            let state_root = header.state_root;

            // Find the storage proof for our requested slot
            let storage_proof = proof
                .storage_proofs
                .iter()
                .find(|sp| sp.key == slot)
                .ok_or_else(|| rpc_err("storage proof not found in response"))?;

            let value: alloy_primitives::FixedBytes<32> = {
                let mut buf = [0u8; 32];
                storage_proof.value.to_big_endian(&mut buf);
                alloy_primitives::FixedBytes(buf)
            };

            let attestation = store
                .get(&block_num)
                .map(|a| a.value().clone())
                .ok_or_else(|| {
                    rpc_err(format!("no attestation for block {block_num}"))
                })?;

            debug!(%address, %slot, block_num, "served vrpc_getStorageAtWithProof");

            Ok(VerifiedStorageSlot {
                address,
                slot,
                value,
                block_number: block_num,
                state_root,
                account_proof: proof.proof,
                storage_proof: storage_proof.proof.clone(),
                attestation,
            })
        })
        .await
        .map_err(|e| rpc_err(e.to_string()))?
    }

    async fn get_attestation(
        &self,
        block_number: u64,
    ) -> RpcResult<Option<SignedStateAttestation>> {
        Ok(self
            .attestation_store
            .get(&block_number)
            .map(|a| a.value().clone()))
    }

    async fn node_info(&self) -> RpcResult<NodeInfo> {
        let latest   = latest_attested(&self.attestation_store).unwrap_or(0);
        let count    = self.attest_count.load(std::sync::atomic::Ordering::Relaxed);

        Ok(NodeInfo {
            node_address:      self.node_address,
            chain_id:          self.chain_id,
            latest_attested:   latest,
            attestation_count: count,
        })
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Resolve a `BlockNumberOrTag` to a concrete block number using the provider.
fn resolve_block_number<P: BlockNumReader>(
    provider: &P,
    tag:      BlockNumberOrTag,
) -> RpcResult<u64> {
    match tag {
        BlockNumberOrTag::Number(n) => Ok(n),
        BlockNumberOrTag::Latest | BlockNumberOrTag::Pending => provider
            .best_block_number()
            .map_err(reth_to_rpc_err),
        BlockNumberOrTag::Earliest => Ok(0),
        BlockNumberOrTag::Safe => provider
            .safe_block_number()
            .map_err(reth_to_rpc_err)?
            .ok_or_else(|| rpc_err("safe block not available"))
            .map(|n| n),
        BlockNumberOrTag::Finalized => provider
            .finalized_block_number()
            .map_err(reth_to_rpc_err)?
            .ok_or_else(|| rpc_err("finalized block not available"))
            .map(|n| n),
    }
}

/// Convert a reth `ProviderError` into a jsonrpsee `ErrorObjectOwned`.
fn reth_to_rpc_err(e: reth_provider::ProviderError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, e.to_string(), None::<()>)
}

/// Create a generic RPC error with a message.
fn rpc_err(msg: impl ToString) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, msg.to_string(), None::<()>)
}
