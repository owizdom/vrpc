//! Verifiable-RPC Execution Extension.
//!
//! This ExEx hooks into Reth's block execution pipeline.  After every
//! committed block it:
//!
//!   1. Extracts the canonical state root from the block header.
//!   2. Signs it with the node operator's key (EIP-712).
//!   3. Stores the `SignedStateAttestation` in a shared in-memory cache that
//!      the JSON-RPC layer reads when attaching proofs to responses.
//!   4. (Optional) Submits the attestation to the on-chain `StateRootRegistry`
//!      so external verifiers can slash nodes that lie.
//!
//! Chain reorgs are handled: old attestations are evicted and new ones are
//! generated for the canonical chain.

use std::{future::Future, sync::Arc};

use dashmap::DashMap;
use eyre::Context;
use futures::TryStreamExt;
use reth_exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::FullNodeComponents;
use reth_tracing::tracing::{error, info, warn};

use alloy_primitives::{Address, B256};
use alloy_signer_local::PrivateKeySigner;

use vrpc_attestation::{build_domain, sign_state_root, SignedStateAttestation};

// ── Shared state ──────────────────────────────────────────────────────────────

/// Thread-safe cache mapping block_number → signed attestation.
///
/// Written by the ExEx; read by the RPC layer.  Entries for reverted blocks
/// are removed so clients can never receive an attestation for a non-canonical
/// block.
pub type AttestationStore = Arc<DashMap<u64, SignedStateAttestation>>;

/// Create a new, empty attestation store.
pub fn new_store() -> AttestationStore {
    Arc::new(DashMap::new())
}

// ── ExEx entry points ─────────────────────────────────────────────────────────

/// Initialisation shim required by `install_exex`.
///
/// Called once at node startup.  Any async resources (e.g. an HTTP client for
/// on-chain submission) can be set up here before returning the long-running
/// future.
pub async fn exex_init<Node: FullNodeComponents>(
    ctx:      ExExContext<Node>,
    signer:   Arc<PrivateKeySigner>,
    store:    AttestationStore,
    chain_id: u64,
    registry: Option<Address>,
) -> eyre::Result<impl Future<Output = eyre::Result<()>>> {
    info!(
        node_address = %signer.address(),
        chain_id,
        "VerifiableRPC ExEx initialised"
    );
    Ok(exex(ctx, signer, store, chain_id, registry))
}

/// The main ExEx loop.
///
/// Processes chain notifications indefinitely, signing state roots for every
/// committed block and evicting attestations for reverted blocks.
async fn exex<Node: FullNodeComponents>(
    mut ctx:  ExExContext<Node>,
    signer:   Arc<PrivateKeySigner>,
    store:    AttestationStore,
    chain_id: u64,
    registry: Option<Address>,
) -> eyre::Result<()> {
    let domain = Arc::new(build_domain(chain_id, registry));

    while let Some(notification) = ctx.notifications.try_next().await? {
        match &notification {
            ExExNotification::ChainCommitted { new } => {
                let chain = new.committed();
                attest_chain_blocks(chain.blocks(), &signer, &domain, chain_id, &store).await;
            }

            ExExNotification::ChainReverted { old } => {
                let chain = old.reverted();
                for (num, _) in chain.blocks() {
                    if store.remove(num).is_some() {
                        warn!(block_number = num, "Evicted attestation for reverted block");
                    }
                }
            }

            ExExNotification::ChainReorged { old, new } => {
                // 1. Evict the now-canonical-no-more blocks
                let old_chain = old.reverted();
                for (num, _) in old_chain.blocks() {
                    store.remove(num);
                }

                // 2. Attest the new canonical chain
                let new_chain = new.committed();
                attest_chain_blocks(new_chain.blocks(), &signer, &domain, chain_id, &store).await;
            }
        }

        // Signal to Reth that we have processed up to the committed tip.
        // This allows Reth to prune notifications from the channel.
        if let Some(committed) = notification.committed_chain() {
            ctx.events
                .send(ExExEvent::FinishedHeight(committed.tip().num_hash()))
                .wrap_err("failed to send FinishedHeight")?;
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Sign the state root for every block in `blocks` and insert into `store`.
///
/// `blocks` is a `BTreeMap<BlockNumber, SealedBlockWithSenders>` as returned
/// by `Chain::blocks()`.
async fn attest_chain_blocks<B>(
    blocks:   &std::collections::BTreeMap<u64, B>,
    signer:   &PrivateKeySigner,
    domain:   &alloy_sol_types::Eip712Domain,
    chain_id: u64,
    store:    &AttestationStore,
) where
    B: BlockStateRoot,
{
    for (block_number, block) in blocks {
        let state_root = block.state_root();

        match sign_state_root(signer, domain, chain_id, *block_number, state_root).await {
            Ok(att) => {
                info!(
                    block_number,
                    %state_root,
                    node_address = %att.node_address,
                    "Signed state root attestation"
                );
                store.insert(*block_number, att);
            }
            Err(e) => {
                error!(block_number, error = %e, "Failed to sign state root");
            }
        }
    }
}

/// Abstraction over reth's `SealedBlockWithSenders` so we can unit-test
/// without pulling in the full reth block type.
pub trait BlockStateRoot {
    fn state_root(&self) -> B256;
}

// Blanket impl for reth's concrete type.
// `SealedBlockWithSenders` derefs through `SealedBlock -> SealedHeader -> Header`
// which exposes `.state_root`.  If reth changes the field path in a future
// version, only this impl needs updating.
impl BlockStateRoot for reth_primitives::SealedBlockWithSenders {
    fn state_root(&self) -> B256 {
        // reth 1.9.0: SealedBlockWithSenders -> block: SealedBlock
        //              SealedBlock -> header: SealedHeader
        //              SealedHeader implements Deref<Target = Header>
        //              Header has .state_root: B256
        self.block.header.state_root
    }
}

// ── Statistics helper ─────────────────────────────────────────────────────────

/// Returns the highest block number currently in the store, if any.
pub fn latest_attested(store: &AttestationStore) -> Option<u64> {
    store.iter().map(|e| *e.key()).max()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vrpc_attestation::verify_attestation;

    struct FakeBlock {
        state_root: B256,
    }
    impl BlockStateRoot for FakeBlock {
        fn state_root(&self) -> B256 {
            self.state_root
        }
    }

    #[tokio::test]
    async fn attest_and_evict() {
        let signer = Arc::new(PrivateKeySigner::random());
        let store = new_store();
        let domain = Arc::new(build_domain(1, None));

        let mut blocks = std::collections::BTreeMap::new();
        blocks.insert(10u64, FakeBlock { state_root: B256::repeat_byte(0x01) });
        blocks.insert(11u64, FakeBlock { state_root: B256::repeat_byte(0x02) });

        attest_chain_blocks(&blocks, &signer, &domain, 1, &store).await;

        assert_eq!(store.len(), 2);

        // Verify both attestations are valid
        for (num, block) in &blocks {
            let att = store.get(num).expect("attestation should be present");
            assert_eq!(att.state_root, block.state_root);
            assert!(verify_attestation(&att, None).unwrap());
        }

        // Simulate revert of block 11
        store.remove(&11);
        assert_eq!(store.len(), 1);
        assert!(store.contains_key(&10));
    }
}
