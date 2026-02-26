//! `vrpc-node` — a Reth node extended with the Verifiable-RPC ExEx and
//! the `vrpc_*` JSON-RPC namespace.
//!
//! # Usage
//!
//! ```text
//! vrpc-node node \
//!     --chain mainnet \
//!     --datadir /data/reth \
//!     --vrpc.key 0xdeadbeef...       # node operator private key (hex, no prefix optional)
//!     --vrpc.registry 0x1234...      # optional: deployed StateRootRegistry address
//!     --vrpc.chain-id 1              # default: 1 (mainnet)
//!     --http --http.api vrpc,eth,net
//! ```
//!
//! The node is a **drop-in replacement** for the standard `reth` binary — it
//! exposes all existing RPC methods plus the new `vrpc_*` namespace.
//!
//! # Architecture
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────┐
//!  │                   vrpc-node binary                    │
//!  │                                                       │
//!  │  ┌──────────────┐      ┌────────────────────────┐   │
//!  │  │  Reth Engine │─────▶│  VerifiableRPC ExEx    │   │
//!  │  │  (execution) │      │  • signs state roots   │   │
//!  │  └──────────────┘      │  • fills AttestStore   │   │
//!  │                         └────────────┬───────────┘   │
//!  │                                      │ Arc<DashMap>   │
//!  │  ┌──────────────────────────────────▼───────────┐   │
//!  │  │  JSON-RPC layer (Reth + vrpc_* namespace)     │   │
//!  │  │  • vrpc_getBalanceWithProof                   │   │
//!  │  │  • vrpc_getStorageAtWithProof                 │   │
//!  │  │  • vrpc_getAttestation                        │   │
//!  │  │  • vrpc_nodeInfo                              │   │
//!  │  └──────────────────────────────────────────────┘   │
//!  └──────────────────────────────────────────────────────┘
//! ```

use std::sync::Arc;

use alloy_primitives::Address;
use alloy_signer_local::PrivateKeySigner;
use clap::Parser;
use eyre::Context;
use reth::cli::Cli;
use reth_node_ethereum::EthereumNode;
use reth_tracing::tracing::info;

use vrpc_attestation::build_domain;
use vrpc_exex::{exex_init, new_store};
use vrpc_rpc::{VerifiableRpcApiServer, VerifiableRpcImpl};

// ── CLI extension ─────────────────────────────────────────────────────────────

/// Extra arguments added to the standard Reth CLI by this binary.
#[derive(Debug, Clone, Parser)]
pub struct VRpcArgs {
    /// Hex-encoded private key for the node operator identity.
    ///
    /// This key signs every state root attestation.  It does NOT need to hold
    /// funds; it is purely an identity key.  In production, load from an
    /// encrypted keystore using `--vrpc.keystore` instead.
    #[arg(
        long  = "vrpc.key",
        env   = "VRPC_OPERATOR_KEY",
        value_name = "HEX_KEY"
    )]
    pub operator_key: Option<String>,

    /// Path to an eth-keystore JSON file for the operator identity key.
    /// Password is read from `VRPC_KEYSTORE_PASSWORD` env var.
    #[arg(long = "vrpc.keystore", env = "VRPC_KEYSTORE_PATH")]
    pub keystore_path: Option<std::path::PathBuf>,

    /// Address of the deployed `StateRootRegistry` contract.
    ///
    /// When set, the ExEx will (in a future release) submit attestations
    /// on-chain so external parties can slash dishonest nodes.
    #[arg(long = "vrpc.registry", env = "VRPC_REGISTRY_ADDRESS")]
    pub registry_address: Option<Address>,

    /// EVM chain-id used in the EIP-712 domain separator.
    /// Defaults to 1 (Ethereum mainnet).
    #[arg(long = "vrpc.chain-id", env = "VRPC_CHAIN_ID", default_value = "1")]
    pub chain_id: u64,
}

impl VRpcArgs {
    /// Resolve the operator signer from CLI flags / environment.
    ///
    /// Priority: `--vrpc.key` > keystore file > random ephemeral key.
    /// An ephemeral key is **only** acceptable for local testing; a real node
    /// should always persist the operator key so its on-chain registration
    /// identity remains stable.
    pub fn resolve_signer(&self) -> eyre::Result<PrivateKeySigner> {
        if let Some(hex_key) = &self.operator_key {
            let hex = hex_key.trim_start_matches("0x");
            let bytes: [u8; 32] = hex::decode(hex)
                .wrap_err("vrpc.key must be a 32-byte hex string")?
                .try_into()
                .map_err(|_| eyre::eyre!("vrpc.key must be exactly 32 bytes"))?;
            return Ok(PrivateKeySigner::from_bytes(&bytes.into())?);
        }

        if let Some(path) = &self.keystore_path {
            let password = std::env::var("VRPC_KEYSTORE_PASSWORD")
                .unwrap_or_default();
            let signer = PrivateKeySigner::decrypt_keystore(path, password)
                .wrap_err("failed to decrypt operator keystore")?;
            return Ok(signer);
        }

        // Fallback: ephemeral random key (dev/test only)
        let signer = PrivateKeySigner::random();
        tracing::warn!(
            address = %signer.address(),
            "No operator key provided — using a random ephemeral key. \
             Attestations will not be verifiable across restarts."
        );
        Ok(signer)
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> eyre::Result<()> {
    // Install a SIGSEGV handler so panics produce useful backtraces
    reth::cli::sigsegv_handler::install();

    // Parse the full Reth CLI (standard args + our VRpcArgs extension)
    Cli::<reth_node_ethereum::EthereumChainSpecParser, VRpcArgs>::parse().run(
        |builder, vrpc_args| async move {
            // ── Shared state between ExEx and RPC ─────────────────────────────
            let store        = new_store();
            let signer       = Arc::new(vrpc_args.resolve_signer()?);
            let chain_id     = vrpc_args.chain_id;
            let registry     = vrpc_args.registry_address;
            let node_address = signer.address();

            info!(
                %node_address,
                chain_id,
                ?registry,
                "Starting VerifiableRPC node"
            );

            // ── Build and launch the node ─────────────────────────────────────
            let handle = builder
                .node(EthereumNode::default())
                // Install the ExEx — runs as an async task inside Reth
                .install_exex("VerifiableRPC", {
                    let store  = store.clone();
                    let signer = signer.clone();
                    move |ctx| {
                        let store    = store.clone();
                        let signer   = signer.clone();
                        let registry = registry;
                        async move {
                            exex_init(ctx, signer, store, chain_id, registry).await
                        }
                    }
                })
                // Extend the RPC with the vrpc_* namespace
                .extend_rpc_modules({
                    let store    = store.clone();
                    let signer   = signer.clone();
                    move |ctx| {
                        let vrpc = VerifiableRpcImpl::new(
                            ctx.provider().clone(),
                            store.clone(),
                            signer.address(),
                            chain_id,
                        );

                        // Merge into all transports (HTTP / WS / IPC)
                        ctx.modules.merge_configured(vrpc.into_rpc())?;

                        info!(
                            %node_address,
                            "Registered vrpc_* RPC namespace \
                             (vrpc_getBalanceWithProof, vrpc_getStorageAtWithProof, \
                              vrpc_getAttestation, vrpc_nodeInfo)"
                        );
                        Ok(())
                    }
                })
                .launch()
                .await?;

            handle.wait_for_node_exit().await
        },
    )
}
