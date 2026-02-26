//! Core attestation types and EIP-712 signing logic.
//!
//! Every Reth node running this ExEx produces a `SignedStateAttestation` for
//! each committed block.  The attestation binds:
//!
//!   chain_id  +  block_number  +  state_root  +  node_address  +  timestamp
//!
//! into a single EIP-712 structured-data hash that the node signs with its
//! registered key.  Any client can independently verify the signature without
//! trusting the RPC endpoint.

use alloy_primitives::{Address, Bytes, FixedBytes, B256, U256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{eip712_domain, sol, SolStruct};
use serde::{Deserialize, Serialize};

// ── EIP-712 type definition ───────────────────────────────────────────────────

sol! {
    /// Structured data that is signed by the node operator.
    struct StateAttestation {
        uint256 chainId;
        bytes32 stateRoot;
        uint64  blockNumber;
        address nodeAddress;
        uint64  timestamp;
    }
}

// ── Wire types ────────────────────────────────────────────────────────────────

/// A node's cryptographic attestation for a single block's state root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedStateAttestation {
    pub chain_id:     u64,
    pub state_root:   B256,
    pub block_number: u64,
    pub node_address: Address,
    pub timestamp:    u64,
    /// 65-byte EIP-712 signature (r ++ s ++ v)
    pub signature:    Bytes,
}

/// Proof-backed balance response returned by `vrpc_getBalanceWithProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedBalance {
    pub address:      Address,
    pub balance:      U256,
    pub nonce:        u64,
    pub block_number: u64,
    pub state_root:   B256,
    /// EIP-1186 Merkle nodes from state root to account leaf
    pub account_proof: Vec<Bytes>,
    /// Node's attestation for the block's state root
    pub attestation:  SignedStateAttestation,
}

/// Proof-backed storage slot returned by `vrpc_getStorageAtWithProof`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedStorageSlot {
    pub address:       Address,
    pub slot:          B256,
    pub value:         FixedBytes<32>,
    pub block_number:  u64,
    pub state_root:    B256,
    pub account_proof: Vec<Bytes>,
    pub storage_proof: Vec<Bytes>,
    pub attestation:   SignedStateAttestation,
}

/// Basic information about the attesting node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    pub node_address:       Address,
    pub chain_id:           u64,
    pub latest_attested:    u64,
    pub attestation_count:  u64,
}

// ── Signing ───────────────────────────────────────────────────────────────────

/// Build the EIP-712 domain for this chain.
///
/// An optional `verifying_contract` address can be passed once the
/// `StateRootRegistry` contract is deployed; it further scopes the
/// domain so attestations cannot be replayed across deployment addresses.
pub fn build_domain(chain_id: u64, verifying_contract: Option<Address>) -> alloy_sol_types::Eip712Domain {
    match verifying_contract {
        Some(addr) => eip712_domain! {
            name:                "VerifiableRPC",
            version:             "1",
            chain_id:            chain_id,
            verifying_contract:  addr,
        },
        None => eip712_domain! {
            name:     "VerifiableRPC",
            version:  "1",
            chain_id: chain_id,
        },
    }
}

/// Sign a block's state root and produce a `SignedStateAttestation`.
///
/// This is called by the ExEx once per committed block.  The operation is
/// cheap: it is a single secp256k1 sign over a 32-byte hash.
pub async fn sign_state_root(
    signer:       &PrivateKeySigner,
    domain:       &alloy_sol_types::Eip712Domain,
    chain_id:     u64,
    block_number: u64,
    state_root:   B256,
) -> eyre::Result<SignedStateAttestation> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let structured = StateAttestation {
        chainId:     U256::from(chain_id),
        stateRoot:   state_root,
        blockNumber: block_number,
        nodeAddress: signer.address(),
        timestamp,
    };

    let signing_hash: B256 = structured.eip712_signing_hash(domain);
    let signature = signer.sign_hash(&signing_hash).await?;

    Ok(SignedStateAttestation {
        chain_id,
        state_root,
        block_number,
        node_address: signer.address(),
        timestamp,
        signature: Bytes::from(signature.as_bytes()),
    })
}

/// Verify a `SignedStateAttestation` without any external dependency.
///
/// Returns `Ok(true)` when the signature is valid and the recovered signer
/// matches `attestation.node_address`.
pub fn verify_attestation(
    attestation: &SignedStateAttestation,
    verifying_contract: Option<Address>,
) -> eyre::Result<bool> {
    let domain = build_domain(attestation.chain_id, verifying_contract);

    let structured = StateAttestation {
        chainId:     U256::from(attestation.chain_id),
        stateRoot:   attestation.state_root,
        blockNumber: attestation.block_number,
        nodeAddress: attestation.node_address,
        timestamp:   attestation.timestamp,
    };

    let signing_hash: B256 = structured.eip712_signing_hash(&domain);

    let sig_bytes: [u8; 65] = attestation
        .signature
        .as_ref()
        .try_into()
        .map_err(|_| eyre::eyre!("signature must be 65 bytes"))?;

    let sig = alloy_primitives::PrimitiveSignature::from_bytes_and_parity(
        &sig_bytes[..64],
        sig_bytes[64] != 0,
    )?;

    let recovered = sig.recover_address_from_prehash(&signing_hash)?;
    Ok(recovered == attestation.node_address)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_sign_verify() {
        let signer = PrivateKeySigner::random();
        let domain = build_domain(1, None);
        let state_root = B256::repeat_byte(0xab);

        let att = sign_state_root(&signer, &domain, 1, 42, state_root)
            .await
            .unwrap();

        assert_eq!(att.block_number, 42);
        assert_eq!(att.state_root, state_root);
        assert_eq!(att.signature.len(), 65);

        let ok = verify_attestation(&att, None).unwrap();
        assert!(ok, "signature should verify");
    }

    #[tokio::test]
    async fn tampered_state_root_fails_verification() {
        let signer = PrivateKeySigner::random();
        let domain = build_domain(1, None);

        let mut att = sign_state_root(&signer, &domain, 1, 42, B256::repeat_byte(0xab))
            .await
            .unwrap();

        // Tamper with the state root after signing
        att.state_root = B256::repeat_byte(0xff);

        let ok = verify_attestation(&att, None).unwrap();
        assert!(!ok, "tampered attestation should not verify");
    }
}
