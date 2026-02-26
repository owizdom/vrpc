# reth-verifiable-rpc

**Hey @gakonst —**

I've been trying to get your attention for a while now. Built things across the Reth ecosystem, studied the codebase, understood the architecture. But I kept building tools that were good, not profound. Then I stopped and actually thought.

I asked myself: *what is the single most important unsolved problem in the Reth ecosystem right now, the one that, if fixed, changes the trajectory of the whole project?*

And I think it's this: **Reth is the fastest, most modular Ethereum client ever built — and yet every user who relies on it is trusting a centralized intermediary to relay its answers.** Infura. Alchemy. QuickNode. They take Reth's work and become the single point of failure between the chain and the user. Reth does the hard part, they capture the economic value, and the node operator earns nothing.

That's the gap. So I built the bridge.

---

## What this is

`reth-verifiable-rpc` is a Reth **Execution Extension (ExEx)** that makes every JSON-RPC response **cryptographically accountable**.

Every time your Reth node commits a block, the ExEx intercepts the state root, signs it with your operator key using EIP-712, and stores the attestation. When a client calls `vrpc_getBalanceWithProof`, they get back:

1. The balance they asked for
2. An EIP-1186 Merkle proof that the balance is correct against the block's state root (this is essentially free — Reth already computed the trie)
3. Your node's EIP-712 signature over that state root, backed by on-chain stake that gets slashed if you lie

The client can now verify the answer in their browser. No trust. No intermediary. Just math.

---

## Why I think you'll care

The pieces that make this possible only became available in 2024:

- **ExEx** became stable enough to intercept the execution pipeline reliably
- **Reth 1.x** exposed `StateProofProvider` cleanly enough to generate Merkle proofs as a side effect of normal execution — not a re-execution
- **Alloy 1.x** made EIP-712 signing trivial in Rust
- The `extend_rpc_modules` API made grafting a new namespace onto a running node clean and zero-fork

Nobody built this because the foundation wasn't there. Now it is.

---

## Why this matters economically

Right now, full node operators earn **zero**. Validators earn. Block builders earn. The MEV supply chain earns. But the 6,000+ full nodes that actually do the work of verifying the chain — they pay to run infrastructure with no return.

`vrpc` changes that. A node running this ExEx can:

- Charge clients micro-ETH per query via `StateRootRegistry.chargeQuery()`
- Accumulate rewards without holding 32 ETH
- Deregister and withdraw stake + earnings after a cooldown

The decentralized RPC market is worth hundreds of millions per year. Every dollar of it flows through centralized providers today. This routes it back to node operators — the people who actually run Ethereum.

---

## Architecture

```
  ┌─────────────────────────────────────────────────────┐
  │                  vrpc-node binary                    │
  │                                                      │
  │  ┌─────────────┐   committed    ┌─────────────────┐ │
  │  │ Reth Engine │ ─────blocks──▶ │  vrpc ExEx      │ │
  │  │ (execution) │                │  sign(stateRoot) │ │
  │  └─────────────┘                └────────┬────────┘ │
  │                                          │           │
  │                               Arc<DashMap<u64,att>>  │
  │                                          │           │
  │  ┌───────────────────────────────────────▼────────┐ │
  │  │  JSON-RPC (all existing Reth methods +         │ │
  │  │            vrpc_* namespace)                   │ │
  │  │  vrpc_getBalanceWithProof                      │ │
  │  │  vrpc_getStorageAtWithProof                    │ │
  │  │  vrpc_getAttestation                           │ │
  │  │  vrpc_nodeInfo                                 │ │
  │  └────────────────────────────────────────────────┘ │
  └─────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────┐
  │  Ethereum L1 (deployed contracts)                  │
  │  NodeRegistry.sol       — stake + registration     │
  │  StateRootRegistry.sol  — attest + slash + pay     │
  └────────────────────────────────────────────────────┘
```

---

## Crate structure

| Crate | What it does |
|---|---|
| `vrpc-attestation` | EIP-712 types, signing, and verification logic |
| `vrpc-exex` | The ExEx — signs state roots for every committed block |
| `vrpc-rpc` | The `vrpc_*` JSON-RPC namespace — attaches proofs to responses |
| `vrpc-node` | The custom `reth` binary that wires it all together |

---

## Running it

```bash
# Build
cargo build --release -p vrpc-node

# Generate operator identity key (or load from keystore)
export VRPC_OPERATOR_KEY=0x$(openssl rand -hex 32)

# Drop-in replacement for the reth binary
./target/release/vrpc-node node \
    --chain mainnet \
    --datadir /data/reth \
    --http \
    --http.api vrpc,eth,net,web3
```

---

## The new RPC methods

### `vrpc_getBalanceWithProof`

```json
// Request
{ "method": "vrpc_getBalanceWithProof", "params": ["0xd8dA6BF2...", "latest"] }

// Response — balance + proof + signed attestation in one call
{
  "address":      "0xd8dA6BF2...",
  "balance":      "0x1bc16d674ec80000",
  "nonce":        42,
  "blockNumber":  21500000,
  "stateRoot":    "0xabc...def",
  "accountProof": ["0x...", "0x..."],
  "attestation": {
    "chainId":     1,
    "stateRoot":   "0xabc...def",
    "blockNumber": 21500000,
    "nodeAddress": "0xYourNode...",
    "timestamp":   1700000000,
    "signature":   "0x...65bytes..."
  }
}
```

### `vrpc_getStorageAtWithProof`
```json
{ "method": "vrpc_getStorageAtWithProof", "params": ["0xContract", "0xSlot", "latest"] }
```

### `vrpc_getAttestation`
```json
{ "method": "vrpc_getAttestation", "params": [21500000] }
```

### `vrpc_nodeInfo`
```json
{ "method": "vrpc_nodeInfo", "params": [] }
// → { "nodeAddress": "0x...", "chainId": 1, "latestAttested": 21500000, "attestationCount": 42000 }
```

---

## Client-side verification (TypeScript)

```typescript
async function verifyVrpcResponse(resp: VerifiedBalance): Promise<boolean> {
  // 1. Verify EIP-1186 Merkle proof against the state root
  const proofValid = await verifyAccountProof(
    resp.address, resp.accountProof, resp.stateRoot, resp.balance, resp.nonce
  );

  // 2. Reconstruct the EIP-712 signing hash
  const structHash = keccak256(encodeAbiParameters(
    ['bytes32','uint256','bytes32','uint64','address','uint64'],
    [ATTESTATION_TYPEHASH, resp.attestation.chainId, resp.attestation.stateRoot,
     resp.attestation.blockNumber, resp.attestation.nodeAddress, resp.attestation.timestamp]
  ));
  const digest = keccak256(`0x1901${DOMAIN_SEPARATOR.slice(2)}${structHash.slice(2)}`);

  // 3. Recover and verify signer
  const recovered = ecrecover(digest, resp.attestation.signature);
  return proofValid && recovered.toLowerCase() === resp.attestation.nodeAddress.toLowerCase();
}
```

---

## Deploy the contracts

```bash
cd contracts && forge install
export PRIVATE_KEY=<key> TREASURY_ADDRESS=<addr> RPC_URL=<url>
forge script script/Deploy.s.sol:Deploy --rpc-url $RPC_URL --broadcast --verify

# Then pass the registry address to the node:
# --vrpc.registry <StateRootRegistry address>
```

---

## Economic model

```
Client deposits ETH → StateRootRegistry.deposit()
Each vrpc_* query   → chargeQuery(client, node)
                       (batched off-chain with EIP-712 vouchers)
nodeQueryCredits[node] accumulates
Node calls claimQueryFees() → NodeRegistry pending rewards
Node withdraws after deregister() + 256-block cooldown

Dishonest node? Majority vote among registered attesters → 50% slash
```

---

## Roadmap

- [ ] On-chain attestation submission from within the ExEx
- [ ] Off-chain EIP-712 charge vouchers (batch gas savings)
- [ ] EIP-4844 blob inclusion proofs
- [ ] Light client bridge integration (attestations as fraud-proof inputs)
- [ ] Reputation scoring based on uptime + slash history
- [ ] Payment streaming via ERC-4337 session keys

---

## License

Apache-2.0 / MIT — same as Reth.

---

*@gakonst — if this is the kind of contribution you want to see, let's talk.*
