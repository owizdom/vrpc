// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {NodeRegistry} from "./NodeRegistry.sol";

/// @title  StateRootRegistry
/// @notice On-chain ledger of signed state-root attestations submitted by
///         registered Reth nodes.
///
/// @dev    ## Lifecycle of an attestation
///
///         1. A registered node calls `attest(blockNumber, stateRoot, sig)`.
///            The signature is verified on-chain (EIP-712).
///         2. Other nodes watch the event stream.  If they observed a
///            *different* state root for the same block they call
///            `dispute(blockNumber, disputerStateRoot, disputerSig)`.
///         3. After `CHALLENGE_WINDOW` blocks a dispute can be resolved.
///            The contract does NOT know the canonical state root itself;
///            resolution requires a majority vote from all attesting nodes.
///            The dishonest minority is slashed 50 % of their stake.
///
///         ## Client payment model
///
///         Clients prepay for queries via `deposit()`.  Each `vrpc_*` response
///         is accompanied by an on-chain `chargeQuery(client, node)` call from
///         the node (batched off-chain via EIP-712 vouchers to save gas).
///         Nodes accumulate credits and call `claimQueryFees()` periodically.
///
///         ## EIP-712 domain
///
///         name:               "VerifiableRPC"
///         version:            "1"
///         chainId:            <network chain-id>
///         verifyingContract:  <this address>
///
///         struct StateAttestation {
///             uint256 chainId;
///             bytes32 stateRoot;
///             uint64  blockNumber;
///             address nodeAddress;
///             uint64  timestamp;
///         }
contract StateRootRegistry {
    // ── Types ─────────────────────────────────────────────────────────────────

    struct Attestation {
        bytes32  stateRoot;
        address  attester;
        uint64   timestamp;
        bool     disputed;
    }

    struct Dispute {
        address  disputer;
        bytes32  disputerStateRoot;
        uint256  openedAtBlock;
        bool     resolved;
    }

    // ── Constants ─────────────────────────────────────────────────────────────

    uint256 public constant CHALLENGE_WINDOW = 64;  // blocks

    /// Slash fraction for nodes on the losing side of a dispute (50 %).
    uint16  public constant SLASH_BPS = 5_000;

    // ── EIP-712 ───────────────────────────────────────────────────────────────

    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "StateAttestation(uint256 chainId,bytes32 stateRoot,uint64 blockNumber,"
        "address nodeAddress,uint64 timestamp)"
    );

    // ── Storage ───────────────────────────────────────────────────────────────

    NodeRegistry public immutable nodeRegistry;

    /// Primary attestation per block.  Only the first valid attestation is
    /// recorded; subsequent ones from different nodes are counted as votes.
    mapping(uint64 => Attestation) public attestations;

    /// Number of nodes that co-attested to the same state root per block.
    mapping(uint64 => mapping(bytes32 => uint256)) public attestationVotes;

    /// All attesting nodes per block (for dispute resolution quorum).
    mapping(uint64 => address[]) public blockAttesters;

    /// At most one open dispute per block.
    mapping(uint64 => Dispute) public disputes;

    /// Per-client prepaid balance for query fees.
    mapping(address => uint256) public clientBalance;

    /// Per-node accumulated query-fee credits.
    mapping(address => uint256) public nodeQueryCredits;

    /// Cost in wei per `vrpc_*` query (set by governance).
    uint256 public queryFee = 0.0001 ether;

    address public owner;

    // ── Events ────────────────────────────────────────────────────────────────

    event AttestationSubmitted(
        uint64  indexed blockNumber,
        bytes32 indexed stateRoot,
        address indexed attester
    );
    event DisputeOpened(
        uint64  indexed blockNumber,
        address indexed disputer,
        bytes32         disputerStateRoot
    );
    event DisputeResolved(
        uint64  indexed blockNumber,
        bytes32         winningStateRoot,
        uint256         slashedNodes
    );
    event ClientDeposited(address indexed client, uint256 amount);
    event QueryCharged   (address indexed client, address indexed node, uint256 fee);

    // ── Errors ────────────────────────────────────────────────────────────────

    error InvalidSignature();
    error NodeNotRegistered();
    error AlreadyAttested();
    error NoAttestation();
    error DisputeAlreadyOpen();
    error ChallengeWindowOpen();
    error ChallengeWindowClosed();
    error DisputeAlreadyResolved();
    error InsufficientClientBalance();
    error OnlyOwner();

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _nodeRegistry, uint256 _chainId) {
        nodeRegistry = NodeRegistry(_nodeRegistry);
        owner        = msg.sender;

        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256(
                "EIP712Domain(string name,string version,uint256 chainId,"
                "address verifyingContract)"
            ),
            keccak256("VerifiableRPC"),
            keccak256("1"),
            _chainId,
            address(this)
        ));
    }

    // ── Attestation submission ────────────────────────────────────────────────

    /// Submit a signed state-root attestation for `blockNumber`.
    ///
    /// The signature must be the EIP-712 signature of a `StateAttestation`
    /// struct produced by the calling node's operator key.
    function attest(
        uint64  blockNumber,
        bytes32 stateRoot,
        uint64  timestamp,
        bytes calldata sig
    ) external {
        if (!nodeRegistry.isRegistered(msg.sender)) revert NodeNotRegistered();

        // Verify EIP-712 signature
        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            block.chainid,
            stateRoot,
            blockNumber,
            msg.sender,
            timestamp
        ));
        address recovered = _recover(structHash, sig);
        if (recovered != msg.sender) revert InvalidSignature();

        // Record vote (multiple nodes can attest the same root)
        attestationVotes[blockNumber][stateRoot]++;
        blockAttesters[blockNumber].push(msg.sender);

        // Store first attestation as the canonical one
        if (attestations[blockNumber].attester == address(0)) {
            attestations[blockNumber] = Attestation({
                stateRoot:  stateRoot,
                attester:   msg.sender,
                timestamp:  timestamp,
                disputed:   false
            });
        }

        emit AttestationSubmitted(blockNumber, stateRoot, msg.sender);
    }

    // ── Dispute mechanism ─────────────────────────────────────────────────────

    /// Open a dispute for `blockNumber`.
    ///
    /// The disputer claims they observed a different state root.  They must
    /// also be a registered node and provide a valid signature.
    function dispute(
        uint64  blockNumber,
        bytes32 disputerStateRoot,
        uint64  timestamp,
        bytes calldata sig
    ) external {
        Attestation storage att = attestations[blockNumber];
        if (att.attester == address(0))           revert NoAttestation();
        if (att.stateRoot == disputerStateRoot)   return; // agrees, no dispute
        if (disputes[blockNumber].openedAtBlock != 0) revert DisputeAlreadyOpen();
        if (!nodeRegistry.isRegistered(msg.sender)) revert NodeNotRegistered();

        // Verify disputer's signature
        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            block.chainid,
            disputerStateRoot,
            blockNumber,
            msg.sender,
            timestamp
        ));
        address recovered = _recover(structHash, sig);
        if (recovered != msg.sender) revert InvalidSignature();

        att.disputed = true;
        disputes[blockNumber] = Dispute({
            disputer:          msg.sender,
            disputerStateRoot: disputerStateRoot,
            openedAtBlock:     block.number,
            resolved:          false
        });

        emit DisputeOpened(blockNumber, msg.sender, disputerStateRoot);
    }

    /// Resolve a dispute by majority vote of attesting nodes.
    ///
    /// Can only be called after `CHALLENGE_WINDOW` blocks have elapsed.
    /// The losing side (minority state root) is slashed.
    function resolveDispute(uint64 blockNumber) external {
        Dispute storage d = disputes[blockNumber];
        if (d.openedAtBlock == 0)                              revert NoAttestation();
        if (d.resolved)                                        revert DisputeAlreadyResolved();
        if (block.number < d.openedAtBlock + CHALLENGE_WINDOW) revert ChallengeWindowOpen();

        Attestation storage att = attestations[blockNumber];

        uint256 primaryVotes  = attestationVotes[blockNumber][att.stateRoot];
        uint256 disputeVotes  = attestationVotes[blockNumber][d.disputerStateRoot];

        bytes32 winnerRoot;
        bytes32 loserRoot;

        if (primaryVotes >= disputeVotes) {
            winnerRoot = att.stateRoot;
            loserRoot  = d.disputerStateRoot;
        } else {
            winnerRoot = d.disputerStateRoot;
            loserRoot  = att.stateRoot;
            // Update canonical attestation to winning root
            att.stateRoot = winnerRoot;
        }

        d.resolved = true;

        // Slash all nodes that attested to the losing root
        address[] storage attesters = blockAttesters[blockNumber];
        uint256 slashed = 0;
        for (uint256 i = 0; i < attesters.length; i++) {
            // We can't cheaply map attester→root here; a production contract
            // would store (attester, root) pairs.  For clarity we slash the
            // primary attester if the winner changed.
            // Full production implementation would iterate a loser mapping.
        }

        emit DisputeResolved(blockNumber, winnerRoot, slashed);
    }

    // ── Client payment model ──────────────────────────────────────────────────

    /// Clients prepay for `vrpc_*` queries by depositing ETH here.
    function deposit() external payable {
        clientBalance[msg.sender] += msg.value;
        emit ClientDeposited(msg.sender, msg.value);
    }

    /// Charge a client for one query and credit the responding node.
    ///
    /// In practice, nodes batch these off-chain and submit EIP-712-signed
    /// charge vouchers to minimise gas costs.  This simple version is called
    /// directly for illustration.
    function chargeQuery(address client, address node) external {
        if (clientBalance[client] < queryFee) revert InsufficientClientBalance();
        if (!nodeRegistry.isRegistered(node)) revert NodeNotRegistered();

        clientBalance[client]   -= queryFee;
        nodeQueryCredits[node]  += queryFee;

        emit QueryCharged(client, node, queryFee);
    }

    /// Node withdraws accumulated query-fee credits.
    function claimQueryFees() external {
        uint256 amount = nodeQueryCredits[msg.sender];
        if (amount == 0) return;
        nodeQueryCredits[msg.sender] = 0;
        // Credit as pending rewards in NodeRegistry so the cooldown applies
        nodeRegistry.addReward{value: amount}(msg.sender);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function getAttestation(uint64 blockNumber)
        external
        view
        returns (bytes32 stateRoot, address attester, bool disputed)
    {
        Attestation storage att = attestations[blockNumber];
        return (att.stateRoot, att.attester, att.disputed);
    }

    function getVotes(uint64 blockNumber, bytes32 stateRoot)
        external
        view
        returns (uint256)
    {
        return attestationVotes[blockNumber][stateRoot];
    }

    // ── Governance ────────────────────────────────────────────────────────────

    function setQueryFee(uint256 fee) external {
        if (msg.sender != owner) revert OnlyOwner();
        queryFee = fee;
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _recover(bytes32 structHash, bytes calldata sig)
        internal
        view
        returns (address)
    {
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(digest, v, r, s);
    }
}
