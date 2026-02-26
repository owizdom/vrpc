// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title  NodeRegistry
/// @notice Allows Reth node operators to register their attesting identity and
///         post a minimum ETH stake.  Registered nodes can submit state-root
///         attestations to the StateRootRegistry and earn query fees from
///         clients.  Nodes that lie are slashed.
///
/// @dev    Registration flow:
///         1. Node calls `register()` with ≥ MIN_STAKE wei attached.
///         2. Node begins signing state roots and serving `vrpc_*` responses.
///         3. Node calls `deregister()` after a COOLDOWN period to reclaim stake.
///
///         Slashing is triggered exclusively by the StateRootRegistry; this
///         contract trusts it as an authorised slasher.
contract NodeRegistry {
    // ── Constants ────────────────────────────────────────────────────────────

    /// Minimum ETH stake per node (0.1 ETH — adjustable by governance).
    uint256 public constant MIN_STAKE = 0.1 ether;

    /// Blocks a node must wait after calling `deregister()` before it can
    /// withdraw.  Gives time for fraud proofs to arrive.
    uint256 public constant COOLDOWN_BLOCKS = 256;

    // ── Storage ───────────────────────────────────────────────────────────────

    struct NodeInfo {
        uint256 stake;
        uint256 deregisterBlock;   // 0 = not deregistering
        bool    active;
        uint256 totalAttestations;
        uint256 pendingRewards;
    }

    mapping(address => NodeInfo) public nodes;

    /// Address of the StateRootRegistry that is authorised to slash nodes.
    address public slasher;

    /// Protocol treasury that receives slashed stake.
    address public treasury;

    /// Governance owner (can update slasher / treasury).
    address public owner;

    // ── Events ────────────────────────────────────────────────────────────────

    event Registered   (address indexed node, uint256 stake);
    event Deregistered (address indexed node);
    event Withdrew     (address indexed node, uint256 amount);
    event Slashed      (address indexed node, uint256 amount, string reason);
    event RewardClaimed(address indexed node, uint256 amount);
    event RewardAdded  (address indexed node, uint256 amount);

    // ── Errors ────────────────────────────────────────────────────────────────

    error AlreadyRegistered();
    error NotRegistered();
    error InsufficientStake();
    error CooldownNotElapsed();
    error NotDeregistering();
    error OnlySlasher();
    error OnlyOwner();
    error TransferFailed();

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address _treasury) {
        owner    = msg.sender;
        treasury = _treasury;
    }

    // ── Node lifecycle ────────────────────────────────────────────────────────

    /// Register as an attesting node.  Requires ≥ MIN_STAKE wei.
    function register() external payable {
        if (nodes[msg.sender].active)        revert AlreadyRegistered();
        if (msg.value < MIN_STAKE)           revert InsufficientStake();

        nodes[msg.sender] = NodeInfo({
            stake:             msg.value,
            deregisterBlock:   0,
            active:            true,
            totalAttestations: 0,
            pendingRewards:    0
        });

        emit Registered(msg.sender, msg.value);
    }

    /// Initiate deregistration.  Starts the cooldown period.
    /// The node should stop serving attestations after calling this.
    function deregister() external {
        NodeInfo storage info = nodes[msg.sender];
        if (!info.active)                  revert NotRegistered();
        if (info.deregisterBlock != 0)     revert AlreadyRegistered(); // already deregistering

        info.deregisterBlock = block.number;
        info.active          = false;

        emit Deregistered(msg.sender);
    }

    /// Withdraw stake after the cooldown period has elapsed.
    function withdraw() external {
        NodeInfo storage info = nodes[msg.sender];
        if (info.deregisterBlock == 0)    revert NotDeregistering();
        if (block.number < info.deregisterBlock + COOLDOWN_BLOCKS)
            revert CooldownNotElapsed();

        uint256 amount = info.stake + info.pendingRewards;
        delete nodes[msg.sender];

        _transfer(msg.sender, amount);
        emit Withdrew(msg.sender, amount);
    }

    // ── Rewards ───────────────────────────────────────────────────────────────

    /// Called by the StateRootRegistry (or a payment distributor) to credit
    /// query-fee rewards to a node.
    function addReward(address node) external payable {
        if (!nodes[node].active) revert NotRegistered();
        nodes[node].pendingRewards += msg.value;
        emit RewardAdded(node, msg.value);
    }

    /// Node claims its pending rewards without deregistering.
    function claimRewards() external {
        NodeInfo storage info = nodes[msg.sender];
        if (!info.active) revert NotRegistered();

        uint256 amount = info.pendingRewards;
        info.pendingRewards = 0;

        _transfer(msg.sender, amount);
        emit RewardClaimed(msg.sender, amount);
    }

    // ── Slashing (called by StateRootRegistry) ────────────────────────────────

    /// Slash a misbehaving node.  `fraction` is expressed in basis points
    /// (10_000 = 100%).  The slashed ETH goes to the treasury.
    function slash(address node, uint16 fractionBps, string calldata reason)
        external
    {
        if (msg.sender != slasher) revert OnlySlasher();

        NodeInfo storage info = nodes[node];
        if (info.stake == 0) return; // already slashed to zero

        uint256 slashAmount = (info.stake * fractionBps) / 10_000;
        info.stake         -= slashAmount;
        info.active         = false;   // suspended pending dispute resolution

        _transfer(treasury, slashAmount);
        emit Slashed(node, slashAmount, reason);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function isRegistered(address node) external view returns (bool) {
        return nodes[node].active;
    }

    function stakeOf(address node) external view returns (uint256) {
        return nodes[node].stake;
    }

    function rewardsOf(address node) external view returns (uint256) {
        return nodes[node].pendingRewards;
    }

    // ── Governance ────────────────────────────────────────────────────────────

    function setSlasher(address _slasher) external {
        if (msg.sender != owner) revert OnlyOwner();
        slasher = _slasher;
    }

    function setTreasury(address _treasury) external {
        if (msg.sender != owner) revert OnlyOwner();
        treasury = _treasury;
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _transfer(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}
