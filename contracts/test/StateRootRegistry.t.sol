// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {NodeRegistry}      from "../src/NodeRegistry.sol";
import {StateRootRegistry} from "../src/StateRootRegistry.sol";

/// @dev Test suite for the on-chain attestation + slashing logic.
contract StateRootRegistryTest is Test {
    NodeRegistry      internal nodeReg;
    StateRootRegistry internal registry;

    // Test accounts
    address internal treasury = makeAddr("treasury");
    address internal nodeA    = makeAddr("nodeA");
    address internal nodeB    = makeAddr("nodeB");
    address internal client   = makeAddr("client");

    // Private keys for EIP-712 signing (deterministic)
    uint256 internal nodeAKey = 0xA11CE;
    uint256 internal nodeBKey = 0xB0B;

    function setUp() public {
        // Deploy contracts
        nodeReg  = new NodeRegistry(treasury);
        registry = new StateRootRegistry(address(nodeReg), 31337); // Foundry chain-id

        // Connect registry as authorised slasher
        nodeReg.setSlasher(address(registry));

        // Fund nodes and register them
        address signerA = vm.addr(nodeAKey);
        address signerB = vm.addr(nodeBKey);

        vm.deal(signerA, 1 ether);
        vm.deal(signerB, 1 ether);
        vm.deal(client,  1 ether);

        vm.prank(signerA);
        nodeReg.register{value: 0.5 ether}();

        vm.prank(signerB);
        nodeReg.register{value: 0.5 ether}();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    function _signAttestation(
        uint256 key,
        uint64  blockNumber,
        bytes32 stateRoot,
        uint64  timestamp
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            registry.ATTESTATION_TYPEHASH(),
            uint256(31337),
            stateRoot,
            blockNumber,
            vm.addr(key),
            timestamp
        ));
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                registry.DOMAIN_SEPARATOR(),
                structHash
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    function test_register_and_attest() public {
        uint64  blockNum  = 1_000_000;
        bytes32 root      = keccak256("stateRoot_A");
        uint64  ts        = uint64(block.timestamp);

        bytes memory sig = _signAttestation(nodeAKey, blockNum, root, ts);

        vm.prank(vm.addr(nodeAKey));
        registry.attest(blockNum, root, ts, sig);

        (bytes32 stored, address attester, bool disputed) = registry.getAttestation(blockNum);
        assertEq(stored,   root,           "wrong state root stored");
        assertEq(attester, vm.addr(nodeAKey), "wrong attester");
        assertFalse(disputed, "should not be disputed");
    }

    function test_invalid_signature_reverts() public {
        uint64  blockNum = 1_000_001;
        bytes32 root     = keccak256("someRoot");
        uint64  ts       = uint64(block.timestamp);

        // Sign with nodeB's key but submit as nodeA — should revert
        bytes memory badSig = _signAttestation(nodeBKey, blockNum, root, ts);

        vm.prank(vm.addr(nodeAKey));
        vm.expectRevert(StateRootRegistry.InvalidSignature.selector);
        registry.attest(blockNum, root, ts, badSig);
    }

    function test_dispute_flow() public {
        uint64  blockNum = 2_000_000;
        bytes32 rootA    = keccak256("rootA");
        bytes32 rootB    = keccak256("rootB_different");
        uint64  ts       = uint64(block.timestamp);

        // NodeA attests rootA
        bytes memory sigA = _signAttestation(nodeAKey, blockNum, rootA, ts);
        vm.prank(vm.addr(nodeAKey));
        registry.attest(blockNum, rootA, ts, sigA);

        // NodeB disputes with rootB
        bytes memory sigB = _signAttestation(nodeBKey, blockNum, rootB, ts);
        vm.prank(vm.addr(nodeBKey));
        registry.dispute(blockNum, rootB, ts, sigB);

        (, , bool disputed) = registry.getAttestation(blockNum);
        assertTrue(disputed, "attestation should be marked disputed");
    }

    function test_client_deposit_and_charge() public {
        // Client deposits
        vm.prank(client);
        registry.deposit{value: 0.01 ether}();
        assertEq(registry.clientBalance(client), 0.01 ether);

        uint256 fee = registry.queryFee();

        // Charge for a query answered by nodeA
        registry.chargeQuery(client, vm.addr(nodeAKey));

        assertEq(registry.clientBalance(client),              0.01 ether - fee);
        assertEq(registry.nodeQueryCredits(vm.addr(nodeAKey)), fee);
    }

    function test_node_registration_requires_min_stake() public {
        address cheapNode = makeAddr("cheapNode");
        vm.deal(cheapNode, 0.01 ether);

        vm.prank(cheapNode);
        vm.expectRevert(NodeRegistry.InsufficientStake.selector);
        nodeReg.register{value: 0.05 ether}(); // below 0.1 ETH minimum
    }

    function test_deregister_cooldown() public {
        address node = vm.addr(nodeAKey);

        // Deregister
        vm.prank(node);
        nodeReg.deregister();

        // Try to withdraw immediately — should fail
        vm.prank(node);
        vm.expectRevert(NodeRegistry.CooldownNotElapsed.selector);
        nodeReg.withdraw();

        // Fast-forward past cooldown
        vm.roll(block.number + NodeRegistry(address(nodeReg)).COOLDOWN_BLOCKS() + 1);

        uint256 balBefore = node.balance;
        vm.prank(node);
        nodeReg.withdraw();

        assertGt(node.balance, balBefore, "should have received stake back");
    }

    function test_fuzz_attest_random_roots(uint64 blockNum, bytes32 root) public {
        vm.assume(blockNum > 0);
        uint64 ts = uint64(block.timestamp);
        bytes memory sig = _signAttestation(nodeAKey, blockNum, root, ts);

        vm.prank(vm.addr(nodeAKey));
        registry.attest(blockNum, root, ts, sig);

        (bytes32 stored, , ) = registry.getAttestation(blockNum);
        assertEq(stored, root);
    }
}
