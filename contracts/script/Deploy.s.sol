// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {NodeRegistry}      from "../src/NodeRegistry.sol";
import {StateRootRegistry} from "../src/StateRootRegistry.sol";

/// @dev Deploy the full VerifiableRPC protocol.
///
/// Usage:
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url $RPC_URL \
///     --broadcast \
///     --verify \
///     -vvvv
contract Deploy is Script {
    function run() external {
        uint256 deployer  = vm.envUint("PRIVATE_KEY");
        address treasury  = vm.envAddress("TREASURY_ADDRESS");
        uint256 chainId   = block.chainid;

        vm.startBroadcast(deployer);

        // 1. Deploy NodeRegistry
        NodeRegistry nodeReg = new NodeRegistry(treasury);
        console.log("NodeRegistry deployed at:", address(nodeReg));

        // 2. Deploy StateRootRegistry
        StateRootRegistry registry = new StateRootRegistry(
            address(nodeReg),
            chainId
        );
        console.log("StateRootRegistry deployed at:", address(registry));

        // 3. Wire up: StateRootRegistry is authorised to slash
        nodeReg.setSlasher(address(registry));
        console.log("Slasher configured");

        vm.stopBroadcast();

        // Emit addresses for automated tooling
        console.log("---");
        console.log("NODE_REGISTRY=", address(nodeReg));
        console.log("STATE_ROOT_REGISTRY=", address(registry));
    }
}
