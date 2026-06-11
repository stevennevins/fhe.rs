// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ConfidentialTokenGateway} from "../src/ConfidentialTokenGateway.sol";

interface Vm {
    function prank(address) external;
}

/// @dev The gas-measurement fixture behind the "On-chain ACL gas
/// impact" table in BENCHMARKS.md: one canonical observed flow
/// (observer set, wrap, confidential transfer), no reverts, so
/// `forge test --match-contract GasImpactTest --gas-report` yields
/// exact per-function costs. Run on any two commits to compare; the
/// table compares the Goal G base (42909d6) against Goal H. Asserts
/// nothing beyond completing — it exists to be measured.
contract GasImpactTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant AGENT = address(0xA9E27);
    address internal constant COPROCESSOR = address(0xC0DE);
    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant EVE = address(0xE7E);

    ConfidentialTokenGateway internal gateway;

    function setUp() public {
        gateway = new ConfidentialTokenGateway(AGENT, COPROCESSOR);
    }

    function testCanonicalFlowGas() public {
        // Observer set first so the observed-grant paths (the ACL's
        // worst case) are the ones measured.
        vm.prank(ALICE);
        gateway.setObserver(EVE);
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(1);
        vm.prank(AGENT);
        gateway.setVerified(BOB, true);
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(2);

        vm.prank(ALICE);
        gateway.faucet(1000);
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(3);
        vm.prank(ALICE);
        gateway.wrap(1000);
        vm.prank(COPROCESSOR);
        gateway.fulfillWrap(4, ALICE, 1000, keccak256("aliceBal1"), bytes32(uint256(1)));

        vm.prank(COPROCESSOR);
        gateway.registerInput(keccak256("input1"), bytes32(uint256(2)), ALICE);
        vm.prank(ALICE);
        gateway.confidentialTransfer(BOB, keccak256("input1"));
        vm.prank(COPROCESSOR);
        gateway.fulfillTransfer(
            5,
            ALICE,
            BOB,
            keccak256("input1"),
            keccak256("aliceBal2"),
            bytes32(uint256(3)),
            keccak256("bobBal1"),
            bytes32(uint256(4)),
            keccak256("moved1"),
            bytes32(uint256(5))
        );
    }
}
