// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ConfidentialTokenGateway} from "../src/ConfidentialTokenGateway.sol";

/// @dev Minimal cheatcode surface — deliberately no forge-std: this repo
/// is a Rust workspace and vendoring a Solidity dependency tree for two
/// cheatcodes is not worth it. A test passes if it does not revert.
interface Vm {
    function prank(address) external;
    function expectRevert(bytes calldata) external;
    function expectRevert() external;
}

contract ConfidentialTokenGatewayTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    address internal constant AGENT = address(0xA9E27);
    address internal constant COPROCESSOR = address(0xC0DE);
    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);

    ConfidentialTokenGateway internal gateway;

    function setUp() public {
        gateway = new ConfidentialTokenGateway(AGENT, COPROCESSOR);
    }

    function _registerInput(bytes32 handle, address owner) internal {
        vm.prank(COPROCESSOR);
        gateway.registerInput(handle, keccak256(abi.encode(handle)), owner);
    }

    /// @dev Puts a balance handle on `account` so transfer-shaped entry
    /// points pass the NoBalance check: faucet + wrap + fulfillWrap.
    function _fundConfidential(address account) internal {
        vm.prank(account);
        gateway.faucet(1000);
        uint64 id = gateway.lastFulfilledId() + 1;
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(id);
        vm.prank(account);
        gateway.wrap(1000);
        id = gateway.lastFulfilledId() + 1;
        vm.prank(COPROCESSOR);
        gateway.fulfillWrap(id, account, 1000, keccak256(abi.encode(account, "balance")), bytes32(uint256(1)));
    }

    function testRolesAreSetAtDeploy() public view {
        require(gateway.agent() == AGENT, "agent");
        require(gateway.coprocessor() == COPROCESSOR, "coprocessor");
        require(gateway.nextRequestId() == 1, "nextRequestId");
        require(gateway.lastFulfilledId() == 0, "lastFulfilledId");
    }

    function testWrapDebitsPublicBalanceAndAssignsRequestId() public {
        vm.prank(ALICE);
        gateway.faucet(500);
        require(gateway.publicBalance(ALICE) == 500, "faucet credit");
        vm.prank(ALICE);
        gateway.wrap(200);
        require(gateway.publicBalance(ALICE) == 300, "wrap debit");
        require(gateway.nextRequestId() == 3, "two requests assigned");
    }

    function testWrapOverPublicBalanceReverts() public {
        vm.prank(ALICE);
        gateway.faucet(100);
        vm.expectRevert(
            abi.encodeWithSelector(ConfidentialTokenGateway.InsufficientPublicBalance.selector, ALICE, 100, 101)
        );
        vm.prank(ALICE);
        gateway.wrap(101);
    }

    function testOnlyCoprocessorMayFulfill() public {
        vm.prank(ALICE);
        gateway.faucet(1);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotCoprocessor.selector));
        vm.prank(ALICE);
        gateway.fulfillAck(1);
    }

    function testOnlyCoprocessorMayRegisterInputs() public {
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotCoprocessor.selector));
        vm.prank(ALICE);
        gateway.registerInput(bytes32(uint256(1)), bytes32(uint256(2)), ALICE);
    }

    function testFulfillmentMustBeInRequestOrder() public {
        vm.prank(ALICE);
        gateway.faucet(1);
        vm.prank(ALICE);
        gateway.faucet(2);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.OutOfOrderFulfillment.selector, 2, 1));
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(2);
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(1);
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(2);
        require(gateway.lastFulfilledId() == 2, "cursor advanced");
    }

    function testFulfillmentOfNonexistentRequestReverts() public {
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.OutOfOrderFulfillment.selector, 1, 1));
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(1);
    }

    function testFulfillmentMustMatchRequestPayload() public {
        _fundConfidential(ALICE);
        _registerInput(bytes32(uint256(0xA)), ALICE);
        vm.prank(AGENT);
        gateway.setVerified(BOB, true);
        uint64 id = gateway.lastFulfilledId() + 1;
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(id);
        vm.prank(ALICE);
        gateway.transfer(BOB, bytes32(uint256(0xA)));
        id = gateway.lastFulfilledId() + 1;
        // Right id, wrong payload (recipient swapped for the sender).
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.RequestMismatch.selector, id));
        vm.prank(COPROCESSOR);
        gateway.fulfillTransfer(
            id,
            ALICE,
            ALICE,
            bytes32(uint256(0xA)),
            bytes32(uint256(1)),
            0,
            bytes32(uint256(2)),
            0,
            bytes32(uint256(3)),
            0
        );
        // A transfer request cannot be acked away.
        vm.expectRevert();
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(id);
    }

    function testTransferRejectsUnregisteredInput() public {
        _fundConfidential(ALICE);
        vm.prank(AGENT);
        gateway.setVerified(BOB, true);
        vm.expectRevert(
            abi.encodeWithSelector(ConfidentialTokenGateway.UnknownInput.selector, bytes32(uint256(0xDEAD)))
        );
        vm.prank(ALICE);
        gateway.transfer(BOB, bytes32(uint256(0xDEAD)));
    }

    function testTransferRejectsInputOwnedByAnotherAccount() public {
        _fundConfidential(BOB);
        _registerInput(bytes32(uint256(0xA)), ALICE);
        vm.prank(AGENT);
        gateway.setVerified(ALICE, true);
        vm.expectRevert(
            abi.encodeWithSelector(ConfidentialTokenGateway.NotInputOwner.selector, bytes32(uint256(0xA)), BOB)
        );
        vm.prank(BOB);
        gateway.transfer(ALICE, bytes32(uint256(0xA)));
    }

    function testReanchoringAHandleReverts() public {
        _registerInput(bytes32(uint256(0xA)), ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(ConfidentialTokenGateway.HandleAlreadyAnchored.selector, bytes32(uint256(0xA)))
        );
        vm.prank(COPROCESSOR);
        gateway.registerInput(bytes32(uint256(0xA)), bytes32(uint256(0xB)), BOB);
    }

    function testTransferPolicyGates() public {
        _fundConfidential(ALICE);
        _registerInput(bytes32(uint256(0xA)), ALICE);

        // Unverified recipient.
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.RecipientNotVerified.selector, BOB));
        vm.prank(ALICE);
        gateway.transfer(BOB, bytes32(uint256(0xA)));

        vm.prank(AGENT);
        gateway.setVerified(BOB, true);

        // Paused.
        vm.prank(AGENT);
        gateway.setPaused(true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.TransfersPaused.selector));
        vm.prank(ALICE);
        gateway.transfer(BOB, bytes32(uint256(0xA)));
        vm.prank(AGENT);
        gateway.setPaused(false);

        // Blocked sender, then blocked recipient.
        vm.prank(AGENT);
        gateway.setBlocked(ALICE, true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.AccountBlocked.selector, ALICE));
        vm.prank(ALICE);
        gateway.transfer(BOB, bytes32(uint256(0xA)));
        vm.prank(AGENT);
        gateway.setBlocked(ALICE, false);
        vm.prank(AGENT);
        gateway.setBlocked(BOB, true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.AccountBlocked.selector, BOB));
        vm.prank(ALICE);
        gateway.transfer(BOB, bytes32(uint256(0xA)));
    }

    function testAgentRoleGates() public {
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.setPaused(true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.setBlocked(BOB, true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.setVerified(BOB, true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.setConfidentialFrozen(BOB, bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.forceTransfer(BOB, ALICE, bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.recover(BOB, ALICE);
    }

    function testSetObserverOnlyTouchesOwnAccount() public {
        vm.prank(ALICE);
        gateway.setObserver(BOB);
        require(gateway.observerOf(ALICE) == BOB, "alice observer");
        // Another sender's call cannot touch alice's observer: the entry
        // point has no account parameter at all.
        vm.prank(BOB);
        gateway.setObserver(address(0xE4E));
        require(gateway.observerOf(ALICE) == BOB, "alice unchanged");
        require(gateway.observerOf(BOB) == address(0xE4E), "bob own");
    }

    function testForceTransferBypassesPublicPolicy() public {
        _fundConfidential(ALICE);
        vm.prank(COPROCESSOR);
        gateway.registerInput(bytes32(uint256(0xF0)), keccak256("force"), AGENT);
        vm.prank(AGENT);
        gateway.setPaused(true);
        vm.prank(AGENT);
        gateway.setBlocked(ALICE, true);
        // No revert despite pause + block + unverified recipient.
        vm.prank(AGENT);
        gateway.forceTransfer(ALICE, BOB, bytes32(uint256(0xF0)));
    }
}
