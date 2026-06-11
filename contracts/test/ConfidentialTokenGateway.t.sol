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

    // ------------------------------------------------------------------
    // On-chain ACL (Goal H1): grant-authorization rules.
    // ------------------------------------------------------------------

    function testRegisterInputGrantsOwnerOnAcl() public {
        bytes32 handle = keccak256("input");
        _registerInput(handle, ALICE);
        require(gateway.isAllowed(handle, ALICE), "owner allowed");
        require(!gateway.isAllowed(handle, BOB), "others not allowed");
    }

    function testAllowRequiresChainOfCustody() public {
        bytes32 handle = keccak256("input");
        _registerInput(handle, ALICE);
        // A caller the ACL does not allow cannot grant.
        vm.prank(BOB);
        vm.expectRevert(
            abi.encodeWithSelector(ConfidentialTokenGateway.NotAllowed.selector, handle, BOB)
        );
        gateway.allow(handle, BOB);
        // The owner grants bob; bob may then grant onward.
        vm.prank(ALICE);
        gateway.allow(handle, BOB);
        require(gateway.isAllowed(handle, BOB), "grantee allowed");
        vm.prank(BOB);
        gateway.allow(handle, address(0xCA401));
        require(gateway.isAllowed(handle, address(0xCA401)), "second-hop grant");
    }

    function testAllowIsARequestAckedByTheCoprocessor() public {
        bytes32 handle = keccak256("input");
        _registerInput(handle, ALICE);
        uint64 id = gateway.nextRequestId();
        vm.prank(ALICE);
        gateway.allow(handle, BOB);
        require(gateway.nextRequestId() == id + 1, "allow assigns a request id");
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(id);
        require(gateway.lastFulfilledId() == id, "acked");
    }

    function testWrapFulfillmentGrantsAccountAndObserverSnapshot() public {
        address observer = address(0x0B5);
        vm.prank(ALICE);
        gateway.setObserver(observer);
        uint64 id = gateway.lastFulfilledId() + 1;
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(id);
        _fundConfidential(ALICE);
        bytes32 balance = gateway.confidentialBalanceOf(ALICE);
        require(gateway.isAllowed(balance, ALICE), "account allowed");
        require(gateway.isAllowed(balance, observer), "observer allowed");
        require(!gateway.isAllowed(balance, BOB), "stranger denied");
    }

    function testTransferGrantsUseTheRequestTimeObserverSnapshot() public {
        _fundConfidential(ALICE);
        _fundConfidential(BOB);
        vm.prank(AGENT);
        gateway.setVerified(BOB, true);
        uint64 id = gateway.lastFulfilledId() + 1;
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(id);

        address lateObserver = address(0x1A7E);
        bytes32 input = keccak256("amount");
        _registerInput(input, ALICE);
        vm.prank(ALICE);
        gateway.confidentialTransfer(BOB, input);
        uint64 transferId = gateway.nextRequestId() - 1;
        // The observer set AFTER the request must not be granted at its
        // fulfillment: the coprocessor mirrors observer state in request
        // order, and the grant must match what it saw.
        vm.prank(ALICE);
        gateway.setObserver(lateObserver);

        bytes32 newFrom = keccak256("newFrom");
        bytes32 newTo = keccak256("newTo");
        bytes32 moved = keccak256("moved");
        vm.prank(COPROCESSOR);
        gateway.fulfillTransfer(
            transferId, ALICE, BOB, input, newFrom, bytes32(uint256(1)), newTo, bytes32(uint256(2)), moved, bytes32(uint256(3))
        );
        require(gateway.isAllowed(newFrom, ALICE), "sender on own balance");
        require(gateway.isAllowed(newTo, BOB), "recipient on own balance");
        require(gateway.isAllowed(moved, ALICE) && gateway.isAllowed(moved, BOB), "parties on amount");
        require(!gateway.isAllowed(newFrom, lateObserver), "post-request observer not granted");
        require(!gateway.isAllowed(newTo, ALICE), "sender not on recipient balance");
    }

    function testForceTransferGrantsNoObservers() public {
        _fundConfidential(ALICE);
        _fundConfidential(BOB);
        address observer = address(0x0B5);
        vm.prank(ALICE);
        gateway.setObserver(observer);
        uint64 id = gateway.lastFulfilledId() + 1;
        vm.prank(COPROCESSOR);
        gateway.fulfillAck(id);

        bytes32 input = keccak256("amount");
        _registerInput(input, AGENT);
        vm.prank(AGENT);
        gateway.forceConfidentialTransferFrom(ALICE, BOB, input);
        uint64 forceId = gateway.nextRequestId() - 1;
        bytes32 newFrom = keccak256("fNewFrom");
        bytes32 newTo = keccak256("fNewTo");
        bytes32 moved = keccak256("fMoved");
        vm.prank(COPROCESSOR);
        gateway.fulfillTransfer(
            forceId, ALICE, BOB, input, newFrom, bytes32(uint256(1)), newTo, bytes32(uint256(2)), moved, bytes32(uint256(3))
        );
        require(gateway.isAllowed(newFrom, ALICE) && gateway.isAllowed(newTo, BOB), "parties allowed");
        require(!gateway.isAllowed(newFrom, observer), "force transfers are unobserved");
        require(!gateway.isAllowed(moved, observer), "force amount unobserved");
    }

    function testFrozenSetGrantsAccountAndFreezer() public {
        _fundConfidential(ALICE);
        bytes32 input = keccak256("frozen");
        _registerInput(input, AGENT);
        vm.prank(AGENT);
        gateway.setConfidentialFrozen(ALICE, input);
        uint64 id = gateway.nextRequestId() - 1;
        bytes32 newFrozen = keccak256("newFrozen");
        vm.prank(COPROCESSOR);
        gateway.fulfillFrozenSet(id, ALICE, input, newFrozen, bytes32(uint256(1)));
        require(gateway.isAllowed(newFrozen, ALICE), "account reads its frozen amount");
        require(gateway.isAllowed(newFrozen, AGENT), "freezer reads it too");
        require(!gateway.isAllowed(newFrozen, BOB), "stranger denied");
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
        gateway.confidentialTransfer(BOB, bytes32(uint256(0xA)));
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
        gateway.confidentialTransfer(BOB, bytes32(uint256(0xDEAD)));
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
        gateway.confidentialTransfer(ALICE, bytes32(uint256(0xA)));
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
        gateway.confidentialTransfer(BOB, bytes32(uint256(0xA)));

        vm.prank(AGENT);
        gateway.setVerified(BOB, true);

        // Paused.
        vm.prank(AGENT);
        gateway.pause();
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.TransfersPaused.selector));
        vm.prank(ALICE);
        gateway.confidentialTransfer(BOB, bytes32(uint256(0xA)));
        vm.prank(AGENT);
        gateway.unpause();

        // Blocked sender, then blocked recipient.
        vm.prank(AGENT);
        gateway.blockUser(ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.AccountBlocked.selector, ALICE));
        vm.prank(ALICE);
        gateway.confidentialTransfer(BOB, bytes32(uint256(0xA)));
        vm.prank(AGENT);
        gateway.unblockUser(ALICE);
        vm.prank(AGENT);
        gateway.blockUser(BOB);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.AccountBlocked.selector, BOB));
        vm.prank(ALICE);
        gateway.confidentialTransfer(BOB, bytes32(uint256(0xA)));
    }

    function testAgentRoleGates() public {
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.pause();
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.blockUser(BOB);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.setVerified(BOB, true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.setConfidentialFrozen(BOB, bytes32(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAgent.selector));
        vm.prank(ALICE);
        gateway.forceConfidentialTransferFrom(BOB, ALICE, bytes32(uint256(1)));
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

    function testTransferWithoutBalanceReverts() public {
        _registerInput(bytes32(uint256(0xA)), ALICE);
        vm.prank(AGENT);
        gateway.setVerified(BOB, true);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NoBalance.selector, ALICE));
        vm.prank(ALICE);
        gateway.confidentialTransfer(BOB, bytes32(uint256(0xA)));
    }

    function testUnwrapGates() public {
        // No confidential balance.
        _registerInput(bytes32(uint256(0xA)), ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NoBalance.selector, ALICE));
        vm.prank(ALICE);
        gateway.unwrap(bytes32(uint256(0xA)));
        // Funded, but spending someone else's input.
        _fundConfidential(ALICE);
        _registerInput(bytes32(uint256(0xB)), BOB);
        vm.expectRevert(
            abi.encodeWithSelector(ConfidentialTokenGateway.NotInputOwner.selector, bytes32(uint256(0xB)), ALICE)
        );
        vm.prank(ALICE);
        gateway.unwrap(bytes32(uint256(0xB)));
    }

    function testUnwrapFailureCreditsNothingAndKeepsBalanceHandle() public {
        _fundConfidential(ALICE);
        _registerInput(bytes32(uint256(0xA)), ALICE);
        bytes32 handleBefore = gateway.confidentialBalanceOf(ALICE);
        uint64 publicBefore = gateway.publicBalance(ALICE);
        vm.prank(ALICE);
        gateway.unwrap(bytes32(uint256(0xA)));
        uint64 id = gateway.lastFulfilledId() + 1;
        vm.prank(COPROCESSOR);
        gateway.fulfillUnwrap(id, ALICE, bytes32(uint256(0xA)), 9999, false, 0, 0);
        require(gateway.publicBalance(ALICE) == publicBefore, "no credit on failure");
        require(gateway.confidentialBalanceOf(ALICE) == handleBefore, "balance handle untouched");
        require(gateway.lastFulfilledId() == id, "request still consumed");
    }

    function testForceTransferBypassesPublicPolicy() public {
        _fundConfidential(ALICE);
        vm.prank(COPROCESSOR);
        gateway.registerInput(bytes32(uint256(0xF0)), keccak256("force"), AGENT);
        vm.prank(AGENT);
        gateway.pause();
        vm.prank(AGENT);
        gateway.blockUser(ALICE);
        // No revert despite pause + block + unverified recipient.
        vm.prank(AGENT);
        gateway.forceConfidentialTransferFrom(ALICE, BOB, bytes32(uint256(0xF0)));
    }
}
