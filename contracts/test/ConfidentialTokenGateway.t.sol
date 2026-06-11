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

    // Mirrors of the gateway's symbolic-op constants (a getter call
    // would consume vm.prank); pinned against the contract in
    // testSymbolicConstantsMatch.
    uint8 internal constant SOP_ADD = 1;
    uint8 internal constant SOP_GE = 3;
    uint8 internal constant SOP_SELECT = 4;
    uint8 internal constant TYPE_EBOOL = 0;

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

    // ------------------------------------------------------------------
    // Symbolic ops (Goal H2): derivation, authorization, deferred
    // binding.
    // ------------------------------------------------------------------

    /// @dev The documented derivation, recomputed independently.
    function _expectedSymbolicHandle(
        uint8 op,
        bytes32 lhs,
        bytes32 rhs,
        bytes32 cond,
        uint64 id,
        uint32 index,
        uint8 typeTag
    ) internal pure returns (bytes32) {
        uint256 h = uint256(keccak256(abi.encodePacked("fhe.rs/sym", op, lhs, rhs, cond, id, index)));
        h = (h & ~(uint256(0xff) << 80)) | (uint256(0xff) << 80);
        h = (h & ~(uint256(0xff) << 8)) | (uint256(typeTag) << 8);
        h = (h & ~uint256(0xff));
        return bytes32(h); // version byte 31 is 0
    }

    function testSymbolicConstantsMatch() public view {
        require(gateway.SOP_ADD() == SOP_ADD, "SOP_ADD");
        require(gateway.SOP_GE() == SOP_GE, "SOP_GE");
        require(gateway.SOP_SELECT() == SOP_SELECT, "SOP_SELECT");
        require(gateway.TYPE_EBOOL() == TYPE_EBOOL, "TYPE_EBOOL");
        require(gateway.TYPE_EUINT64() == 5, "TYPE_EUINT64");
        require(gateway.HANDLE_VERSION() == 0, "HANDLE_VERSION");
        require(gateway.SOP_SUB() == 2, "SOP_SUB");
    }

    function testRequestOpDerivesTheDocumentedHandle() public {
        bytes32 x = keccak256("x");
        bytes32 y = keccak256("y");
        _registerInput(x, ALICE);
        _registerInput(y, ALICE);
        uint64 id = gateway.nextRequestId();
        vm.prank(ALICE);
        bytes32 result = gateway.requestOp(SOP_GE, x, y, bytes32(0));
        require(
            result == _expectedSymbolicHandle(SOP_GE, x, y, bytes32(0), id, 0, TYPE_EBOOL),
            "ge handle derivation"
        );
        require(uint8(result[21]) == 0xff, "computed marker byte");
        require(uint8(result[30]) == TYPE_EBOOL, "type tag byte");
        require(uint8(result[31]) == 0, "version byte");
        require(gateway.isAllowed(result, ALICE), "caller allowed on result");
    }

    function testRequestOpRequiresAllowedOperands() public {
        bytes32 x = keccak256("x");
        bytes32 y = keccak256("y");
        _registerInput(x, ALICE);
        _registerInput(y, ALICE);
        // Bob is not allowed on alice's inputs.
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.NotAllowed.selector, x, BOB));
        gateway.requestOp(SOP_ADD, x, y, bytes32(0));
        // A never-created handle has no grants: same revert.
        vm.prank(ALICE);
        vm.expectRevert();
        gateway.requestOp(SOP_ADD, x, keccak256("never"), bytes32(0));
    }

    function testRequestOpArityAndTypeChecks() public {
        bytes32 x = keccak256("x");
        bytes32 y = keccak256("y");
        _registerInput(x, ALICE);
        _registerInput(y, ALICE);
        // cond must be zero for two-operand ops.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.WrongArity.selector, SOP_ADD));
        gateway.requestOp(SOP_ADD, x, y, x);
        // select's cond must be an ebool, not a euint64 input.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.WrongOperandType.selector, x));
        gateway.requestOp(SOP_SELECT, x, y, x);
        // an ebool result is not a euint64 operand.
        vm.prank(ALICE);
        bytes32 bit = gateway.requestOp(SOP_GE, x, y, bytes32(0));
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.WrongOperandType.selector, bit));
        gateway.requestOp(SOP_ADD, bit, y, bytes32(0));
        // the alphabet is closed.
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.UnknownOp.selector, uint8(99)));
        gateway.requestOp(99, x, y, bytes32(0));
    }

    function testOpCommitmentIsDeferredAndChainingWorksBeforeIt() public {
        bytes32 x = keccak256("x");
        bytes32 y = keccak256("y");
        _registerInput(x, ALICE);
        _registerInput(y, ALICE);
        vm.prank(ALICE);
        bytes32 bit = gateway.requestOp(SOP_GE, x, y, bytes32(0));
        uint64 geId = gateway.nextRequestId() - 1;
        // The promise: no commitment yet.
        require(gateway.handleCommitment(bit) == bytes32(0), "commitment deferred");
        // Chaining on the unmaterialized result is the point: select
        // over it in a later transaction, before any fulfillment.
        vm.prank(ALICE);
        bytes32 picked = gateway.requestOp(SOP_SELECT, x, y, bit);
        uint64 selectId = gateway.nextRequestId() - 1;
        // Fulfillment binds in order, with the echoed request payload.
        vm.prank(COPROCESSOR);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.RequestMismatch.selector, geId));
        gateway.fulfillOp(geId, ALICE, SOP_GE, x, y, bytes32(0), keccak256("wrong"), bytes32(uint256(7)));
        vm.prank(COPROCESSOR);
        gateway.fulfillOp(geId, ALICE, SOP_GE, x, y, bytes32(0), bit, bytes32(uint256(7)));
        require(gateway.handleCommitment(bit) == bytes32(uint256(7)), "deferred binding posted");
        vm.prank(COPROCESSOR);
        gateway.fulfillOp(selectId, ALICE, SOP_SELECT, x, y, bit, picked, bytes32(uint256(8)));
        require(gateway.handleCommitment(picked) == bytes32(uint256(8)), "second binding posted");
        require(gateway.lastFulfilledId() == selectId, "both fulfilled in order");
    }

    // ------------------------------------------------------------------
    // Atomic batches (Goal H3): indexed derivation, intra-batch refs,
    // one fulfillment.
    // ------------------------------------------------------------------

    function _twoInputs() internal returns (bytes32 x, bytes32 y) {
        x = keccak256("x");
        y = keccak256("y");
        _registerInput(x, ALICE);
        _registerInput(y, ALICE);
    }

    function testBatchDerivesIndexedHandlesAndResolvesRefs() public {
        (bytes32 x, bytes32 y) = _twoInputs();
        ConfidentialTokenGateway.SymbolicOp[] memory ops = new ConfidentialTokenGateway.SymbolicOp[](3);
        ops[0] = ConfidentialTokenGateway.SymbolicOp(SOP_GE, x, y, bytes32(0));
        ops[1] = ConfidentialTokenGateway.SymbolicOp(SOP_SELECT, x, y, gateway.batchRef(0));
        ops[2] = ConfidentialTokenGateway.SymbolicOp(SOP_ADD, gateway.batchRef(1), y, bytes32(0));
        uint64 id = gateway.nextRequestId();
        vm.prank(ALICE);
        bytes32[] memory results = gateway.requestBatch(ops);
        // Derivation: refs resolve to the earlier RESULT handles before
        // hashing, and the op index separates handles within the batch.
        require(
            results[0] == _expectedSymbolicHandle(SOP_GE, x, y, bytes32(0), id, 0, TYPE_EBOOL),
            "op 0 derivation"
        );
        require(
            results[1] == _expectedSymbolicHandle(SOP_SELECT, x, y, results[0], id, 1, 5),
            "op 1 derivation resolves the ref"
        );
        require(
            results[2] == _expectedSymbolicHandle(SOP_ADD, results[1], y, bytes32(0), id, 2, 5),
            "op 2 derivation resolves the ref"
        );
        for (uint256 i = 0; i < 3; i++) {
            require(gateway.isAllowed(results[i], ALICE), "caller allowed on every result");
            require(gateway.handleCommitment(results[i]) == bytes32(0), "commitments deferred");
        }
        require(gateway.nextRequestId() == id + 1, "ONE request id for the whole batch");
    }

    function testBatchRefsMustPointStrictlyBackwards() public {
        (bytes32 x, bytes32 y) = _twoInputs();
        ConfidentialTokenGateway.SymbolicOp[] memory ops = new ConfidentialTokenGateway.SymbolicOp[](1);
        // A self-reference (index 0 in op 0) cannot resolve.
        ops[0] = ConfidentialTokenGateway.SymbolicOp(SOP_ADD, gateway.batchRef(0), y, bytes32(0));
        bytes32 selfRef = gateway.batchRef(0);
        vm.prank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(ConfidentialTokenGateway.RefOutOfRange.selector, selfRef, 0)
        );
        gateway.requestBatch(ops);
        // Type checks see through refs: an ebool result is not a
        // euint64 operand even via a marker.
        ConfidentialTokenGateway.SymbolicOp[] memory typed = new ConfidentialTokenGateway.SymbolicOp[](2);
        typed[0] = ConfidentialTokenGateway.SymbolicOp(SOP_GE, x, y, bytes32(0));
        typed[1] = ConfidentialTokenGateway.SymbolicOp(SOP_ADD, gateway.batchRef(0), y, bytes32(0));
        vm.prank(ALICE);
        vm.expectRevert();
        gateway.requestBatch(typed);
    }

    function testBatchSizeBoundsArePinned() public {
        (bytes32 x, bytes32 y) = _twoInputs();
        ConfidentialTokenGateway.SymbolicOp[] memory empty = new ConfidentialTokenGateway.SymbolicOp[](0);
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.EmptyBatch.selector));
        gateway.requestBatch(empty);

        uint256 over = gateway.MAX_BATCH_OPS() + 1;
        ConfidentialTokenGateway.SymbolicOp[] memory tooLarge = new ConfidentialTokenGateway.SymbolicOp[](over);
        for (uint256 i = 0; i < over; i++) {
            tooLarge[i] = ConfidentialTokenGateway.SymbolicOp(SOP_ADD, x, y, bytes32(0));
        }
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.BatchTooLarge.selector, over));
        gateway.requestBatch(tooLarge);
    }

    function testFulfillBatchPostsEveryCommitmentInOneTransaction() public {
        (bytes32 x, bytes32 y) = _twoInputs();
        ConfidentialTokenGateway.SymbolicOp[] memory ops = new ConfidentialTokenGateway.SymbolicOp[](2);
        ops[0] = ConfidentialTokenGateway.SymbolicOp(SOP_GE, x, y, bytes32(0));
        ops[1] = ConfidentialTokenGateway.SymbolicOp(SOP_SELECT, x, y, gateway.batchRef(0));
        uint64 id = gateway.nextRequestId();
        vm.prank(ALICE);
        bytes32[] memory results = gateway.requestBatch(ops);

        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = bytes32(uint256(11));
        commitments[1] = bytes32(uint256(22));
        // Shape and payload binding are enforced.
        bytes32[] memory short = new bytes32[](1);
        vm.prank(COPROCESSOR);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.BatchShapeMismatch.selector, id));
        gateway.fulfillBatch(id, ALICE, ops, results, short);
        vm.prank(COPROCESSOR);
        vm.expectRevert(abi.encodeWithSelector(ConfidentialTokenGateway.RequestMismatch.selector, id));
        gateway.fulfillBatch(id, BOB, ops, results, commitments);
        // One transaction posts both deferred bindings.
        vm.prank(COPROCESSOR);
        gateway.fulfillBatch(id, ALICE, ops, results, commitments);
        require(gateway.handleCommitment(results[0]) == commitments[0], "first binding");
        require(gateway.handleCommitment(results[1]) == commitments[1], "second binding");
        require(gateway.lastFulfilledId() == id, "one fulfillment for the batch");
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
