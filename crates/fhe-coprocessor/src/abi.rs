//! Typed bindings for `ConfidentialTokenGateway.sol`, kept by hand in
//! sync with the contract (the deploy helper in [`crate::harness`] uses
//! the forge-built bytecode, so a drift fails loudly at test time).

// The generated call builders take one argument per Solidity parameter;
// the fulfillment functions carry (handle, commitment) pairs by design.
#![allow(clippy::too_many_arguments)]

use alloy::sol;

sol! {
    /// The on-chain gateway interface. See
    /// `contracts/src/ConfidentialTokenGateway.sol` for semantics.
    #[sol(rpc)]
    #[derive(Debug)]
    interface IConfidentialTokenGateway {
        /// One op of an atomic symbolic batch.
        struct SymbolicOp {
            uint8 op;
            bytes32 lhs;
            bytes32 rhs;
            bytes32 cond;
        }

        function agent() external view returns (address);
        function coprocessor() external view returns (address);
        function nextRequestId() external view returns (uint64);
        function lastFulfilledId() external view returns (uint64);
        function publicBalance(address account) external view returns (uint64);
        function confidentialBalanceOf(address account) external view returns (bytes32);
        function confidentialFrozen(address account) external view returns (bytes32);
        function handleCommitment(bytes32 handle) external view returns (bytes32);
        function inputOwner(bytes32 handle) external view returns (address);
        function paused() external view returns (bool);
        function blocked(address account) external view returns (bool);
        function isVerified(address account) external view returns (bool);
        function observerOf(address account) external view returns (address);
        function isAllowed(bytes32 handle, address account) external view returns (bool);

        function faucet(uint64 amount) external;
        function wrap(uint64 amount) external;
        function confidentialTransfer(address to, bytes32 amountHandle) external;
        function setObserver(address observer) external;
        function setVerified(address account, bool isVerified) external;
        function setConfidentialFrozen(address account, bytes32 amountHandle) external;
        function blockUser(address account) external;
        function unblockUser(address account) external;
        function pause() external;
        function unpause() external;
        function forceConfidentialTransferFrom(address from, address to, bytes32 amountHandle) external;
        function recover(address lost, address recipient) external;
        function unwrap(bytes32 amountHandle) external;
        function allow(bytes32 handle, address account) external;
        function requestOp(uint8 op, bytes32 lhs, bytes32 rhs, bytes32 cond) external returns (bytes32 result);
        function requestBatch(SymbolicOp[] calldata ops) external returns (bytes32[] memory results);
        function batchRef(uint256 index) external pure returns (bytes32);

        function registerInput(bytes32 handle, bytes32 commitment, address owner) external;
        function fulfillAck(uint64 id) external;
        function fulfillWrap(
            uint64 id,
            address account,
            uint64 amount,
            bytes32 newBalanceHandle,
            bytes32 newBalanceCommitment
        ) external;
        function fulfillTransfer(
            uint64 id,
            address from,
            address to,
            bytes32 amountHandle,
            bytes32 newFromHandle,
            bytes32 newFromCommitment,
            bytes32 newToHandle,
            bytes32 newToCommitment,
            bytes32 transferredHandle,
            bytes32 transferredCommitment
        ) external;
        function fulfillFrozenSet(
            uint64 id,
            address account,
            bytes32 amountHandle,
            bytes32 newFrozenHandle,
            bytes32 newFrozenCommitment
        ) external;
        function fulfillRecover(
            uint64 id,
            address lost,
            address recipient,
            bytes32 newLostHandle,
            bytes32 newLostCommitment,
            bytes32 newRecipientHandle,
            bytes32 newRecipientCommitment,
            bytes32 newRecipientFrozenHandle,
            bytes32 newRecipientFrozenCommitment
        ) external;
        function fulfillOp(
            uint64 id,
            address caller,
            uint8 op,
            bytes32 lhs,
            bytes32 rhs,
            bytes32 cond,
            bytes32 result,
            bytes32 commitment
        ) external;
        function fulfillBatch(
            uint64 id,
            address caller,
            SymbolicOp[] calldata ops,
            bytes32[] calldata results,
            bytes32[] calldata commitments
        ) external;
        function fulfillUnwrap(
            uint64 id,
            address account,
            bytes32 amountHandle,
            uint64 amount,
            bool success,
            bytes32 newBalanceHandle,
            bytes32 newBalanceCommitment
        ) external;

        event FaucetRequested(uint64 indexed id, address indexed account, uint64 amount);
        event WrapRequested(uint64 indexed id, address indexed account, uint64 amount);
        event TransferRequested(uint64 indexed id, address indexed from, address indexed to, bytes32 amountHandle);
        event ObserverSetRequested(uint64 indexed id, address indexed account, address observer);
        event VerifiedSetRequested(uint64 indexed id, address indexed account, bool verified);
        event FrozenSetRequested(uint64 indexed id, address indexed account, bytes32 amountHandle);
        event BlockedSetRequested(uint64 indexed id, address indexed account, bool blocked);
        event PausedSetRequested(uint64 indexed id, bool paused);
        event ForceTransferRequested(uint64 indexed id, address indexed from, address indexed to, bytes32 amountHandle);
        event RecoverRequested(uint64 indexed id, address indexed lost, address indexed recipient);
        event UnwrapRequested(uint64 indexed id, address indexed account, bytes32 amountHandle);
        event AllowRequested(uint64 indexed id, bytes32 indexed handle, address indexed account);
        event OpRequested(
            uint64 indexed id,
            address indexed caller,
            uint8 op,
            bytes32 lhs,
            bytes32 rhs,
            bytes32 cond,
            bytes32 result
        );
        event InputRegistered(bytes32 indexed handle, bytes32 commitment, address indexed owner);
        event Allowed(bytes32 indexed handle, address indexed account);

        event RequestAcked(uint64 indexed id);
        event WrapFulfilled(uint64 indexed id, address indexed account, bytes32 newBalanceHandle);
        event TransferFulfilled(
            uint64 indexed id,
            address indexed from,
            address indexed to,
            bytes32 newFromHandle,
            bytes32 newToHandle,
            bytes32 transferredHandle
        );
        event FrozenSetFulfilled(uint64 indexed id, address indexed account, bytes32 newFrozenHandle);
        event RecoverFulfilled(
            uint64 indexed id,
            address indexed lost,
            address indexed recipient,
            bytes32 newLostHandle,
            bytes32 newRecipientHandle,
            bytes32 newRecipientFrozenHandle
        );
        event UnwrapFulfilled(
            uint64 indexed id,
            address indexed account,
            uint64 amount,
            bool success,
            bytes32 newBalanceHandle
        );

        error NotAgent();
        error NotCoprocessor();
        error TransfersPaused();
        error AccountBlocked(address account);
        error RecipientNotVerified(address account);
        error UnknownInput(bytes32 handle);
        error NotInputOwner(bytes32 handle, address caller);
        error NoBalance(address account);
        error InsufficientPublicBalance(address account, uint64 balance, uint64 amount);
        error OutOfOrderFulfillment(uint64 id, uint64 expected);
        error RequestMismatch(uint64 id);
        error HandleAlreadyAnchored(bytes32 handle);
        event BatchRequested(uint64 indexed id, address indexed caller, SymbolicOp[] ops, bytes32[] results);
        event OpFulfilled(uint64 indexed id, bytes32 indexed result);
        event BatchFulfilled(uint64 indexed id);

        error NotAllowed(bytes32 handle, address account);
        error UnknownOp(uint8 op);
        error WrongArity(uint8 op);
        error WrongOperandType(bytes32 handle);
        error EmptyBatch();
        error BatchTooLarge(uint256 size);
        error RefOutOfRange(bytes32 handle, uint256 resolvableBelow);
        error BatchShapeMismatch(uint64 id);
    }
}
