// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ConfidentialTokenGateway
/// @notice The on-chain half of the fhe.rs confidential token kit, in the
/// fhEVM deployment shape: the chain holds 32-byte ciphertext HANDLES,
/// keccak256 COMMITMENTS to the ciphertext bytes, and all PUBLIC
/// access-control state; the off-chain coprocessor holds the ciphertexts
/// and the threshold committee.
///
/// Transport split (the fhEVM input-handle model, not a shortcut): a
/// degree-16384 ciphertext is megabytes, so ciphertext bytes never enter
/// calldata. A user first registers an encrypted input with the
/// coprocessor off-chain; the coprocessor anchors `(handle, commitment,
/// owner)` here via `registerInput`, and the user's transaction carries
/// only the 32-byte handle. The contract accepts only anchored handles,
/// owned by the transaction sender.
///
/// Authorization model: `msg.sender` IS the account. Public policy
/// (pause, blocklist, identity verification, the agent role) is enforced
/// here, where it is public anyway, and rejections revert before any
/// coprocessor work. Encrypted guards (balance/frozen sufficiency) live
/// in the coprocessor and never revert — an insufficient transfer
/// fulfills with the same shape as a successful one.
///
/// Ordering: every state-changing entry point emits a request event with
/// a strictly increasing id and records `keccak256(op, payload)`. Only
/// the coprocessor may fulfill, only in request order, and only with a
/// fulfillment whose recomputed hash matches the recorded request — every
/// encrypted state transition is attributable to exactly one request.
///
/// Trust model (v1): the coprocessor is a TRUSTED EXECUTOR. It cannot
/// decrypt anything by itself (the committee is N-of-N inside it in this
/// kit, and nothing here changes that), but it could censor or reorder by
/// simply not fulfilling. This contract narrows that to "stall": it
/// cannot fulfill out of order or invent a transition with no matching
/// request. The gap is named, not filled.
contract ConfidentialTokenGateway {
    /// @notice Holder of the agent (and freezer) role: pause, block,
    /// freeze, verify, force-transfer, recover.
    address public immutable agent;
    /// @notice The only address allowed to anchor inputs and fulfill
    /// requests.
    address public immutable coprocessor;

    /// @notice Id the next request will get (first request is id 1).
    uint64 public nextRequestId = 1;
    /// @notice Highest fulfilled request id; all ids at or below it are
    /// fulfilled (fulfillment is strictly in order).
    uint64 public lastFulfilledId;

    /// @notice Public ERC20-side balances (the wrapper's public ledger).
    mapping(address => uint64) public publicBalance;
    /// @notice Current confidential balance handle per account (0 = none).
    mapping(address => bytes32) public balanceHandle;
    /// @notice Current confidential frozen-amount handle per account.
    mapping(address => bytes32) public frozenHandle;
    /// @notice keccak256 of the ciphertext bytes behind each handle the
    /// chain has seen (anchored inputs and fulfillment outputs alike).
    mapping(bytes32 => bytes32) public handleCommitment;
    /// @notice Owner of each anchored encrypted input handle.
    mapping(bytes32 => address) public inputOwner;

    /// @notice Whether transfers are paused (agent-set, public).
    bool public paused;
    /// @notice Blocklist (agent-set, public).
    mapping(address => bool) public blocked;
    /// @notice Identity registry: transfer recipients must be verified.
    mapping(address => bool) public verified;
    /// @notice Current observer per account (0 = none). Set only by the
    /// account itself: `msg.sender` is the account, which closes the
    /// kit's unauthenticated `set_observer` caveat.
    mapping(address => address) public observerOf;

    /// @dev Request binding: op tag and payload hash per pending id.
    mapping(uint64 => uint8) public requestOp;
    mapping(uint64 => bytes32) public requestHash;

    uint8 public constant OP_FAUCET = 1;
    uint8 public constant OP_WRAP = 2;
    uint8 public constant OP_TRANSFER = 3;
    uint8 public constant OP_SET_OBSERVER = 4;
    uint8 public constant OP_SET_VERIFIED = 5;
    uint8 public constant OP_SET_FROZEN = 6;
    uint8 public constant OP_SET_BLOCKED = 7;
    uint8 public constant OP_SET_PAUSED = 8;
    uint8 public constant OP_FORCE_TRANSFER = 9;
    uint8 public constant OP_RECOVER = 10;
    uint8 public constant OP_UNWRAP = 11;

    // ------------------------------------------------------------------
    // Request events (decoded by the coprocessor, processed in id order).
    // ------------------------------------------------------------------
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

    /// @notice An encrypted input was anchored by the coprocessor.
    event InputRegistered(bytes32 indexed handle, bytes32 commitment, address indexed owner);

    // ------------------------------------------------------------------
    // Fulfillment events (the handle rotations the e2e asserts against).
    // ------------------------------------------------------------------
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
        uint64 indexed id, address indexed account, uint64 amount, bool success, bytes32 newBalanceHandle
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

    modifier onlyAgent() {
        if (msg.sender != agent) revert NotAgent();
        _;
    }

    modifier onlyCoprocessor() {
        if (msg.sender != coprocessor) revert NotCoprocessor();
        _;
    }

    constructor(address agent_, address coprocessor_) {
        agent = agent_;
        coprocessor = coprocessor_;
    }

    // ------------------------------------------------------------------
    // User entry points (public policy enforced here, with reverts).
    // ------------------------------------------------------------------

    /// @notice Test stand-in for receiving the underlying public token:
    /// credits the caller's public balance. The only entry that changes
    /// the combined public + confidential total.
    function faucet(uint64 amount) external {
        publicBalance[msg.sender] += amount;
        uint64 id = _request(OP_FAUCET, abi.encode(msg.sender, amount));
        emit FaucetRequested(id, msg.sender, amount);
    }

    /// @notice Moves `amount` of the caller's public balance into a
    /// confidential mint (public amount, as in ERC7984 mints). The public
    /// debit happens now; the confidential credit lands at fulfillment.
    function wrap(uint64 amount) external {
        uint64 balance = publicBalance[msg.sender];
        if (balance < amount) revert InsufficientPublicBalance(msg.sender, balance, amount);
        publicBalance[msg.sender] = balance - amount;
        uint64 id = _request(OP_WRAP, abi.encode(msg.sender, amount));
        emit WrapRequested(id, msg.sender, amount);
    }

    /// @notice Requests a confidential transfer of the registered
    /// encrypted input `amountHandle` to `to`. Public policy reverts
    /// here; the encrypted balance guard never reverts — an insufficient
    /// amount fulfills as a silent zero, indistinguishable on-chain.
    function transfer(address to, bytes32 amountHandle) external {
        if (paused) revert TransfersPaused();
        if (blocked[msg.sender]) revert AccountBlocked(msg.sender);
        if (blocked[to]) revert AccountBlocked(to);
        if (!verified[to]) revert RecipientNotVerified(to);
        if (balanceHandle[msg.sender] == 0) revert NoBalance(msg.sender);
        _requireOwnedInput(amountHandle);
        uint64 id = _request(OP_TRANSFER, abi.encode(msg.sender, to, amountHandle));
        emit TransferRequested(id, msg.sender, to, amountHandle);
    }

    /// @notice Sets the caller's OWN observer (address 0 removes it).
    /// There is deliberately no way to set anyone else's observer.
    function setObserver(address observer) external {
        observerOf[msg.sender] = observer;
        uint64 id = _request(OP_SET_OBSERVER, abi.encode(msg.sender, observer));
        emit ObserverSetRequested(id, msg.sender, observer);
    }

    /// @notice Marks `account` (un)verified in the identity registry.
    function setVerified(address account, bool isVerified) external onlyAgent {
        verified[account] = isVerified;
        uint64 id = _request(OP_SET_VERIFIED, abi.encode(account, isVerified));
        emit VerifiedSetRequested(id, account, isVerified);
    }

    /// @notice Sets `account`'s encrypted frozen amount to the registered
    /// input `amountHandle` (agent is the freezer).
    function setConfidentialFrozen(address account, bytes32 amountHandle) external onlyAgent {
        _requireOwnedInput(amountHandle);
        uint64 id = _request(OP_SET_FROZEN, abi.encode(account, amountHandle));
        emit FrozenSetRequested(id, account, amountHandle);
    }

    /// @notice Blocks or unblocks `account` (public blocklist).
    function setBlocked(address account, bool isBlocked) external onlyAgent {
        blocked[account] = isBlocked;
        uint64 id = _request(OP_SET_BLOCKED, abi.encode(account, isBlocked));
        emit BlockedSetRequested(id, account, isBlocked);
    }

    /// @notice Pauses or unpauses transfers.
    function setPaused(bool isPaused) external onlyAgent {
        paused = isPaused;
        uint64 id = _request(OP_SET_PAUSED, abi.encode(isPaused));
        emit PausedSetRequested(id, isPaused);
    }

    /// @notice Agent-only transfer that bypasses pause, blocklist,
    /// identity, and the frozen guard — but NOT the encrypted balance
    /// guard: overdraws still silently zero at fulfillment.
    function forceTransfer(address from, address to, bytes32 amountHandle) external onlyAgent {
        if (balanceHandle[from] == 0) revert NoBalance(from);
        _requireOwnedInput(amountHandle);
        uint64 id = _request(OP_FORCE_TRANSFER, abi.encode(from, to, amountHandle));
        emit ForceTransferRequested(id, from, to, amountHandle);
    }

    /// @notice Recovers a lost wallet: moves its full confidential
    /// balance (frozen included) to `recipient`; the frozen portion
    /// re-freezes there, computed encrypted in the coprocessor.
    function recover(address lost, address recipient) external onlyAgent {
        if (balanceHandle[lost] == 0) revert NoBalance(lost);
        uint64 id = _request(OP_RECOVER, abi.encode(lost, recipient));
        emit RecoverRequested(id, lost, recipient);
    }

    /// @notice Requests an unwrap of the registered encrypted input
    /// `amountHandle` back to the caller's public balance. The amount is
    /// revealed at fulfillment (the wrapper's documented leakage); an
    /// insufficient confidential balance fulfills as a failure and
    /// credits nothing.
    function requestUnwrap(bytes32 amountHandle) external {
        if (balanceHandle[msg.sender] == 0) revert NoBalance(msg.sender);
        _requireOwnedInput(amountHandle);
        uint64 id = _request(OP_UNWRAP, abi.encode(msg.sender, amountHandle));
        emit UnwrapRequested(id, msg.sender, amountHandle);
    }

    // ------------------------------------------------------------------
    // Coprocessor entry points.
    // ------------------------------------------------------------------

    /// @notice Anchors an off-chain-registered encrypted input. This is
    /// anchoring, not a state transition: the ciphertext bytes live in
    /// the coprocessor; the chain learns only the handle, the keccak256
    /// commitment, and the owner allowed to spend it.
    function registerInput(bytes32 handle, bytes32 commitment, address owner) external onlyCoprocessor {
        if (inputOwner[handle] != address(0)) revert HandleAlreadyAnchored(handle);
        inputOwner[handle] = owner;
        handleCommitment[handle] = commitment;
        emit InputRegistered(handle, commitment, owner);
    }

    /// @notice Acknowledges a request that changes no confidential state
    /// (faucet, observer, verify, block, pause): advances the cursor so
    /// every request has exactly one fulfillment.
    function fulfillAck(uint64 id) external onlyCoprocessor {
        if (id != lastFulfilledId + 1 || id >= nextRequestId) {
            revert OutOfOrderFulfillment(id, lastFulfilledId + 1);
        }
        uint8 op = requestOp[id];
        require(
            op == OP_FAUCET || op == OP_SET_OBSERVER || op == OP_SET_VERIFIED || op == OP_SET_BLOCKED
                || op == OP_SET_PAUSED,
            "ack only for mirror ops"
        );
        _fulfill(id, op, requestHash[id]);
        emit RequestAcked(id);
    }

    /// @notice Fulfills a wrap: the account's confidential balance
    /// rotated to `newBalanceHandle`.
    function fulfillWrap(
        uint64 id,
        address account,
        uint64 amount,
        bytes32 newBalanceHandle,
        bytes32 newBalanceCommitment
    ) external onlyCoprocessor {
        _fulfill(id, OP_WRAP, keccak256(abi.encode(account, amount)));
        _rotate(account, newBalanceHandle, newBalanceCommitment);
        emit WrapFulfilled(id, account, newBalanceHandle);
    }

    /// @notice Fulfills a transfer (or force transfer): both balance
    /// handles rotate and the transferred-amount ciphertext gets a
    /// handle. IDENTICAL shape whether the encrypted guard passed or
    /// silently zeroed — nothing on-chain distinguishes them.
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
    ) external onlyCoprocessor {
        uint8 op = requestOp[id];
        if (op != OP_TRANSFER && op != OP_FORCE_TRANSFER) revert RequestMismatch(id);
        _fulfill(id, op, keccak256(abi.encode(from, to, amountHandle)));
        _rotate(from, newFromHandle, newFromCommitment);
        _rotate(to, newToHandle, newToCommitment);
        handleCommitment[transferredHandle] = transferredCommitment;
        emit TransferFulfilled(id, from, to, newFromHandle, newToHandle, transferredHandle);
    }

    /// @notice Fulfills a freeze: the account's frozen handle rotates.
    function fulfillFrozenSet(
        uint64 id,
        address account,
        bytes32 amountHandle,
        bytes32 newFrozenHandle,
        bytes32 newFrozenCommitment
    ) external onlyCoprocessor {
        _fulfill(id, OP_SET_FROZEN, keccak256(abi.encode(account, amountHandle)));
        frozenHandle[account] = newFrozenHandle;
        handleCommitment[newFrozenHandle] = newFrozenCommitment;
        emit FrozenSetFulfilled(id, account, newFrozenHandle);
    }

    /// @notice Fulfills a recovery: the lost wallet's balance handle
    /// rotates to an encrypted zero, the recipient's balance and frozen
    /// handles rotate, and the lost wallet's frozen entry clears.
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
    ) external onlyCoprocessor {
        _fulfill(id, OP_RECOVER, keccak256(abi.encode(lost, recipient)));
        _rotate(lost, newLostHandle, newLostCommitment);
        _rotate(recipient, newRecipientHandle, newRecipientCommitment);
        frozenHandle[recipient] = newRecipientFrozenHandle;
        handleCommitment[newRecipientFrozenHandle] = newRecipientFrozenCommitment;
        delete frozenHandle[lost];
        emit RecoverFulfilled(id, lost, recipient, newLostHandle, newRecipientHandle, newRecipientFrozenHandle);
    }

    /// @notice Fulfills an unwrap. On success the revealed amount (the
    /// wrapper's documented leakage) credits the public balance and the
    /// confidential balance handle rotates; on failure nothing is
    /// credited and the balance is untouched.
    function fulfillUnwrap(
        uint64 id,
        address account,
        bytes32 amountHandle,
        uint64 amount,
        bool success,
        bytes32 newBalanceHandle,
        bytes32 newBalanceCommitment
    ) external onlyCoprocessor {
        _fulfill(id, OP_UNWRAP, keccak256(abi.encode(account, amountHandle)));
        if (success) {
            publicBalance[account] += amount;
            _rotate(account, newBalanceHandle, newBalanceCommitment);
        }
        emit UnwrapFulfilled(id, account, amount, success, newBalanceHandle);
    }

    // ------------------------------------------------------------------
    // Internals.
    // ------------------------------------------------------------------

    function _request(uint8 op, bytes memory payload) internal returns (uint64 id) {
        id = nextRequestId++;
        requestOp[id] = op;
        requestHash[id] = keccak256(payload);
    }

    function _requireOwnedInput(bytes32 handle) internal view {
        address owner = inputOwner[handle];
        if (owner == address(0)) revert UnknownInput(handle);
        if (owner != msg.sender) revert NotInputOwner(handle, msg.sender);
    }

    /// @dev In-order, request-bound fulfillment: `id` must be the next
    /// unfulfilled request and the recomputed payload hash must match.
    function _fulfill(uint64 id, uint8 op, bytes32 payloadHash) internal {
        if (id != lastFulfilledId + 1 || id >= nextRequestId) {
            revert OutOfOrderFulfillment(id, lastFulfilledId + 1);
        }
        if (requestOp[id] != op || requestHash[id] != payloadHash) revert RequestMismatch(id);
        lastFulfilledId = id;
        delete requestOp[id];
        delete requestHash[id];
    }

    function _rotate(address account, bytes32 newHandle, bytes32 commitment) internal {
        balanceHandle[account] = newHandle;
        handleCommitment[newHandle] = commitment;
    }
}
