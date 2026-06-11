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
    mapping(address => bytes32) public confidentialBalanceOf;
    /// @notice Current confidential frozen-amount handle per account.
    mapping(address => bytes32) public confidentialFrozen;
    /// @notice keccak256 of the ciphertext bytes behind each handle the
    /// chain has seen (anchored inputs and fulfillment outputs alike).
    mapping(bytes32 => bytes32) public handleCommitment;
    /// @notice Owner of each anchored encrypted input handle.
    mapping(bytes32 => address) public inputOwner;

    /// @notice The on-chain ACL, in the fhEVM shape: which accounts may
    /// read (decrypt) the ciphertext behind each handle. Written by the
    /// contract at every handle creation and extended by `allow`; the
    /// coprocessor's decryption read path enforces exactly this state.
    mapping(bytes32 => mapping(address => bool)) public isAllowed;

    /// @notice Whether transfers are paused (agent-set, public).
    bool public paused;
    /// @notice Blocklist (agent-set, public).
    mapping(address => bool) public blocked;
    /// @notice Identity registry: transfer recipients must be verified.
    mapping(address => bool) public isVerified;
    /// @notice Current observer per account (0 = none). Set only by the
    /// account itself: `msg.sender` is the account, which closes the
    /// kit's unauthenticated `set_observer` caveat.
    mapping(address => address) public observerOf;

    /// @dev Request binding: op tag and payload hash per pending id.
    mapping(uint64 => uint8) public requestOpTag;
    mapping(uint64 => bytes32) public requestHash;

    /// @dev Observer snapshots taken at REQUEST time for wraps and
    /// transfers, so the ACL grants written at fulfillment reflect the
    /// observer state the request saw — the coprocessor processes
    /// requests in id order and mirrors exactly that state. Cleared at
    /// fulfillment.
    mapping(uint64 => address) private requestObserverFrom;
    mapping(uint64 => address) private requestObserverTo;

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
    uint8 public constant OP_ALLOW = 12;
    uint8 public constant OP_SYMBOLIC = 13;
    uint8 public constant OP_BATCH = 14;

    // ------------------------------------------------------------------
    // Symbolic encrypted ops (Goal H2): a small fixed alphabet over
    // ACL-allowed handles, with the RESULT handle derived on-chain
    // before its ciphertext exists. The handle is a promise: its
    // `handleCommitment` is posted at fulfillment (deferred binding —
    // a documented weakening of anchor-at-mint, see the docs).
    // ------------------------------------------------------------------
    uint8 public constant SOP_ADD = 1;
    uint8 public constant SOP_SUB = 2;
    uint8 public constant SOP_GE = 3;
    uint8 public constant SOP_SELECT = 4;

    /// @notice fhEVM-style type tags carried in a symbolic handle's
    /// byte 30 (`ebool` = 0, `euint64` = 5, as in FhevmHandle).
    uint8 public constant TYPE_EBOOL = 0;
    uint8 public constant TYPE_EUINT64 = 5;
    /// @notice Symbolic handle version, carried in byte 31.
    uint8 public constant HANDLE_VERSION = 0;

    /// @dev Type tag + 1 per symbolic result handle (0 = not symbolic).
    /// The deterministic type source for operand checks; the trailing
    /// bytes of the handle mirror it for off-chain readers. Anchored
    /// inputs and fulfillment outputs are euint64 by construction.
    mapping(bytes32 => uint8) private symbolicType;

    /// @notice One op of an atomic batch. Operands may be real handles
    /// or `batchRef(i)` markers referencing the result of an EARLIER op
    /// in the same batch (result handles embed the request id, so an
    /// off-chain builder cannot know them in advance; a contract caller
    /// gets the real handles back from `requestBatch` synchronously).
    struct SymbolicOp {
        uint8 op;
        bytes32 lhs;
        bytes32 rhs;
        bytes32 cond;
    }

    /// @notice Hard batch-size bound, pinned by a forge test: bounded
    /// loops keep request and fulfillment gas predictable. A documented
    /// limit, not an implicit one.
    uint256 public constant MAX_BATCH_OPS = 32;

    /// @dev Intra-batch reference marker prefix (first 24 bytes of
    /// keccak256("fhe.rs/ref")); the low 8 bytes carry the op index.
    bytes24 internal constant REF_PREFIX = bytes24(keccak256("fhe.rs/ref"));

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
    event BatchRequested(uint64 indexed id, address indexed caller, SymbolicOp[] ops, bytes32[] results);

    /// @notice An encrypted input was anchored by the coprocessor.
    event InputRegistered(bytes32 indexed handle, bytes32 commitment, address indexed owner);

    /// @notice `account` may now read (decrypt) the ciphertext behind
    /// `handle`. Emitted once per (handle, account) grant.
    event Allowed(bytes32 indexed handle, address indexed account);

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
    event OpFulfilled(uint64 indexed id, bytes32 indexed result);
    event BatchFulfilled(uint64 indexed id);

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
    error NotAllowed(bytes32 handle, address account);
    error UnknownOp(uint8 op);
    error WrongArity(uint8 op);
    error WrongOperandType(bytes32 handle);
    error EmptyBatch();
    error BatchTooLarge(uint256 size);
    error RefOutOfRange(bytes32 handle, uint256 resolvableBelow);
    error BatchShapeMismatch(uint64 id);

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
        requestObserverFrom[id] = observerOf[msg.sender];
        emit WrapRequested(id, msg.sender, amount);
    }

    /// @notice Requests a confidential transfer of the registered
    /// encrypted input `amountHandle` to `to`. Public policy reverts
    /// here; the encrypted balance guard never reverts — an insufficient
    /// amount fulfills as a silent zero, indistinguishable on-chain.
    function confidentialTransfer(address to, bytes32 amountHandle) external {
        if (paused) revert TransfersPaused();
        if (blocked[msg.sender]) revert AccountBlocked(msg.sender);
        if (blocked[to]) revert AccountBlocked(to);
        if (!isVerified[to]) revert RecipientNotVerified(to);
        if (confidentialBalanceOf[msg.sender] == 0) revert NoBalance(msg.sender);
        _requireOwnedInput(amountHandle);
        uint64 id = _request(OP_TRANSFER, abi.encode(msg.sender, to, amountHandle));
        requestObserverFrom[id] = observerOf[msg.sender];
        requestObserverTo[id] = observerOf[to];
        emit TransferRequested(id, msg.sender, to, amountHandle);
    }

    /// @notice Requests one symbolic encrypted operation over handles
    /// the caller is allowed on, returning the RESULT handle derived
    /// deterministically here — before the ciphertext exists, so calls
    /// may chain on it immediately (including within one transaction).
    /// `cond` is the select condition (an ebool handle) and must be
    /// zero for the two-operand ops. Encrypted semantics never revert:
    /// a `select` on a failed `ge` fulfills with the same shape as a
    /// successful one. Operand bound: `ge` compares values below 2^40
    /// (the committee's comparison bound), a documented precondition
    /// on encrypted values that cannot be checked here.
    function requestOp(uint8 op, bytes32 lhs, bytes32 rhs, bytes32 cond)
        external
        returns (bytes32 result)
    {
        uint8 typeTag = _validateOp(op, lhs, rhs, cond);
        uint64 id = nextRequestId;
        result = _symbolicHandle(op, lhs, rhs, cond, id, 0, typeTag);
        _request(OP_SYMBOLIC, abi.encode(msg.sender, op, lhs, rhs, cond, result));
        symbolicType[result] = typeTag + 1;
        _allow(result, msg.sender);
        emit OpRequested(id, msg.sender, op, lhs, rhs, cond, result);
    }

    /// @notice Requests an atomic ordered batch of symbolic ops in one
    /// transaction: one request id, one fulfillment. Later ops may
    /// reference earlier results via `batchRef(i)` markers (resolved
    /// here, deterministically, before validation and derivation) or —
    /// for contract callers — via the returned handles directly. Same
    /// public checks per op as `requestOp`; same deferred binding, one
    /// `fulfillBatch` posts every commitment.
    function requestBatch(SymbolicOp[] calldata ops) external returns (bytes32[] memory results) {
        uint256 n = ops.length;
        if (n == 0) revert EmptyBatch();
        if (n > MAX_BATCH_OPS) revert BatchTooLarge(n);
        results = new bytes32[](n);
        uint64 id = nextRequestId;
        for (uint256 i = 0; i < n; i++) {
            bytes32 lhs = _resolveRef(ops[i].lhs, results, i);
            bytes32 rhs = _resolveRef(ops[i].rhs, results, i);
            bytes32 cond = _resolveRef(ops[i].cond, results, i);
            uint8 typeTag = _validateOp(ops[i].op, lhs, rhs, cond);
            bytes32 result = _symbolicHandle(ops[i].op, lhs, rhs, cond, id, uint32(i), typeTag);
            results[i] = result;
            symbolicType[result] = typeTag + 1;
            _allow(result, msg.sender);
        }
        _request(OP_BATCH, abi.encode(msg.sender, ops, results));
        emit BatchRequested(id, msg.sender, ops, results);
    }

    /// @notice The intra-batch reference marker for the result of op
    /// `index` (only earlier ops resolve; see `requestBatch`).
    function batchRef(uint256 index) public pure returns (bytes32) {
        return bytes32(REF_PREFIX) | bytes32(uint256(uint64(index)));
    }

    /// @notice Grants `account` read (decryption) access to `handle` —
    /// the fhEVM `FHE.allow` shape. Chain of custody: only a caller the
    /// ACL already allows on the handle may extend it. The grant is
    /// public state immediately; the request/ack cycle mirrors it into
    /// the coprocessor's read path in request order, like the rest of
    /// the policy state.
    function allow(bytes32 handle, address account) external {
        if (!isAllowed[handle][msg.sender]) revert NotAllowed(handle, msg.sender);
        _allow(handle, account);
        uint64 id = _request(OP_ALLOW, abi.encode(handle, account));
        emit AllowRequested(id, handle, account);
    }

    /// @notice Sets the caller's OWN observer (address 0 removes it).
    /// There is deliberately no way to set anyone else's observer.
    function setObserver(address observer) external {
        observerOf[msg.sender] = observer;
        uint64 id = _request(OP_SET_OBSERVER, abi.encode(msg.sender, observer));
        emit ObserverSetRequested(id, msg.sender, observer);
    }

    /// @notice Marks `account` (un)verified in the identity registry.
    function setVerified(address account, bool verified) external onlyAgent {
        isVerified[account] = verified;
        uint64 id = _request(OP_SET_VERIFIED, abi.encode(account, verified));
        emit VerifiedSetRequested(id, account, verified);
    }

    /// @notice Sets `account`'s encrypted frozen amount to the registered
    /// input `amountHandle` (agent is the freezer).
    function setConfidentialFrozen(address account, bytes32 amountHandle) external onlyAgent {
        _requireOwnedInput(amountHandle);
        uint64 id = _request(OP_SET_FROZEN, abi.encode(account, amountHandle));
        emit FrozenSetRequested(id, account, amountHandle);
    }

    /// @notice Blocks `account` (public blocklist, OZ ERC7984Rwa
    /// naming).
    function blockUser(address account) external onlyAgent {
        _setBlocked(account, true);
    }

    /// @notice Unblocks `account`.
    function unblockUser(address account) external onlyAgent {
        _setBlocked(account, false);
    }

    function _setBlocked(address account, bool isBlocked) internal {
        blocked[account] = isBlocked;
        uint64 id = _request(OP_SET_BLOCKED, abi.encode(account, isBlocked));
        emit BlockedSetRequested(id, account, isBlocked);
    }

    /// @notice Pauses transfers (OZ Pausable naming).
    function pause() external onlyAgent {
        _setPaused(true);
    }

    /// @notice Unpauses transfers.
    function unpause() external onlyAgent {
        _setPaused(false);
    }

    function _setPaused(bool isPaused) internal {
        paused = isPaused;
        uint64 id = _request(OP_SET_PAUSED, abi.encode(isPaused));
        emit PausedSetRequested(id, isPaused);
    }

    /// @notice Agent-only transfer that bypasses pause, blocklist,
    /// identity, AND the frozen guard — but NOT the encrypted balance
    /// guard: overdraws still silently zero at fulfillment.
    ///
    /// DIVERGENCE FROM OZ: ERC7984Rwa's forceConfidentialTransferFrom
    /// keeps the frozen guard ("frozen tokens must be unfrozen first");
    /// here the agent's force transfer moves frozen funds too. This is
    /// the kit's documented Rwa::force_transfer semantics, kept frozen
    /// by Goal G — the name matches OZ, this behavior deliberately does
    /// not.
    function forceConfidentialTransferFrom(address from, address to, bytes32 amountHandle)
        external
        onlyAgent
    {
        if (confidentialBalanceOf[from] == 0) revert NoBalance(from);
        _requireOwnedInput(amountHandle);
        uint64 id = _request(OP_FORCE_TRANSFER, abi.encode(from, to, amountHandle));
        emit ForceTransferRequested(id, from, to, amountHandle);
    }

    /// @notice Recovers a lost wallet: moves its full confidential
    /// balance (frozen included) to `recipient`; the frozen portion
    /// re-freezes there, computed encrypted in the coprocessor.
    function recover(address lost, address recipient) external onlyAgent {
        if (confidentialBalanceOf[lost] == 0) revert NoBalance(lost);
        uint64 id = _request(OP_RECOVER, abi.encode(lost, recipient));
        emit RecoverRequested(id, lost, recipient);
    }

    /// @notice Requests an unwrap of the registered encrypted input
    /// `amountHandle` back to the caller's public balance. The amount is
    /// revealed at fulfillment (the wrapper's documented leakage); an
    /// insufficient confidential balance fulfills as a failure and
    /// credits nothing.
    function unwrap(bytes32 amountHandle) external {
        if (confidentialBalanceOf[msg.sender] == 0) revert NoBalance(msg.sender);
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
        _allow(handle, owner);
        emit InputRegistered(handle, commitment, owner);
    }

    /// @notice Acknowledges a request that changes no confidential state
    /// (faucet, observer, verify, block, pause): advances the cursor so
    /// every request has exactly one fulfillment.
    function fulfillAck(uint64 id) external onlyCoprocessor {
        if (id != lastFulfilledId + 1 || id >= nextRequestId) {
            revert OutOfOrderFulfillment(id, lastFulfilledId + 1);
        }
        uint8 op = requestOpTag[id];
        require(
            op == OP_FAUCET || op == OP_SET_OBSERVER || op == OP_SET_VERIFIED || op == OP_SET_BLOCKED
                || op == OP_SET_PAUSED || op == OP_ALLOW,
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
        // The wrapper's mint grant: the account, plus the observer the
        // request saw (snapshot, so the mirror agrees in request order).
        _allow(newBalanceHandle, account);
        _allowObserver(newBalanceHandle, requestObserverFrom[id]);
        delete requestObserverFrom[id];
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
        uint8 op = requestOpTag[id];
        if (op != OP_TRANSFER && op != OP_FORCE_TRANSFER) revert RequestMismatch(id);
        _fulfill(id, op, keccak256(abi.encode(from, to, amountHandle)));
        _rotate(from, newFromHandle, newFromCommitment);
        _rotate(to, newToHandle, newToCommitment);
        handleCommitment[transferredHandle] = transferredCommitment;
        // Each party reads its own rotated balance; both read the
        // transferred amount. Observer grants come from the snapshots
        // the request took — force transfers took none (unobserved).
        _allow(newFromHandle, from);
        _allow(newToHandle, to);
        _allow(transferredHandle, from);
        _allow(transferredHandle, to);
        address fromObserver = requestObserverFrom[id];
        address toObserver = requestObserverTo[id];
        _allowObserver(newFromHandle, fromObserver);
        _allowObserver(newToHandle, toObserver);
        _allowObserver(transferredHandle, fromObserver);
        _allowObserver(transferredHandle, toObserver);
        delete requestObserverFrom[id];
        delete requestObserverTo[id];
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
        confidentialFrozen[account] = newFrozenHandle;
        handleCommitment[newFrozenHandle] = newFrozenCommitment;
        // Frozen amounts read by the account and the freezer (agent).
        _allow(newFrozenHandle, account);
        _allow(newFrozenHandle, agent);
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
        confidentialFrozen[recipient] = newRecipientFrozenHandle;
        handleCommitment[newRecipientFrozenHandle] = newRecipientFrozenCommitment;
        delete confidentialFrozen[lost];
        _allow(newLostHandle, lost);
        _allow(newRecipientHandle, recipient);
        _allow(newRecipientFrozenHandle, recipient);
        _allow(newRecipientFrozenHandle, agent);
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
            _allow(newBalanceHandle, account);
        }
        emit UnwrapFulfilled(id, account, amount, success, newBalanceHandle);
    }

    /// @notice Fulfills a symbolic op: posts the result handle's
    /// commitment — the DEFERRED binding. Until this lands, the result
    /// handle is a coprocessor-signed promise; afterwards it is
    /// hash-bound exactly like an anchored input.
    function fulfillOp(
        uint64 id,
        address caller,
        uint8 op,
        bytes32 lhs,
        bytes32 rhs,
        bytes32 cond,
        bytes32 result,
        bytes32 commitment
    ) external onlyCoprocessor {
        _fulfill(id, OP_SYMBOLIC, keccak256(abi.encode(caller, op, lhs, rhs, cond, result)));
        handleCommitment[result] = commitment;
        emit OpFulfilled(id, result);
    }

    /// @notice Fulfills an atomic batch: several results' deferred
    /// commitments posted in ONE transaction (the fulfillment-side gas
    /// amortization), bound to the one batch request.
    function fulfillBatch(
        uint64 id,
        address caller,
        SymbolicOp[] calldata ops,
        bytes32[] calldata results,
        bytes32[] calldata commitments
    ) external onlyCoprocessor {
        if (results.length != ops.length || commitments.length != ops.length) {
            revert BatchShapeMismatch(id);
        }
        _fulfill(id, OP_BATCH, keccak256(abi.encode(caller, ops, results)));
        for (uint256 i = 0; i < results.length; i++) {
            handleCommitment[results[i]] = commitments[i];
        }
        emit BatchFulfilled(id);
    }

    // ------------------------------------------------------------------
    // Internals.
    // ------------------------------------------------------------------

    /// @dev Public checks for one symbolic op (these DO revert — they
    /// are public anyway): known op, right arity, caller allowed on
    /// every operand, operand types match. Returns the result type.
    function _validateOp(uint8 op, bytes32 lhs, bytes32 rhs, bytes32 cond)
        internal
        view
        returns (uint8)
    {
        if (op == SOP_SELECT) {
            _requireOperand(cond, TYPE_EBOOL);
            _requireOperand(lhs, TYPE_EUINT64);
            _requireOperand(rhs, TYPE_EUINT64);
            return TYPE_EUINT64;
        }
        if (op == SOP_ADD || op == SOP_SUB || op == SOP_GE) {
            if (cond != bytes32(0)) revert WrongArity(op);
            _requireOperand(lhs, TYPE_EUINT64);
            _requireOperand(rhs, TYPE_EUINT64);
            return op == SOP_GE ? TYPE_EBOOL : TYPE_EUINT64;
        }
        revert UnknownOp(op);
    }

    /// @dev An operand is usable iff the ACL allows the caller on it
    /// (which also proves the handle exists — every real handle has at
    /// least one grant) and its type matches. A symbolic operand need
    /// NOT be materialized yet: requests are fulfilled in order, so an
    /// earlier result is available by the time this op executes.
    function _requireOperand(bytes32 handle, uint8 wantType) internal view {
        if (!isAllowed[handle][msg.sender]) revert NotAllowed(handle, msg.sender);
        uint8 tagged = symbolicType[handle];
        uint8 actual = tagged == 0 ? TYPE_EUINT64 : tagged - 1;
        if (actual != wantType) revert WrongOperandType(handle);
    }

    /// @dev Resolves a `batchRef` marker against the results derived so
    /// far; non-markers pass through. Only strictly earlier ops are
    /// resolvable — execution is in op order.
    function _resolveRef(bytes32 handle, bytes32[] memory results, uint256 current)
        internal
        pure
        returns (bytes32)
    {
        if (bytes24(handle) != REF_PREFIX) return handle;
        uint256 index = uint256(handle) & type(uint64).max;
        if (index >= current) revert RefOutOfRange(handle, current);
        return results[index];
    }

    /// @dev The symbolic result handle: keccak over a domain tag, the
    /// op, its inputs, the request id, and the op's index within the
    /// request, with the fhEVM-style trailing bytes written in — byte
    /// 21 = 0xff (computed marker), byte 30 = type tag, byte 31 =
    /// version. Anyone can recompute it; the coprocessor re-derives
    /// and refuses a mismatch.
    function _symbolicHandle(
        uint8 op,
        bytes32 lhs,
        bytes32 rhs,
        bytes32 cond,
        uint64 id,
        uint32 index,
        uint8 typeTag
    ) internal pure returns (bytes32) {
        uint256 h =
            uint256(keccak256(abi.encodePacked("fhe.rs/sym", op, lhs, rhs, cond, id, index)));
        h = (h & ~(uint256(0xff) << 80)) | (uint256(0xff) << 80); // byte 21
        h = (h & ~(uint256(0xff) << 8)) | (uint256(typeTag) << 8); // byte 30
        h = (h & ~uint256(0xff)) | uint256(HANDLE_VERSION); // byte 31
        return bytes32(h);
    }

    function _request(uint8 op, bytes memory payload) internal returns (uint64 id) {
        id = nextRequestId++;
        requestOpTag[id] = op;
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
        if (requestOpTag[id] != op || requestHash[id] != payloadHash) revert RequestMismatch(id);
        lastFulfilledId = id;
        delete requestOpTag[id];
        delete requestHash[id];
    }

    function _rotate(address account, bytes32 newHandle, bytes32 commitment) internal {
        confidentialBalanceOf[account] = newHandle;
        handleCommitment[newHandle] = commitment;
    }

    /// @dev Idempotent ACL grant; emits `Allowed` once per new grant.
    function _allow(bytes32 handle, address account) internal {
        if (!isAllowed[handle][account]) {
            isAllowed[handle][account] = true;
            emit Allowed(handle, account);
        }
    }

    /// @dev Grant to an observer snapshot, skipping the no-observer zero.
    function _allowObserver(bytes32 handle, address observer) internal {
        if (observer != address(0)) {
            _allow(handle, observer);
        }
    }
}
