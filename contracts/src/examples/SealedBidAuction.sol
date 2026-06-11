// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev The gateway's PUBLIC composability surface — the only thing
/// this contract knows about the system. No token entry points, no
/// coprocessor knowledge: just the ACL and the symbolic-op alphabet.
interface IConfidentialOps {
    struct SymbolicOp {
        uint8 op;
        bytes32 lhs;
        bytes32 rhs;
        bytes32 cond;
    }

    function requestBatch(SymbolicOp[] calldata ops) external returns (bytes32[] memory results);
    function allow(bytes32 handle, address account) external;
    function isAllowed(bytes32 handle, address account) external view returns (bool);
    function batchRef(uint256 index) external pure returns (bytes32);
}

/// @title SealedBidAuction
/// @notice The Goal H third-party proof: a sealed-bid auction step
/// settled over ENCRYPTED bids, built ONLY on the gateway's public
/// primitives (`allow` / `isAllowed` / `requestBatch`). The
/// coprocessor learns nothing about "auctions" — it executes the same
/// fixed alphabet it always does — and the gateway gains no entry
/// points for this contract to exist.
///
/// Flow: each bidder registers an encrypted bid (a gateway input
/// handle), grants this contract read access on it
/// (`gateway.allow(bid, auction)`), and submits the handle. `settle`
/// composes `ge` + `select` in ONE atomic batch — "did A win, and
/// what is the winning bid" — and extends read access on both results
/// to the seller. Nothing is decrypted on-chain; the seller reads the
/// outcome through the coprocessor's ACL-checked path.
contract SealedBidAuction {
    // The gateway's symbolic-op alphabet (pinned by its constants).
    uint8 internal constant SOP_GE = 3;
    uint8 internal constant SOP_SELECT = 4;

    IConfidentialOps public immutable gateway;
    address public immutable seller;

    address public bidderA;
    bytes32 public bidA;
    address public bidderB;
    bytes32 public bidB;

    /// @notice ebool result: 1 if bidder A's bid is the winning one.
    bytes32 public aWins;
    /// @notice euint64 result: the winning (maximum) bid amount.
    bytes32 public winningBid;

    error BidSlotsFull();
    error AuctionNotAllowedOnBid(bytes32 bid);
    error NotEnoughBids();
    error AlreadySettled();

    constructor(IConfidentialOps gateway_, address seller_) {
        gateway = gateway_;
        seller = seller_;
    }

    /// @notice Submits an encrypted bid (a registered input handle).
    /// The bidder must have granted this contract read access first —
    /// the ACL is how encrypted state crosses contract boundaries.
    function submitBid(bytes32 bid) external {
        if (!gateway.isAllowed(bid, address(this))) revert AuctionNotAllowedOnBid(bid);
        if (bidderA == address(0)) {
            bidderA = msg.sender;
            bidA = bid;
        } else if (bidderB == address(0)) {
            bidderB = msg.sender;
            bidB = bid;
        } else {
            revert BidSlotsFull();
        }
    }

    /// @notice Settles the auction: one atomic batch computes the
    /// winner bit and the winning amount, and the seller is granted
    /// read access on both. The encrypted comparison never reverts —
    /// a tie or any ordering settles with the same shape.
    function settle() external {
        if (bidA == bytes32(0) || bidB == bytes32(0)) revert NotEnoughBids();
        if (winningBid != bytes32(0)) revert AlreadySettled();
        IConfidentialOps.SymbolicOp[] memory ops = new IConfidentialOps.SymbolicOp[](2);
        ops[0] = IConfidentialOps.SymbolicOp(SOP_GE, bidA, bidB, bytes32(0));
        ops[1] = IConfidentialOps.SymbolicOp(SOP_SELECT, bidA, bidB, gateway.batchRef(0));
        bytes32[] memory results = gateway.requestBatch(ops);
        aWins = results[0];
        winningBid = results[1];
        // This contract created the results, so the ACL lets it grant
        // onward (chain of custody): the seller may read both.
        gateway.allow(aWins, seller);
        gateway.allow(winningBid, seller);
    }
}
