//! Unit tests for the confidential token service against a plaintext
//! reference ledger: mint/transfer/balance/total-supply semantics,
//! never-revert transfers, and the ACL.

use std::collections::HashMap;

use fhe::gateway::Committee;
use fhe::token::{Account, ConfidentialToken, RefreshPolicy};
use fhe::typed::{FheUint64, set_server_key};
use rand::rng;

const ALICE: Account = 1;
const BOB: Account = 2;
const CAROL: Account = 3;

fn toy_token() -> ConfidentialToken {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());
    ConfidentialToken::new(committee, &mut rng).unwrap()
}

/// Decrypts `account`'s balance through the ACL (the owner is allowed on
/// its own balance handle).
fn balance_of(token: &ConfidentialToken, account: Account) -> u64 {
    let handle = token.balance_handle(account).unwrap();
    token.decrypt_for(handle, account, &mut rng()).unwrap()
}

fn total_supply(token: &ConfidentialToken) -> u64 {
    token
        .committee()
        .threshold_decrypt(token.total_supply(), &mut rng())
        .unwrap()
}

/// The encrypted ledger must track a plaintext reference ledger exactly
/// through a mixed mint/transfer history — including transfers that fail
/// for insufficient funds, which must be no-ops on every balance.
#[test]
fn ledger_matches_plaintext_reference() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut reference: HashMap<Account, u64> = HashMap::new();

    let mints: [(Account, u64); 3] = [(ALICE, 1000), (BOB, 500), (ALICE, 250)];
    for (to, amount) in mints {
        token.mint(to, amount, &mut rng).unwrap();
        *reference.entry(to).or_default() += amount;
    }

    // (from, to, amount); 5000 exceeds every balance and must be a no-op.
    let transfers: [(Account, Account, u64); 4] = [
        (ALICE, BOB, 300),
        (BOB, CAROL, 800),
        (BOB, ALICE, 5000),
        (CAROL, ALICE, 1),
    ];
    for (from, to, amount) in transfers {
        let enc = token.committee().encrypt(amount, &mut rng).unwrap();
        token.transfer(from, to, &enc, &mut rng).unwrap();
        let from_balance = reference.entry(from).or_default();
        if *from_balance >= amount {
            *from_balance -= amount;
            *reference.entry(to).or_default() += amount;
        }
    }

    for (account, expected) in &reference {
        assert_eq!(balance_of(&token, *account), *expected, "account {account}");
    }
    let expected_supply: u64 = reference.values().sum();
    assert_eq!(total_supply(&token), expected_supply);
}

/// Never-revert: an insufficient-funds transfer returns Ok, leaves both
/// balances unchanged, and its transferred-amount ciphertext decrypts to
/// 0 — indistinguishable from a zero-amount transfer.
#[test]
fn insufficient_funds_transfer_is_silent_noop() {
    let mut rng = rng();
    let mut token = toy_token();
    token.mint(ALICE, 100, &mut rng).unwrap();
    token.mint(BOB, 50, &mut rng).unwrap();

    let enc = token.committee().encrypt(101, &mut rng).unwrap();
    let amount_handle = token.transfer(ALICE, BOB, &enc, &mut rng).unwrap();

    assert_eq!(balance_of(&token, ALICE), 100);
    assert_eq!(balance_of(&token, BOB), 50);
    assert_eq!(total_supply(&token), 150);
    // Both parties may read the transferred amount; it is zero.
    assert_eq!(
        token.decrypt_for(amount_handle, ALICE, &mut rng).unwrap(),
        0
    );
    assert_eq!(token.decrypt_for(amount_handle, BOB, &mut rng).unwrap(), 0);
}

/// Reading a handle without an ACL grant must be an Err — for the
/// ciphertext, for decryption, and for granting.
#[test]
fn acl_denies_unallowed_reads_and_grants() {
    let mut rng = rng();
    let mut token = toy_token();
    let alice_balance = token.mint(ALICE, 1000, &mut rng).unwrap();

    // Bob is not allowed on alice's balance handle.
    assert!(!token.is_allowed(alice_balance, BOB));
    assert!(token.ciphertext(alice_balance, BOB).is_err());
    assert!(token.decrypt_for(alice_balance, BOB, &mut rng).is_err());
    // Nor may bob grant himself (or carol) access.
    assert!(token.allow(alice_balance, BOB, CAROL).is_err());

    // Alice, who is allowed, may grant bob access.
    token.allow(alice_balance, ALICE, BOB).unwrap();
    assert!(token.is_allowed(alice_balance, BOB));
    assert_eq!(
        token.decrypt_for(alice_balance, BOB, &mut rng).unwrap(),
        1000
    );
}

/// Minting must enforce the public supply bound that every encrypted
/// comparison's correctness depends on.
#[test]
fn mint_rejects_supply_over_domain_bound() {
    let mut rng = rng();
    let mut token = toy_token();
    let max = fhe::typed::safe_math::MAX_SAFE_VALUE;
    token.mint(ALICE, max, &mut rng).unwrap();
    assert!(token.mint(BOB, 1, &mut rng).is_err());
    assert_eq!(total_supply(&token), max);
}

/// Transferring from an account that never held tokens is the one
/// structural error transfer may raise.
#[test]
fn transfer_from_unknown_account_errors() {
    let mut rng = rng();
    let mut token = toy_token();
    token.mint(ALICE, 10, &mut rng).unwrap();
    let enc = token.committee().encrypt(1, &mut rng).unwrap();
    assert!(token.transfer(CAROL, ALICE, &enc, &mut rng).is_err());
}

/// The RefreshPolicy::Never escape hatch must exist and construct — the
/// e2e companion test uses it to prove refresh is load-bearing.
#[test]
fn refresh_policy_never_constructs() {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());
    let mut token =
        ConfidentialToken::with_refresh_policy(committee, RefreshPolicy::Never, &mut rng).unwrap();
    token.mint(ALICE, 10, &mut rng).unwrap();
    assert_eq!(balance_of(&token, ALICE), 10);
}
