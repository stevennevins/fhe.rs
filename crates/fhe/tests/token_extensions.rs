//! Unit tests for the ERC7984 extension suite at toy parameters:
//! restriction modes, identity checks, and their "public check before
//! encrypted work" guarantee.

use fhe::gateway::Committee;
use fhe::token::extensions::identity::{IdentityCheck, IdentityRegistry, InMemoryIdentityRegistry};
use fhe::token::extensions::restricted::{Restriction, RestrictionMode, Restrictions};
use fhe::token::{Account, ConfidentialToken};
use fhe::typed::{FheUint64, set_server_key};
use rand::rng;

const ALICE: Account = 1;
const BOB: Account = 2;

fn toy_token() -> ConfidentialToken {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let committee = Committee::new(3, &params, &mut rng).unwrap();
    set_server_key(committee.server_key());
    ConfidentialToken::new(committee, &mut rng).unwrap()
}

fn balance_of(token: &ConfidentialToken, account: Account) -> u64 {
    let handle = token.balance_handle(account).unwrap();
    token.decrypt_for(handle, account, &mut rng()).unwrap()
}

/// Blocklist mode: a blocked sender and a blocked recipient each make
/// the transfer a structural Err — before any encrypted work, so no new
/// handles are created and no committee comparison runs. Unblocking
/// restores the transfer.
#[test]
fn blocklist_blocks_sender_and_recipient_publicly() {
    let mut rng = rng();
    let mut token = toy_token();
    token.mint(ALICE, 100, &mut rng).unwrap();
    let mut restrictions = Restrictions::new(RestrictionMode::Blocklist);

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    for blocked in [ALICE, BOB] {
        restrictions.set_restriction(blocked, Restriction::Blocked);
        assert!(!restrictions.is_user_allowed(blocked));

        let handles_before = token.handles().len();
        let comparisons_before = token.audit_log().len();
        assert!(
            restrictions
                .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
                .is_err()
        );
        // The check happened before any encrypted work: no new handles,
        // zero committee comparisons.
        assert_eq!(token.handles().len(), handles_before);
        assert_eq!(token.audit_log().len(), comparisons_before);

        restrictions.set_restriction(blocked, Restriction::Default);
    }

    // Unblocked: the transfer goes through.
    restrictions
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    assert_eq!(balance_of(&token, ALICE), 90);
    assert_eq!(balance_of(&token, BOB), 10);
}

/// Allowlist mode: default-deny — a transfer between two unlisted
/// accounts fails; explicitly allowing both restores it.
#[test]
fn allowlist_denies_by_default() {
    let mut rng = rng();
    let mut token = toy_token();
    token.mint(ALICE, 100, &mut rng).unwrap();
    let mut restrictions = Restrictions::new(RestrictionMode::Allowlist);
    assert_eq!(restrictions.mode(), RestrictionMode::Allowlist);

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    assert!(
        restrictions
            .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );
    // Allowing only one party is not enough.
    restrictions.set_restriction(ALICE, Restriction::Allowed);
    assert!(
        restrictions
            .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );

    restrictions.set_restriction(BOB, Restriction::Allowed);
    restrictions
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    assert_eq!(balance_of(&token, BOB), 10);
}

/// Unverified recipient: transfer and mint both Err with no encrypted
/// work; verifying the recipient through the registry restores both.
#[test]
fn identity_check_gates_recipient_on_transfer_and_mint() {
    let mut rng = rng();
    let mut token = toy_token();
    let mut check = IdentityCheck::new(InMemoryIdentityRegistry::new());
    check.registry_mut().set_verified(ALICE, true);
    assert!(check.registry().is_verified(ALICE));
    check.mint(&mut token, ALICE, 100, &mut rng).unwrap();

    let amount = token.committee().encrypt(10, &mut rng).unwrap();
    let handles_before = token.handles().len();
    let comparisons_before = token.audit_log().len();
    assert!(
        check
            .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
            .is_err()
    );
    assert!(check.mint(&mut token, BOB, 5, &mut rng).is_err());
    // Both rejections happened before any encrypted work.
    assert_eq!(token.handles().len(), handles_before);
    assert_eq!(token.audit_log().len(), comparisons_before);

    check.registry_mut().set_verified(BOB, true);
    check
        .transfer(&mut token, ALICE, BOB, &amount, &mut rng)
        .unwrap();
    check.mint(&mut token, BOB, 5, &mut rng).unwrap();
    assert_eq!(balance_of(&token, ALICE), 90);
    assert_eq!(balance_of(&token, BOB), 15);
}
