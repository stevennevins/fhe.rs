//! Round-trip serialization tests for the typed API (`FheUint64`,
//! `ServerKey`).

use fhe::bfv::{BfvParametersBuilder, SecretKey};
use fhe::typed::{FheUint64, ServerKey, set_server_key};
use fhe_traits::{DeserializeParametrized, Serialize};
use rand::rng;

/// A ciphertext survives a serialization round-trip if it still decrypts to
/// the same value; a wire format that loses information would break the
/// gateway, which only ever sees bytes.
#[test]
fn serialization_fheuint64_roundtrip_fresh_added_multiplied() {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let sk = SecretKey::random(&params, &mut rng);
    set_server_key(ServerKey::new(&sk, &mut rng).unwrap());

    let a = FheUint64::encrypt(u64::MAX - 41, &sk, &mut rng).unwrap();
    let b = FheUint64::encrypt(1234567, &sk, &mut rng).unwrap();

    let fresh = a.clone();
    let added = &a + &b;
    let multiplied = &a * &b;

    for (ct, expected) in [
        (fresh, u64::MAX - 41),
        (added, (u64::MAX - 41).wrapping_add(1234567)),
        (multiplied, (u64::MAX - 41).wrapping_mul(1234567)),
    ] {
        let bytes = ct.to_bytes();
        let restored = FheUint64::from_bytes(&bytes, &params).unwrap();
        assert_eq!(restored.decrypt(&sk).unwrap(), expected);
    }
}

/// A restored ciphertext must also still be usable as an operand, not just
/// decryptable: the token service computes on deserialized handles.
#[test]
fn serialization_fheuint64_roundtrip_behaves_identically() {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let sk = SecretKey::random(&params, &mut rng);
    set_server_key(ServerKey::new(&sk, &mut rng).unwrap());

    let a = FheUint64::encrypt(99, &sk, &mut rng).unwrap();
    let b = FheUint64::encrypt(7, &sk, &mut rng).unwrap();
    let a2 = FheUint64::from_bytes(&a.to_bytes(), &params).unwrap();

    assert_eq!((&a2 + &b).decrypt(&sk).unwrap(), 106);
    assert_eq!((&a2 * &b).decrypt(&sk).unwrap(), 693);
}

/// A serialized server key must relinearize products exactly like the
/// original; a gateway distributing key material over a wire depends on it.
#[test]
fn serialization_server_key_roundtrip_enables_multiplication() {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let sk = SecretKey::random(&params, &mut rng);
    let server_key = ServerKey::new(&sk, &mut rng).unwrap();

    let bytes = server_key.to_bytes();
    let restored = ServerKey::from_bytes(&bytes, &params).unwrap();
    set_server_key(restored);

    let a = FheUint64::encrypt(3, &sk, &mut rng).unwrap();
    let b = FheUint64::encrypt(5, &sk, &mut rng).unwrap();
    assert_eq!((&a * &b).decrypt(&sk).unwrap(), 15);
}

/// Deserializing against parameters whose plaintext modulus is not 2^64 must
/// be an `Err`, not a panic: it would silently change the arithmetic
/// semantics of every value that passes through the wire.
#[test]
fn serialization_rejects_wrong_plaintext_modulus() {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[60, 60, 60, 60]).unwrap();
    let sk = SecretKey::random(&params, &mut rng);

    let ct = FheUint64::encrypt(42, &sk, &mut rng).unwrap();
    let sk_bytes = ServerKey::new(&sk, &mut rng).unwrap().to_bytes();

    // Same degree and moduli structure, but t != 2^64.
    let wrong_t = BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus(1 << 10)
        .set_moduli_sizes(&[60, 60, 60, 60])
        .build_arc()
        .unwrap();

    assert!(FheUint64::from_bytes(&ct.to_bytes(), &wrong_t).is_err());
    assert!(ServerKey::from_bytes(&sk_bytes, &wrong_t).is_err());
}
