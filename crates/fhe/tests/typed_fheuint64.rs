#![allow(missing_docs)]
//! Tests for the typed `FheUint64` API: encrypted arithmetic must match
//! Rust's wrapping u64 semantics exactly, because the whole point of the
//! typed layer is that users can reason about ciphertexts as plain u64s.

use fhe::bfv::{PublicKey, SecretKey};
use fhe::typed::{FheUint64, ServerKey, set_server_key};
use rand::rng;
use std::error::Error;
use std::sync::Arc;

/// Toy parameters: fast, not 128-bit secure. Arithmetic semantics do not
/// depend on the degree, so most tests use these.
fn toy_setup() -> Result<(Arc<fhe::bfv::BfvParameters>, SecretKey), Box<dyn Error>> {
    let mut rng = rng();
    let params = FheUint64::parameters(16, &[62, 62, 62, 62])?;
    let sk = SecretKey::random(&params, &mut rng);
    Ok((params, sk))
}

#[test]
fn encrypt_decrypt_roundtrip_secret_key() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (_params, sk) = toy_setup()?;
    // Extremes included: every u64 must be a valid message.
    for v in [0u64, 1, u64::MAX, 1u64 << 63, 0x0123_4567_89AB_CDEF] {
        let ct = FheUint64::encrypt(v, &sk, &mut rng)?;
        assert_eq!(ct.decrypt(&sk)?, v);
    }
    Ok(())
}

#[test]
fn encrypt_decrypt_roundtrip_public_key() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (_params, sk) = toy_setup()?;
    let pk = PublicKey::new(&sk, &mut rng);
    for v in [0u64, u64::MAX, 0xDEAD_BEEF_1234_5678] {
        let ct = FheUint64::encrypt_with_public_key(v, &pk, &mut rng)?;
        assert_eq!(ct.decrypt(&sk)?, v);
    }
    Ok(())
}

#[test]
fn addition_matches_wrapping_add() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (_params, sk) = toy_setup()?;
    // u64::MAX - 1 + 7 overflows, so the encrypted sum must wrap.
    let (a, b) = (u64::MAX - 1, 7u64);
    let ca = FheUint64::encrypt(a, &sk, &mut rng)?;
    let cb = FheUint64::encrypt(b, &sk, &mut rng)?;

    assert_eq!((&ca + &cb).decrypt(&sk)?, a.wrapping_add(b));
    // Owned and assign variants must agree with the by-reference one.
    assert_eq!((ca.clone() + &cb).decrypt(&sk)?, a.wrapping_add(b));
    let mut acc = ca;
    acc += &cb;
    assert_eq!(acc.decrypt(&sk)?, a.wrapping_add(b));
    Ok(())
}

#[test]
fn subtraction_and_negation_match_wrapping_ops() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (_params, sk) = toy_setup()?;
    // 3 - 10 underflows, so the encrypted difference must wrap.
    let (a, b) = (3u64, 10u64);
    let ca = FheUint64::encrypt(a, &sk, &mut rng)?;
    let cb = FheUint64::encrypt(b, &sk, &mut rng)?;

    assert_eq!((&ca - &cb).decrypt(&sk)?, a.wrapping_sub(b));
    assert_eq!((ca.clone() - &cb).decrypt(&sk)?, a.wrapping_sub(b));
    let mut acc = ca.clone();
    acc -= &cb;
    assert_eq!(acc.decrypt(&sk)?, a.wrapping_sub(b));

    assert_eq!((-&ca).decrypt(&sk)?, a.wrapping_neg());
    assert_eq!((-ca).decrypt(&sk)?, a.wrapping_neg());
    Ok(())
}

#[test]
fn multiplication_matches_wrapping_mul() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (_params, sk) = toy_setup()?;
    set_server_key(ServerKey::new(&sk, &mut rng)?);

    // Product overflows 64 bits, so the result must wrap modulo 2^64.
    let (a, b) = (0xDEAD_BEEF_1234_5678u64, 0x0123_4567_89AB_CDEFu64);
    let ca = FheUint64::encrypt(a, &sk, &mut rng)?;
    let cb = FheUint64::encrypt(b, &sk, &mut rng)?;

    assert_eq!((&ca * &cb).decrypt(&sk)?, a.wrapping_mul(b));
    assert_eq!((ca.clone() * &cb).decrypt(&sk)?, a.wrapping_mul(b));
    Ok(())
}

#[test]
#[should_panic(expected = "no server key installed")]
fn multiplication_without_server_key_panics() {
    // The `*` operator needs a relinearization key; failing loudly beats
    // returning a silently un-relinearized ciphertext.
    let mut rng = rng();
    let (_params, sk) = toy_setup().unwrap();
    let ca = FheUint64::encrypt(1, &sk, &mut rng).unwrap();
    let cb = FheUint64::encrypt(2, &sk, &mut rng).unwrap();
    let _ = &ca * &cb;
}

#[test]
fn encrypt_rejects_non_2_64_parameters() {
    // FheUint64 semantics only hold for t = 2^64; any other modulus would
    // silently change the wrap-around point.
    let mut rng = rng();
    let params = fhe::bfv::BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus(65537)
        .set_moduli_sizes(&[60, 60, 60])
        .build_arc()
        .unwrap();
    let sk = SecretKey::random(&params, &mut rng);
    assert!(FheUint64::encrypt(1, &sk, &mut rng).is_err());
}

/// The curated 128-bit parameter set advertises multiplicative depth 2; this
/// proves a depth-2 chain (with extra additions) actually decrypts correctly
/// rather than trusting noise arithmetic on paper.
#[test]
fn default_parameters_128_support_depth_2() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128()?;
    let sk = SecretKey::random(&params, &mut rng);
    set_server_key(ServerKey::new(&sk, &mut rng)?);

    let (a, b, c, d) = (
        0xDEAD_BEEF_1234_5678u64,
        0x0123_4567_89AB_CDEFu64,
        u64::MAX - 12345,
        987_654_321u64,
    );
    let ca = FheUint64::encrypt(a, &sk, &mut rng)?;
    let cb = FheUint64::encrypt(b, &sk, &mut rng)?;
    let cc = FheUint64::encrypt(c, &sk, &mut rng)?;
    let cd = FheUint64::encrypt(d, &sk, &mut rng)?;

    // Depth 2: (a*b) * (c+d), then one more addition on top.
    let prod = &(&ca * &cb) * &(&cc + &cd);
    let result = &prod + &ca;
    let expected = a
        .wrapping_mul(b)
        .wrapping_mul(c.wrapping_add(d))
        .wrapping_add(a);
    assert_eq!(result.decrypt(&sk)?, expected);
    Ok(())
}

/// The CUDA backend only engages above its element-count threshold
/// (k * n >= 2^13). The curated 128-bit parameters (degree 16384, six
/// moduli) are far above it, so this pushes the typed API through the GPU
/// NTT/scaler paths.
#[cfg(feature = "cuda")]
#[test]
fn typed_mul_gpu_sized() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = FheUint64::default_parameters_128()?;
    let sk = SecretKey::random(&params, &mut rng);
    set_server_key(ServerKey::new(&sk, &mut rng)?);

    let (a, b) = (0xDEAD_BEEF_1234_5678u64, 0x0123_4567_89AB_CDEFu64);
    let ca = FheUint64::encrypt(a, &sk, &mut rng)?;
    let cb = FheUint64::encrypt(b, &sk, &mut rng)?;
    assert_eq!((&ca * &cb).decrypt(&sk)?, a.wrapping_mul(b));
    Ok(())
}
