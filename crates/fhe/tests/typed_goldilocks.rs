#![allow(missing_docs, clippy::indexing_slicing)]
//! Differential tests for the typed `FheGoldilocks` API: every encrypted
//! slot operation must match an independent reference implementation of
//! Goldilocks field arithmetic over u128. The typed layer's whole promise
//! is "slots behave like Plonky2/Plonky3 field elements", so the reference
//! is plain modular arithmetic, sharing no code with the library.

use fhe::bfv::{PublicKey, SecretKey};
use fhe::typed::{FheGoldilocks, GOLDILOCKS_MODULUS, ServerKey, set_server_key};
use rand::{Rng, rng};
use std::error::Error;
use std::sync::Arc;

const T: u128 = GOLDILOCKS_MODULUS as u128;

// Reference Goldilocks field ops, independent of the library's arithmetic.
fn add_field(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % T) as u64
}

fn sub_field(a: u64, b: u64) -> u64 {
    ((a as u128 + T - b as u128) % T) as u64
}

fn mul_field(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % T) as u64
}

fn neg_field(a: u64) -> u64 {
    ((T - a as u128) % T) as u64
}

/// Random field elements with the mandatory edge cases planted in the first
/// slots: 0, 1, t - 1, the 2^32-structured values x = 2^32 and
/// 2^64 mod t = 2^32 - 1, and t - 2^32 (so sums and products cross every
/// boundary the prime's 2^32 structure creates).
fn edge_case_vec(n: usize) -> Vec<u64> {
    let mut rng = rng();
    let mut v: Vec<u64> = (0..n)
        .map(|_| rng.random_range(0..GOLDILOCKS_MODULUS))
        .collect();
    let edges = [
        0,
        1,
        GOLDILOCKS_MODULUS - 1,
        1u64 << 32,
        (1u64 << 32) - 1, // 2^64 mod t
        GOLDILOCKS_MODULUS - (1u64 << 32),
    ];
    for (slot, &e) in v.iter_mut().zip(edges.iter()) {
        *slot = e;
    }
    v
}

/// Toy parameters: fast, not 128-bit secure. Slot semantics do not depend
/// on the degree, so most tests use these.
fn toy_setup() -> Result<(Arc<fhe::bfv::BfvParameters>, SecretKey), Box<dyn Error>> {
    let mut rng = rng();
    let params = FheGoldilocks::parameters(16, &[62, 62, 62, 62])?;
    let sk = SecretKey::random(&params, &mut rng);
    Ok((params, sk))
}

#[test]
fn encrypt_decrypt_roundtrip_secret_key() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (params, sk) = toy_setup()?;
    let values = edge_case_vec(params.degree());
    let ct = FheGoldilocks::encrypt_slots(&values, &sk, &mut rng)?;
    assert_eq!(ct.decrypt_slots(&sk)?, values);
    Ok(())
}

#[test]
fn encrypt_decrypt_roundtrip_public_key() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (params, sk) = toy_setup()?;
    let pk = PublicKey::new(&sk, &mut rng);
    let values = edge_case_vec(params.degree());
    let ct = FheGoldilocks::encrypt_slots_with_public_key(&values, &pk, &mut rng)?;
    assert_eq!(ct.decrypt_slots(&sk)?, values);
    Ok(())
}

#[test]
fn inputs_above_t_are_reduced_modulo_t() -> Result<(), Box<dyn Error>> {
    // The documented reduction behavior: values in t..2^64 encrypt x - t.
    // u64::MAX = 2^64 - 1 reduces to 2^32 - 2, and t itself reduces to 0.
    let mut rng = rng();
    let (_params, sk) = toy_setup()?;
    let values = [u64::MAX, GOLDILOCKS_MODULUS, GOLDILOCKS_MODULUS + 1];
    let ct = FheGoldilocks::encrypt_slots(&values, &sk, &mut rng)?;
    let out = ct.decrypt_slots(&sk)?;
    assert_eq!(&out[..3], &[(1u64 << 32) - 2, 0, 1]);
    Ok(())
}

#[test]
fn short_input_pads_remaining_slots_with_zeros() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (params, sk) = toy_setup()?;
    let ct = FheGoldilocks::encrypt_slots(&[7, 8], &sk, &mut rng)?;
    let out = ct.decrypt_slots(&sk)?;
    assert_eq!(out.len(), params.degree());
    assert_eq!(&out[..2], &[7, 8]);
    assert!(out[2..].iter().all(|&x| x == 0));
    Ok(())
}

#[test]
fn too_many_values_is_an_error() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (params, sk) = toy_setup()?;
    let values = vec![1u64; params.degree() + 1];
    assert!(FheGoldilocks::encrypt_slots(&values, &sk, &mut rng).is_err());
    Ok(())
}

#[test]
fn addition_matches_reference_field_addition() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (params, sk) = toy_setup()?;
    let a = edge_case_vec(params.degree());
    // Pair the edge slots against (t - 1) so every sum crosses t.
    let mut b = edge_case_vec(params.degree());
    b[..6].fill(GOLDILOCKS_MODULUS - 1);

    let ca = FheGoldilocks::encrypt_slots(&a, &sk, &mut rng)?;
    let cb = FheGoldilocks::encrypt_slots(&b, &sk, &mut rng)?;
    let expected: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| add_field(x, y)).collect();

    assert_eq!((&ca + &cb).decrypt_slots(&sk)?, expected);
    // Owned and assign variants must agree with the by-reference one.
    assert_eq!((ca.clone() + &cb).decrypt_slots(&sk)?, expected);
    let mut acc = ca;
    acc += &cb;
    assert_eq!(acc.decrypt_slots(&sk)?, expected);
    Ok(())
}

#[test]
fn subtraction_and_negation_match_reference_field_ops() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (params, sk) = toy_setup()?;
    let a = edge_case_vec(params.degree());
    // Subtracting t - 1 from small edge values forces wrap-around below 0.
    let mut b = edge_case_vec(params.degree());
    b[..6].fill(GOLDILOCKS_MODULUS - 1);

    let ca = FheGoldilocks::encrypt_slots(&a, &sk, &mut rng)?;
    let cb = FheGoldilocks::encrypt_slots(&b, &sk, &mut rng)?;
    let expected: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| sub_field(x, y)).collect();

    assert_eq!((&ca - &cb).decrypt_slots(&sk)?, expected);
    assert_eq!((ca.clone() - &cb).decrypt_slots(&sk)?, expected);
    let mut acc = ca.clone();
    acc -= &cb;
    assert_eq!(acc.decrypt_slots(&sk)?, expected);

    let expected_neg: Vec<u64> = a.iter().map(|&x| neg_field(x)).collect();
    assert_eq!((-&ca).decrypt_slots(&sk)?, expected_neg);
    assert_eq!((-ca).decrypt_slots(&sk)?, expected_neg);
    Ok(())
}

#[test]
fn multiplication_matches_reference_field_multiplication() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let (params, sk) = toy_setup()?;
    set_server_key(ServerKey::new(&sk, &mut rng)?);

    let a = edge_case_vec(params.degree());
    // (t - 1)^2, (t - 1) * 2^32, etc.: products overflow 64 bits and must
    // reduce through the prime's 2^32 structure.
    let mut b = edge_case_vec(params.degree());
    b[..6].fill(GOLDILOCKS_MODULUS - 1);

    let ca = FheGoldilocks::encrypt_slots(&a, &sk, &mut rng)?;
    let cb = FheGoldilocks::encrypt_slots(&b, &sk, &mut rng)?;
    let expected: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| mul_field(x, y)).collect();

    assert_eq!((&ca * &cb).decrypt_slots(&sk)?, expected);
    assert_eq!((ca.clone() * &cb).decrypt_slots(&sk)?, expected);
    Ok(())
}

#[test]
#[should_panic(expected = "no server key installed")]
fn multiplication_without_server_key_panics() {
    // The `*` operator needs a relinearization key; failing loudly beats
    // returning a silently un-relinearized ciphertext.
    let mut rng = rng();
    let (_params, sk) = toy_setup().unwrap();
    fhe::typed::unset_server_key();
    let ca = FheGoldilocks::encrypt_slots(&[1], &sk, &mut rng).unwrap();
    let cb = FheGoldilocks::encrypt_slots(&[2], &sk, &mut rng).unwrap();
    let _ = &ca * &cb;
}

#[test]
fn encrypt_rejects_non_goldilocks_parameters() {
    // Field semantics only hold for t = 2^64 - 2^32 + 1; any other modulus
    // would silently change the field.
    let mut rng = rng();
    let params = fhe::bfv::BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus(65537)
        .set_moduli_sizes(&[60, 60, 60])
        .build_arc()
        .unwrap();
    let sk = SecretKey::random(&params, &mut rng);
    assert!(FheGoldilocks::encrypt_slots(&[1], &sk, &mut rng).is_err());
}

/// The curated 128-bit parameter set advertises multiplicative depth 2; this
/// proves a depth-2 slot-wise chain (with an extra addition) decrypts
/// correctly rather than trusting noise arithmetic on paper.
#[test]
fn default_parameters_128_support_depth_2() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = FheGoldilocks::default_parameters_128()?;
    let sk = SecretKey::random(&params, &mut rng);
    set_server_key(ServerKey::new(&sk, &mut rng)?);

    let a = edge_case_vec(params.degree());
    let b = edge_case_vec(params.degree());
    let c = edge_case_vec(params.degree());
    let d = edge_case_vec(params.degree());

    let ca = FheGoldilocks::encrypt_slots(&a, &sk, &mut rng)?;
    let cb = FheGoldilocks::encrypt_slots(&b, &sk, &mut rng)?;
    let cc = FheGoldilocks::encrypt_slots(&c, &sk, &mut rng)?;
    let cd = FheGoldilocks::encrypt_slots(&d, &sk, &mut rng)?;

    // Depth 2: (a*b) * (c+d), then one more addition on top.
    let result = &(&(&ca * &cb) * &(&cc + &cd)) + &ca;
    let expected: Vec<u64> = (0..params.degree())
        .map(|i| {
            add_field(
                mul_field(mul_field(a[i], b[i]), add_field(c[i], d[i])),
                a[i],
            )
        })
        .collect();
    assert_eq!(result.decrypt_slots(&sk)?, expected);
    Ok(())
}

/// The CUDA backend only engages above its element-count threshold
/// (k * n >= 2^13). The curated 128-bit parameters (degree 16384, six
/// moduli) are far above it, so this pushes Goldilocks SIMD multiplication
/// through the GPU NTT/scaler paths and checks every slot against the
/// reference field arithmetic.
#[cfg(feature = "cuda")]
#[test]
fn goldilocks_typed_mul_gpu_sized() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = FheGoldilocks::default_parameters_128()?;
    let sk = SecretKey::random(&params, &mut rng);
    set_server_key(ServerKey::new(&sk, &mut rng)?);

    let a = edge_case_vec(params.degree());
    let b = edge_case_vec(params.degree());
    let ca = FheGoldilocks::encrypt_slots(&a, &sk, &mut rng)?;
    let cb = FheGoldilocks::encrypt_slots(&b, &sk, &mut rng)?;

    let expected: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| mul_field(x, y)).collect();
    assert_eq!((&ca * &cb).decrypt_slots(&sk)?, expected);
    Ok(())
}
