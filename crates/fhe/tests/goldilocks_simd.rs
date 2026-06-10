#![allow(missing_docs, clippy::indexing_slicing)]
//! SIMD (batching) tests for the Goldilocks plaintext modulus
//! t = 2^64 - 2^32 + 1, the Plonky2/Plonky3 field. Since 2^32 | t - 1, a
//! plaintext NTT exists for every practical degree, so slot-wise encrypted
//! arithmetic happens in exactly the field zk circuits use. The point of
//! these tests is that property: each slot must behave as an independent
//! Goldilocks field element, verified against field arithmetic computed
//! independently over u128.

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, RelinearizationKey,
    SecretKey,
};
use fhe_traits::{Deserialize, FheDecoder, FheDecrypter, FheEncoder as _, FheEncrypter, Serialize};
use num_bigint::BigUint;
use rand::{Rng, rng};
use std::{error::Error, sync::Arc};

/// t = 2^64 - 2^32 + 1, the Goldilocks prime.
const GOLDILOCKS: u64 = 18446744069414584321;

fn parameters(degree: usize, moduli_sizes: &[usize]) -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(degree)
        .set_plaintext_modulus_biguint(BigUint::from(GOLDILOCKS))
        .set_moduli_sizes(moduli_sizes)
        .build_arc()
        .unwrap()
}

fn random_goldilocks_vec(n: usize) -> Vec<u64> {
    let mut rng = rng();
    (0..n).map(|_| rng.random_range(0..GOLDILOCKS)).collect()
}

fn add_field(a: u64, b: u64) -> u64 {
    ((a as u128 + b as u128) % GOLDILOCKS as u128) as u64
}

fn mul_field(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % GOLDILOCKS as u128) as u64
}

#[test]
fn simd_encode_decode_roundtrip() -> Result<(), Box<dyn Error>> {
    // SIMD encode followed by decode must be the identity on slot values:
    // batching reorders and NTT-transforms the data internally, and any
    // mismatch here would silently corrupt every slot-wise computation.
    for degree in [16, 64, 256] {
        let params = parameters(degree, &[60, 60]);
        let values = random_goldilocks_vec(degree);

        let pt = Plaintext::try_encode(values.as_slice(), Encoding::simd(), &params)?;
        let out = Vec::<u64>::try_decode(&pt, Encoding::simd())?;
        assert_eq!(out, values, "degree {degree}");

        // The BigUint encode path must agree with the u64 path.
        let values_big: Vec<BigUint> = values.iter().map(|&x| BigUint::from(x)).collect();
        let pt_big = Plaintext::try_encode(values_big.as_slice(), Encoding::simd(), &params)?;
        let out_big = Vec::<BigUint>::try_decode(&pt_big, Encoding::simd())?;
        assert_eq!(out_big, values_big, "degree {degree} (BigUint)");
        assert_eq!(pt, pt_big);
    }
    Ok(())
}

#[test]
fn simd_encrypted_add_matches_field_addition() -> Result<(), Box<dyn Error>> {
    // Slot semantics = field semantics: adding two ciphertexts must add
    // each slot in the Goldilocks field, verified against an independent
    // u128 computation of (a + b) mod t.
    let mut rng = rng();
    let params = parameters(16, &[60, 60, 60]);
    let sk = SecretKey::random(&params, &mut rng);

    let mut a = random_goldilocks_vec(params.degree());
    let mut b = random_goldilocks_vec(params.degree());
    // Force wrap-around in at least one slot.
    a[0] = GOLDILOCKS - 1;
    b[0] = GOLDILOCKS - 2;

    let pt_a = Plaintext::try_encode(a.as_slice(), Encoding::simd(), &params)?;
    let pt_b = Plaintext::try_encode(b.as_slice(), Encoding::simd(), &params)?;
    let ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
    let ct_b: Ciphertext = sk.try_encrypt(&pt_b, &mut rng)?;

    let out = Vec::<u64>::try_decode(&sk.try_decrypt(&(&ct_a + &ct_b))?, Encoding::simd())?;
    let expected: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| add_field(x, y)).collect();
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn simd_encrypted_mul_matches_field_multiplication() -> Result<(), Box<dyn Error>> {
    // Slot semantics = field semantics: multiplying two ciphertexts must
    // multiply each slot in the Goldilocks field — the property zk users
    // rely on for encrypted arithmetic compatible with their circuits.
    let mut rng = rng();
    let params = parameters(16, &[62, 62, 62, 62]);
    let sk = SecretKey::random(&params, &mut rng);
    let rk = RelinearizationKey::new(&sk, &mut rng)?;

    let mut a = random_goldilocks_vec(params.degree());
    let mut b = random_goldilocks_vec(params.degree());
    // Force products that overflow 64 bits and wrap modulo t.
    a[0] = GOLDILOCKS - 1;
    b[0] = GOLDILOCKS - 1;

    let pt_a = Plaintext::try_encode(a.as_slice(), Encoding::simd(), &params)?;
    let pt_b = Plaintext::try_encode(b.as_slice(), Encoding::simd(), &params)?;
    let ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
    let ct_b: Ciphertext = sk.try_encrypt(&pt_b, &mut rng)?;

    let mut ct_res = &ct_a * &ct_b;
    rk.relinearizes(&mut ct_res)?;

    let out = Vec::<u64>::try_decode(&sk.try_decrypt(&ct_res)?, Encoding::simd())?;
    let expected: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| mul_field(x, y)).collect();
    assert_eq!(out, expected);
    Ok(())
}

#[test]
fn simd_rejected_for_non_ntt_friendly_large_primes() {
    // 2^64 - 59 is prime but t - 1 is not divisible by 2 * degree, so no
    // plaintext NTT exists; SIMD must fail loudly, like it does for t = 2^64.
    let params = BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus_biguint(BigUint::from(u64::MAX - 58))
        .set_moduli_sizes(&[60, 60, 60])
        .build_arc()
        .unwrap();
    let values = vec![1u64; params.degree()];
    let result = Plaintext::try_encode(values.as_slice(), Encoding::simd(), &params);
    assert!(matches!(
        result,
        Err(fhe::Error::EncodingNotSupported { .. })
    ));
}

#[test]
fn goldilocks_parameters_serialization_roundtrip() -> Result<(), Box<dyn Error>> {
    // Parameter equality includes the plaintext NTT operator, so this also
    // checks that deserialization rebuilds the same Goldilocks operator.
    let params = parameters(16, &[60, 60, 60]);
    let deserialized = BfvParameters::try_deserialize(&params.to_bytes())?;
    assert_eq!(*params, deserialized);
    Ok(())
}

/// The CUDA backend only engages above its element-count threshold
/// (k * n >= 2^13), so the small-degree tests above run on the CPU even with
/// the `cuda` feature enabled. This test uses production-sized parameters to
/// push Goldilocks SIMD ciphertexts through the GPU NTT/scaler paths.
#[cfg(feature = "cuda")]
#[test]
fn goldilocks_simd_mul_gpu_sized() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = parameters(8192, &[62, 62, 62, 62]);
    let sk = SecretKey::random(&params, &mut rng);
    let rk = RelinearizationKey::new(&sk, &mut rng)?;

    let a = random_goldilocks_vec(params.degree());
    let b = random_goldilocks_vec(params.degree());

    let pt_a = Plaintext::try_encode(a.as_slice(), Encoding::simd(), &params)?;
    let pt_b = Plaintext::try_encode(b.as_slice(), Encoding::simd(), &params)?;
    let ct_a: Ciphertext = sk.try_encrypt(&pt_a, &mut rng)?;
    let ct_b: Ciphertext = sk.try_encrypt(&pt_b, &mut rng)?;

    let mut ct_res = &ct_a * &ct_b;
    rk.relinearizes(&mut ct_res)?;

    let out = Vec::<u64>::try_decode(&sk.try_decrypt(&ct_res)?, Encoding::simd())?;
    let expected: Vec<u64> = a.iter().zip(&b).map(|(&x, &y)| mul_field(x, y)).collect();
    assert_eq!(out, expected);
    Ok(())
}
