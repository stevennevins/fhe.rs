#![allow(missing_docs, clippy::indexing_slicing)]
//! Tests for true 64-bit plaintext moduli: t = 2^64 (native u64 messages,
//! tfhe-rs style wrap-around semantics) and primes in the 62..=64 bit range.
//! These moduli exceed the 62-bit limit of `fhe_math::zq::Modulus` and are
//! handled through the BigUint plaintext path, so SIMD encoding is not
//! available for them.

use fhe::bfv::{
    BfvParameters, BfvParametersBuilder, Ciphertext, Encoding, Plaintext, RelinearizationKey,
    SecretKey,
};
use fhe_traits::{Deserialize, FheDecoder, FheDecrypter, FheEncoder as _, FheEncrypter, Serialize};
use num_bigint::BigUint;
use rand::rng;
use std::{error::Error, sync::Arc};

/// t = 2^64: plaintext space is exactly the u64 integers with wrap-around.
fn parameters_2_64(moduli_sizes: &[usize]) -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus_biguint(BigUint::from(1u128 << 64))
        .set_moduli_sizes(moduli_sizes)
        .build_arc()
        .unwrap()
}

#[test]
fn build_accepts_62_to_64_bit_moduli() -> Result<(), Box<dyn Error>> {
    // Moduli too large for the native 62-bit Modulus type must build through
    // the BigUint path instead of being rejected.
    for t in [
        BigUint::from(1u64 << 62),        // smallest value above Modulus limit
        BigUint::from((1u64 << 63) - 25), // 63-bit prime
        BigUint::from(u64::MAX - 58),     // 2^64 - 59, 64-bit prime
        BigUint::from(1u128 << 64),       // 2^64
    ] {
        BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(t)
            .set_moduli_sizes(&[60, 60, 60])
            .build_arc()?;
    }
    Ok(())
}

#[test]
fn t_2_64_u64_roundtrip() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = parameters_2_64(&[60, 60, 60]);
    let sk = SecretKey::random(&params, &mut rng);

    // Every u64 is a valid message, including the extremes.
    let mut values = vec![0u64; params.degree()];
    values[0] = u64::MAX;
    values[1] = 1;
    values[2] = 0x0123_4567_89AB_CDEF;
    values[3] = 1u64 << 63;

    let pt = Plaintext::try_encode(values.as_slice(), Encoding::poly(), &params)?;
    let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
    let decrypted = sk.try_decrypt(&ct)?;
    let out = Vec::<u64>::try_decode(&decrypted, Encoding::poly())?;
    assert_eq!(out, values);
    Ok(())
}

#[test]
fn t_2_64_addition_wraps_like_u64() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = parameters_2_64(&[60, 60, 60]);
    let sk = SecretKey::random(&params, &mut rng);

    let a = u64::MAX - 1;
    let b = 7u64;

    let mut v1 = vec![0u64; params.degree()];
    v1[0] = a;
    let mut v2 = vec![0u64; params.degree()];
    v2[0] = b;

    let pt1 = Plaintext::try_encode(v1.as_slice(), Encoding::poly(), &params)?;
    let pt2 = Plaintext::try_encode(v2.as_slice(), Encoding::poly(), &params)?;
    let ct1: Ciphertext = sk.try_encrypt(&pt1, &mut rng)?;
    let ct2: Ciphertext = sk.try_encrypt(&pt2, &mut rng)?;

    let out = Vec::<u64>::try_decode(&sk.try_decrypt(&(&ct1 + &ct2))?, Encoding::poly())?;
    assert_eq!(out[0], a.wrapping_add(b));
    Ok(())
}

#[test]
fn t_2_64_multiplication_wraps_like_u64() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = parameters_2_64(&[62, 62, 62, 62]);
    let sk = SecretKey::random(&params, &mut rng);
    let rk = RelinearizationKey::new(&sk, &mut rng)?;

    // Product overflows 64 bits, so the result must wrap modulo 2^64.
    let a = 0xDEAD_BEEF_1234_5678u64;
    let b = 0x0123_4567_89AB_CDEFu64;

    let mut v1 = vec![0u64; params.degree()];
    v1[0] = a;
    let mut v2 = vec![0u64; params.degree()];
    v2[0] = b;

    let pt1 = Plaintext::try_encode(v1.as_slice(), Encoding::poly(), &params)?;
    let pt2 = Plaintext::try_encode(v2.as_slice(), Encoding::poly(), &params)?;
    let ct1: Ciphertext = sk.try_encrypt(&pt1, &mut rng)?;
    let ct2: Ciphertext = sk.try_encrypt(&pt2, &mut rng)?;

    let mut ct_res = &ct1 * &ct2;
    rk.relinearizes(&mut ct_res)?;
    assert_eq!(ct_res.len(), 2);

    let out = Vec::<u64>::try_decode(&sk.try_decrypt(&ct_res)?, Encoding::poly())?;
    assert_eq!(out[0], a.wrapping_mul(b));
    Ok(())
}

#[test]
fn t_64bit_prime_arithmetic() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    // 2^64 - 59 is prime; it fits in a u64 but exceeds the 62-bit Modulus
    // limit, so it exercises the Small-to-Large routing in the builder.
    let t = BigUint::from(u64::MAX - 58);
    let params = BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus_biguint(t.clone())
        .set_moduli_sizes(&[62, 62, 62, 62])
        .build_arc()?;
    let sk = SecretKey::random(&params, &mut rng);
    let rk = RelinearizationKey::new(&sk, &mut rng)?;

    // 10 * (t - 20) = -200 mod t
    let mut v1 = vec![BigUint::from(0u32); params.degree()];
    v1[0] = BigUint::from(10u32);
    let mut v2 = vec![BigUint::from(0u32); params.degree()];
    v2[0] = &t - 20u32;

    let pt1 = Plaintext::try_encode(v1.as_slice(), Encoding::poly(), &params)?;
    let pt2 = Plaintext::try_encode(v2.as_slice(), Encoding::poly(), &params)?;
    let ct1: Ciphertext = sk.try_encrypt(&pt1, &mut rng)?;
    let ct2: Ciphertext = sk.try_encrypt(&pt2, &mut rng)?;

    let mut ct_res = &ct1 * &ct2;
    rk.relinearizes(&mut ct_res)?;

    let out = Vec::<BigUint>::try_decode(&sk.try_decrypt(&ct_res)?, Encoding::poly())?;
    assert_eq!(out[0], &t - 200u32);
    Ok(())
}

#[test]
fn t_63bit_prime_roundtrip() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let t = BigUint::from((1u64 << 63) - 25);
    let params = BfvParametersBuilder::new()
        .set_degree(16)
        .set_plaintext_modulus_biguint(t.clone())
        .set_moduli_sizes(&[60, 60, 60])
        .build_arc()?;
    let sk = SecretKey::random(&params, &mut rng);

    let mut values = vec![BigUint::from(0u32); params.degree()];
    values[0] = &t - 1u32;
    values[1] = BigUint::from(42u32);

    let pt = Plaintext::try_encode(values.as_slice(), Encoding::poly(), &params)?;
    let ct: Ciphertext = sk.try_encrypt(&pt, &mut rng)?;
    let out = Vec::<BigUint>::try_decode(&sk.try_decrypt(&ct)?, Encoding::poly())?;
    assert_eq!(out, values);
    Ok(())
}

#[test]
fn t_2_64_parameters_serialization_roundtrip() -> Result<(), Box<dyn Error>> {
    for t in [BigUint::from(1u128 << 64), BigUint::from(u64::MAX - 58)] {
        let params = BfvParametersBuilder::new()
            .set_degree(16)
            .set_plaintext_modulus_biguint(t)
            .set_moduli_sizes(&[60, 60, 60])
            .build_arc()?;
        let deserialized = BfvParameters::try_deserialize(&params.to_bytes())?;
        assert_eq!(*params, deserialized);
    }
    Ok(())
}

/// The CUDA backend only engages above its element-count threshold
/// (k * n >= 2^13), so the small-degree tests above run on the CPU even with
/// the `cuda` feature enabled. This test uses production-sized parameters to
/// push the 64-bit plaintext pipeline through the GPU NTT/scaler paths.
#[cfg(feature = "cuda")]
#[test]
fn t_2_64_multiplication_gpu_sized() -> Result<(), Box<dyn Error>> {
    let mut rng = rng();
    let params = BfvParametersBuilder::new()
        .set_degree(8192)
        .set_plaintext_modulus_biguint(BigUint::from(1u128 << 64))
        .set_moduli_sizes(&[62, 62, 62, 62])
        .build_arc()?;
    let sk = SecretKey::random(&params, &mut rng);
    let rk = RelinearizationKey::new(&sk, &mut rng)?;

    let a = 0xDEAD_BEEF_1234_5678u64;
    let b = 0x0123_4567_89AB_CDEFu64;

    let mut v1 = vec![0u64; params.degree()];
    v1[0] = a;
    let mut v2 = vec![0u64; params.degree()];
    v2[0] = b;

    let pt1 = Plaintext::try_encode(v1.as_slice(), Encoding::poly(), &params)?;
    let pt2 = Plaintext::try_encode(v2.as_slice(), Encoding::poly(), &params)?;
    let ct1: Ciphertext = sk.try_encrypt(&pt1, &mut rng)?;
    let ct2: Ciphertext = sk.try_encrypt(&pt2, &mut rng)?;

    let mut ct_res = &ct1 * &ct2;
    rk.relinearizes(&mut ct_res)?;

    let out = Vec::<u64>::try_decode(&sk.try_decrypt(&ct_res)?, Encoding::poly())?;
    assert_eq!(out[0], a.wrapping_mul(b));
    Ok(())
}

#[test]
fn t_2_64_simd_encoding_rejected() {
    // 2^64 is not prime, so there is no NTT over the plaintext space; SIMD
    // encoding must fail loudly instead of producing garbage.
    let params = parameters_2_64(&[60, 60, 60]);
    let values = vec![1u64; params.degree()];
    let result = Plaintext::try_encode(values.as_slice(), Encoding::simd(), &params);
    assert!(matches!(
        result,
        Err(fhe::Error::EncodingNotSupported { .. })
    ));
}
