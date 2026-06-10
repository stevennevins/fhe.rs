//! C4 failure-mode test: with the `cuda` feature enabled but the backend
//! disabled (no usable GPU, simulated via FHE_CUDA_DISABLE), the library
//! silently falls back to the CPU path and still produces correct results.
//!
//! This lives in its own integration-test binary so the environment
//! variable is set before the backend singleton is initialized.
#![cfg(all(feature = "cuda", not(feature = "tfhe-ntt")))]

use fhe_math::rq::{Context, Ntt, Poly, PowerBasis};
use std::sync::Arc;

#[test]
fn cpu_fallback_when_disabled() {
    // SAFETY: set before any other thread exists in this test binary, and
    // before the CUDA backend singleton is initialized.
    unsafe { std::env::set_var("FHE_CUDA_DISABLE", "1") };

    let ctx = Arc::new(Context::new(&[4611686018326724609, 4611686018309947393], 4096).unwrap());
    let mut rng = rand::rng();
    let p = Poly::<PowerBasis>::random(&ctx, &mut rng);
    let q: Poly<Ntt> = p.clone().into_ntt();
    let back = q.into_power_basis();
    assert_eq!(p, back);
}
