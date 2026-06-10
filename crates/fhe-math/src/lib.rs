#![crate_name = "fhe_math"]
#![crate_type = "lib"]

//! Mathematical utilities for the fhe.rs library.

#[cfg(all(feature = "cuda", not(feature = "tfhe-ntt")))]
pub(crate) mod cuda;
mod errors;
mod proto;

pub mod ntt;
pub mod rns;
pub mod rq;
pub mod zq;

pub use errors::{Error, Result};

/// Internal GPU entry point consumed by the `fhe` crate; not public API.
#[cfg(all(feature = "cuda", not(feature = "tfhe-ntt")))]
#[doc(hidden)]
pub use cuda::key_switch as __cuda_key_switch;

/// Opaque handle owning the device-resident copy of one key-switching key's
/// material (CUDA backend). The owner embeds one per key; the first GPU key
/// switch uploads the key material into it, and dropping the owner frees the
/// device memory. Without the `cuda` feature this is a zero-sized stub.
///
/// Internal plumbing for the `fhe` crate; not public API.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct CudaKskCache {
    #[cfg(all(feature = "cuda", not(feature = "tfhe-ntt")))]
    pub(crate) tables: std::sync::OnceLock<std::sync::Arc<cuda::KskTables>>,
}

/// The cache is identity, not state: two keys with equal material are equal
/// regardless of whether either has been uploaded to a device yet.
impl PartialEq for CudaKskCache {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for CudaKskCache {}

impl std::fmt::Debug for CudaKskCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CudaKskCache")
    }
}

#[cfg(test)]
#[macro_use]
extern crate proptest;
