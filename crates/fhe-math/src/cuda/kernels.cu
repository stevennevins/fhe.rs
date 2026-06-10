// CUDA kernels for fhe-math. These mirror, operation for operation, the
// arithmetic in src/zq/mod.rs and src/ntt/native.rs so that GPU results are
// bit-exact with the CPU implementation. Do not "optimize" the arithmetic
// here without changing the CPU side identically.

// NVRTC compiles without standard headers; define the fixed-width types.
typedef unsigned long long uint64_t;
typedef unsigned __int128 u128;

// zq::Modulus::reduce1: x mod p for x < 2p.
__device__ __forceinline__ uint64_t reduce1(uint64_t x, uint64_t p) {
    return x >= p ? x - p : x;
}

// zq::Modulus::lazy_mul_shoup: a * b mod p in [0, 2p), b_shoup = (b << 64) / p.
__device__ __forceinline__ uint64_t lazy_mul_shoup(uint64_t a, uint64_t b,
                                                   uint64_t b_shoup,
                                                   uint64_t p) {
    uint64_t q = __umul64hi(a, b_shoup);
    return a * b - q * p;
}

// zq::Modulus::mul_shoup.
__device__ __forceinline__ uint64_t mul_shoup(uint64_t a, uint64_t b,
                                              uint64_t b_shoup, uint64_t p) {
    return reduce1(lazy_mul_shoup(a, b, b_shoup, p), p);
}

// zq::Modulus::lazy_reduce_u128: Barrett reduction of a 128-bit value into
// [0, 2p), with barrett = floor(2^128 / p) split into hi/lo 64-bit limbs.
__device__ __forceinline__ uint64_t lazy_reduce_u128(u128 a, uint64_t p,
                                                     uint64_t barrett_hi,
                                                     uint64_t barrett_lo) {
    uint64_t a_lo = (uint64_t)a;
    uint64_t a_hi = (uint64_t)(a >> 64);
    u128 p_lo_lo = ((u128)a_lo * (u128)barrett_lo) >> 64;
    u128 p_hi_lo = (u128)a_hi * (u128)barrett_lo;
    u128 p_lo_hi = (u128)a_lo * (u128)barrett_hi;
    u128 q = ((p_lo_hi + p_hi_lo + p_lo_lo) >> 64) + (u128)a_hi * (u128)barrett_hi;
    return (uint64_t)(a - q * (u128)p);
}

// zq::Modulus::mul (Barrett, constant-time variant's exact value).
__device__ __forceinline__ uint64_t mul_barrett(uint64_t a, uint64_t b,
                                                uint64_t p, uint64_t barrett_hi,
                                                uint64_t barrett_lo) {
    return reduce1(lazy_reduce_u128((u128)a * (u128)b, p, barrett_hi, barrett_lo), p);
}

// ---------------------------------------------------------------------------
// NTT. One stage per launch; data is a k x n row-major matrix (k RNS rows).
// Per-row twiddle tables are concatenated: row r uses omegas[r*n .. r*n+n].
// Mirrors ntt::native::NttOperator::forward / backward.
// ---------------------------------------------------------------------------

// Forward NTT stage with butterfly distance l. Thread t handles butterfly
// j = t % (n/2) of row r = t / (n/2). reduce_out != 0 on the last stage
// (l == 1), where the CPU code fully reduces with reduce3.
extern "C" __global__ void ntt_fwd_stage(uint64_t *a, const uint64_t *omegas,
                                         const uint64_t *omegas_shoup,
                                         const uint64_t *moduli,
                                         unsigned int n, unsigned int k,
                                         unsigned int l, int reduce_out) {
    unsigned int half = n >> 1;
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * half) return;
    unsigned int r = (unsigned int)(t / half);
    unsigned int j = (unsigned int)(t % half);

    unsigned int m = half / l;          // number of chunks in this stage
    unsigned int i = j / l;             // chunk index
    unsigned int s = 2 * i * l + (j % l); // index of x; y is at s + l

    uint64_t p = moduli[r];
    uint64_t p2 = p << 1;
    uint64_t w = omegas[(unsigned long long)r * n + m + i];
    uint64_t w_shoup = omegas_shoup[(unsigned long long)r * n + m + i];

    uint64_t *row = a + (unsigned long long)r * n;
    uint64_t x = row[s];
    uint64_t y = row[s + l];

    // NttOperator::butterfly
    x = reduce1(x, p2);
    uint64_t tt = lazy_mul_shoup(y, w, w_shoup, p);
    y = x + p2 - tt;
    x = x + tt;

    if (reduce_out) {
        // NttOperator::reduce3
        x = reduce1(reduce1(x, p2), p);
        y = reduce1(reduce1(y, p2), p);
    }

    row[s] = x;
    row[s + l] = y;
}

// Backward NTT stage with butterfly distance l. On the last stage
// (scale != 0, i.e. l == n/2 completed afterwards), the CPU code multiplies
// by size_inv; that is done by ntt_inv_final below to mirror the CPU's
// separate loop.
extern "C" __global__ void ntt_inv_stage(uint64_t *a, const uint64_t *zetas_inv,
                                         const uint64_t *zetas_inv_shoup,
                                         const uint64_t *moduli,
                                         unsigned int n, unsigned int k,
                                         unsigned int l) {
    unsigned int half = n >> 1;
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * half) return;
    unsigned int r = (unsigned int)(t / half);
    unsigned int j = (unsigned int)(t % half);

    unsigned int m = half / l;            // chunks in this stage
    unsigned int i = j / l;               // chunk index
    unsigned int s = 2 * i * l + (j % l); // index of x; y is at s + l
    unsigned int start = n - 2 * m;       // first zeta index of this stage

    uint64_t p = moduli[r];
    uint64_t p2 = p << 1;
    uint64_t z = zetas_inv[(unsigned long long)r * n + start + i];
    uint64_t z_shoup = zetas_inv_shoup[(unsigned long long)r * n + start + i];

    uint64_t *row = a + (unsigned long long)r * n;
    uint64_t x = row[s];
    uint64_t y = row[s + l];

    // NttOperator::inv_butterfly
    uint64_t tt = x;
    x = reduce1(y + tt, p2);
    y = lazy_mul_shoup(p2 + tt - y, z, z_shoup, p);

    row[s] = x;
    row[s + l] = y;
}

// Final scaling of the backward NTT: a[i] = mul_shoup(a[i], size_inv).
extern "C" __global__ void ntt_inv_final(uint64_t *a, const uint64_t *size_inv,
                                         const uint64_t *size_inv_shoup,
                                         const uint64_t *moduli,
                                         unsigned int n, unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    unsigned int r = (unsigned int)(t / n);
    a[t] = mul_shoup(a[t], size_inv[r], size_inv_shoup[r], moduli[r]);
}

// ---------------------------------------------------------------------------
// Element-wise operations on k x n matrices. Mirrors zq::Modulus::{add, sub,
// neg, mul, mul_shoup} applied row-wise (one modulus per row).
// ---------------------------------------------------------------------------

extern "C" __global__ void ew_add(uint64_t *a, const uint64_t *b,
                                  const uint64_t *moduli, unsigned int n,
                                  unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    uint64_t p = moduli[t / n];
    a[t] = reduce1(a[t] + b[t], p);
}

extern "C" __global__ void ew_sub(uint64_t *a, const uint64_t *b,
                                  const uint64_t *moduli, unsigned int n,
                                  unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    uint64_t p = moduli[t / n];
    a[t] = reduce1(a[t] + p - b[t], p);
}

extern "C" __global__ void ew_neg(uint64_t *a, const uint64_t *moduli,
                                  unsigned int n, unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    uint64_t p = moduli[t / n];
    a[t] = reduce1(p - a[t], p);
}

extern "C" __global__ void ew_mul(uint64_t *a, const uint64_t *b,
                                  const uint64_t *moduli,
                                  const uint64_t *barrett_hi,
                                  const uint64_t *barrett_lo, unsigned int n,
                                  unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    unsigned int r = (unsigned int)(t / n);
    a[t] = mul_barrett(a[t], b[t], moduli[r], barrett_hi[r], barrett_lo[r]);
}

extern "C" __global__ void ew_mul_shoup(uint64_t *a, const uint64_t *b,
                                        const uint64_t *b_shoup,
                                        const uint64_t *moduli, unsigned int n,
                                        unsigned int k) {
    unsigned long long t = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;
    if (t >= (unsigned long long)k * n) return;
    a[t] = mul_shoup(a[t], b[t], b_shoup[t], moduli[t / n]);
}
